package rpchttp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sensepost/ruler/utils"
	"github.com/staaldraad/go-ntlm/ntlm"
)

var rpcInConn net.Conn
var rpcOutConn net.Conn
var rpcInR, rpcInW = io.Pipe()
var rpcOutR, rpcOutW = io.Pipe()
var rpcRespBody *bufio.Reader
var callcounter int
var responses = make([]RPCResponse, 0)
var httpResponses = make([][]byte, 0)
var rpcntlmsession ntlm.ClientSession
var mutex = &sync.Mutex{}
var writemutex = &sync.Mutex{}

//var AuthSession.ContextHandle []byte

// AuthSession Keep track of session data
var AuthSession *utils.Session

func setupHTTP(rpctype string, URL string, ntlmAuth bool, full bool) (net.Conn, error) {
	u, err := url.Parse(URL)

	var connection net.Conn
	if u.Scheme == "http" {
		connection, err = net.Dial("tcp", fmt.Sprintf("%s:80", u.Host))
	} else {
		conf := tls.Config{InsecureSkipVerify: true}
		connection, err = tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), &conf)
	}

	if err != nil {
		return nil, fmt.Errorf("RPC Setup Err: %s", err)
	}

	var request string
	if full == true {
		request = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", rpctype, u.String(), u.Host)
	} else {
		request = fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", rpctype, u.RequestURI(), u.Host)
	}

	request = fmt.Sprintf("%sUser-Agent: MSRPC\r\n", request)
	request = fmt.Sprintf("%sCache-Control: no-cache\r\n", request)
	request = fmt.Sprintf("%sAccept: application/rpc\r\n", request)
	request = fmt.Sprintf("%sConnection: keep-alive\r\n", request)

	//add cookies
	cookiestr := ""
	for _, c := range AuthSession.CookieJar.Cookies(u) {
		cookiestr = fmt.Sprintf("%s%s=%s; ", cookiestr, c.Name, c.Value)
	}
	if cookiestr != "" {
		request = fmt.Sprintf("%sCookie: %s\r\n", request, cookiestr)
	}

	var authenticate *ntlm.AuthenticateMessage
	if ntlmAuth == true {

		//we should probably extract the NTLM type from the server response and use appropriate
		session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
		b, _ := session.GenerateNegotiateMessage()

		if err != nil {
			return nil, err
		}

		//add NTML Authorization header
		requestInit := fmt.Sprintf("%sAuthorization: NTLM %s\r\n", request, utils.EncBase64(b.Bytes()))
		requestInit = fmt.Sprintf("%sContent-Length: 0\r\n\r\n", requestInit)

		//send connect
		connection.Write([]byte(requestInit))
		//read response
		data := make([]byte, 2048)
		_, err = connection.Read(data)
		if err != nil {
			if full == false {
				return nil, fmt.Errorf("Failed with initial setup for %s : %s\n", rpctype, err)
			}
			//utils.Trace.Printf("Failed with initial setup for %s trying again...\n", rpctype)
			return setupHTTP(rpctype, URL, ntlmAuth, false)
		}

		parts := strings.Split(string(data), "\r\n")
		ntlmChallengeHeader := ""
		for _, v := range parts {
			if n := strings.Split(v, ": "); len(n) > 0 {
				//sometimes header name may be WWW or Www
				if strings.ToLower(n[0]) == strings.ToLower("WWW-Authenticate") {
					if strings.HasPrefix(n[1], "NTLM") {
						ntlmChallengeHeader = n[1]
						break
					}
				}
			}
		}

		ntlmChallengeString := strings.Replace(ntlmChallengeHeader, "NTLM ", "", 1)
		challengeBytes, err := utils.DecBase64(ntlmChallengeString)
		if err != nil {
			if full == false {
				return nil, fmt.Errorf("Failed with initial setup for %s : %s\n", rpctype, err)
			}
			utils.Fail.Printf("Failed with initial setup for %s trying again...\n", rpctype)
			return setupHTTP(rpctype, URL, ntlmAuth, false)
		}

		session.SetUserInfo(AuthSession.User, AuthSession.Pass, AuthSession.Domain)
		if len(AuthSession.NTHash) > 0 {
			session.SetNTHash(AuthSession.NTHash)
		}

		if len(challengeBytes) == 0 {
			utils.Debug.Println(string(data))
			return nil, fmt.Errorf("Authentication Error. No NTLM Challenge")
		}
		// parse NTLM challenge
		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			utils.Debug.Println(string(data))
			return nil, err
		}
		err = session.ProcessChallengeMessage(challenge)
		if err != nil {
			utils.Debug.Println(string(data))
			return nil, err
		}
		// authenticate user
		authenticate, err = session.GenerateAuthenticateMessage()

		if err != nil {
			utils.Debug.Println(string(data))
			return nil, err
		}
	}

	if rpctype == "RPC_IN_DATA" {
		request = fmt.Sprintf("%sContent-Length: 1073741824\r\n", request)
	} else if rpctype == "RPC_OUT_DATA" {
		request = fmt.Sprintf("%sContent-Length: 76\r\n", request)
	}

	if ntlmAuth == true {
		request = fmt.Sprintf("%sAuthorization: NTLM %s\r\n\r\n", request, utils.EncBase64(authenticate.Bytes()))
	} else {
		if u.Host == "outlook.office365.com" {
			request = fmt.Sprintf("%sAuthorization: Basic %s\r\n\r\n", request, utils.EncBase64([]byte(fmt.Sprintf("%s:%s", AuthSession.Email, AuthSession.Pass))))
		} else {
			request = fmt.Sprintf("%sAuthorization: Basic %s\r\n\r\n", request, utils.EncBase64([]byte(fmt.Sprintf("%s\\%s:%s", AuthSession.Domain, AuthSession.User, AuthSession.Pass))))
		}
	}

	connection.Write([]byte(request))

	return connection, nil
}

// RPCOpen opens HTTP for RPC_IN_DATA and RPC_OUT_DATA
func RPCOpen(URL string, readySignal chan bool, errOccurred chan error) {
	//I'm so damn frustrated at not being able to use the http client here
	//can't find a way to keep the write channel open (other than going over to http/2, which isn't valid here)
	//so this is some damn messy code, but screw it

	var err error
	rpcInConn, err = setupHTTP("RPC_IN_DATA", URL, AuthSession.RPCNtlm, true)

	if err != nil {
		readySignal <- false
		errOccurred <- err
	}

	//open the RPC_OUT_DATA channel, receive a "ready" signal when this is setup
	//this will be sent back to the caller through "readySignal", while error is sent through errOccurred
	go RPCOpenOut(URL, readySignal, errOccurred)

	select {
	case c := <-readySignal:
		if c == true {
			readySignal <- true
		} else {
			readySignal <- false
		}
	case <-time.After(time.Second * 5): // call timed out
		readySignal <- true
	}

	for {
		data := make([]byte, 2048)
		n, err := rpcInR.Read(data)
		if n > 0 {
			_, err = rpcInConn.Write(data[:n])
		}
		if err != nil && err != io.EOF {
			utils.Error.Println("RPCIN_ERROR: ", err)
			break
		}
	}
}

// RPCOpenOut function opens the RPC_OUT_DATA channel
// starts our listening "loop" which scans for new responses and pushes
// these to our list of recieved responses
func RPCOpenOut(URL string, readySignal chan<- bool, errOccurred chan<- error) {

	var err error
	rpcOutConn, err = setupHTTP("RPC_OUT_DATA", URL, AuthSession.RPCNtlm, true)
	if err != nil {
		readySignal <- false
		errOccurred <- err
	}

	scanner := bufio.NewScanner(rpcOutConn)
	scanner.Split(SplitData)

	for scanner.Scan() {
		if b := scanner.Bytes(); b != nil {
			if string(b[0:4]) == "HTTP" {
				httpResponses = append(httpResponses, b)
			}
			r := RPCResponse{}
			r.Unmarshal(b)
			r.Body = b
			mutex.Lock() //lets be safe, lock the responses array before adding a new value to it

			//if the PFCFlag is set to 0 or 2, this packet is fragment of the previous packet
			//take the PDU of this packet and append it to our previous packet
			if r.Header.PFCFlags == uint8(2) || r.Header.PFCFlags == uint8(0) {
				for k, v := range responses {
					if v.Header.CallID == r.Header.CallID {
						responses[k].PDU = append(v.PDU, r.PDU...)
						if r.Header.PFCFlags == uint8(2) {
							responses[k].Header.PFCFlags = 3
						}
						break
					}
				}
			} else {
				responses = append(responses, r)
			}

			mutex.Unlock()
		}
	}

}

// RPCBind function establishes our session
func RPCBind() error {
	var err error
	//Generate out-channel cookie
	//20 byte channel cookie for out-channel
	connB1 := ConnB1()
	//Send CONN/A1
	connA1 := ConnA1(connB1.VirtualConnectCookie.Cookie)
	RPCOutWrite(connA1.Marshal())

	//send CONN/B1
	RPCWrite(connB1.Marshal())

	//should check if we use Version1 or Version2
	rpcntlmsession, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
	if err != nil {
		return err
	}

	bind := BindPDU{}
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		bind = SecureBind(AuthSession.RPCNetworkAuthLevel, AuthSession.RPCNetworkAuthType, &rpcntlmsession)
	} else {
		bind = Bind()
	}

	RPCWrite(bind.Marshal())

	if _, err := RPCRead(0); err != nil {
		return err
	}
	if _, err := RPCRead(0); err != nil {
		return err
	}

	//parse out and setup security
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		resp, err := RPCRead(1)

		if err != nil {
			return err
		}
		sec := RTSSec{}
		pos, _ := sec.Unmarshal(resp.SecTrailer, int(resp.Header.AuthLen))
		//fmt.Printf("%x\n", resp.Body[len(resp.PDU)+pos+16:])
		challengeBytes := append(resp.Body[len(resp.PDU)+pos+16:], []byte{0x00}...)

		rpcntlmsession.SetUserInfo(AuthSession.User, AuthSession.Pass, AuthSession.Domain)
		rpcntlmsession.SetMode(ntlm.ConnectionOrientedMode)
		rpcntlmsession.SetTarget(fmt.Sprintf("exchangeMDB/%s", AuthSession.RPCMailbox))
		rpcntlmsession.SetNTHash(AuthSession.NTHash)

		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)

		if err != nil {
			return fmt.Errorf("Bad Challenge Message %s", err)
		}
		err = rpcntlmsession.ProcessChallengeMessage(challenge)
		if err != nil {
			return fmt.Errorf("Bad Process Challenge %s", err)
		}

		// authenticate user
		authenticate, err := rpcntlmsession.GenerateAuthenticateMessageAV()

		if err != nil {
			utils.Debug.Println(string(resp.Body))
			return fmt.Errorf("Bad authenticate message %s", err)
		}

		//send auth setup complete bind
		au := Auth3(AuthSession.RPCNetworkAuthLevel, AuthSession.RPCNetworkAuthType, authenticate.Bytes())
		RPCWrite(au.Marshal())
	}
	return nil
}

// RPCPing fucntion
func RPCPing() {
	rpcInW.Write(Ping().Marshal())
}

// EcDoRPCExt2 does our actual RPC request returns the mapi data
func EcDoRPCExt2(MAPI []byte, auxLen uint32) ([]byte, error) {

	RPCWriteN(MAPI, auxLen, 0x0b)
	//RPCWrite(req.Marshal())
	resp, err := RPCRead(callcounter - 1)

	if err != nil {
		return nil, err
	}

	//decrypt response PDU
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		if len(resp.PDU) < 20 {
			return nil, fmt.Errorf("Invalid response received. Please try again")
		}
		dec, _ := rpcntlmsession.UnSeal(resp.PDU[8:])
		sec := RTSSec{}
		sec.Unmarshal(resp.SecTrailer, int(resp.Header.AuthLen))
		return dec[20:], err
	}

	if len(resp.PDU) < 28 {
		utils.Debug.Println(resp)
		return nil, fmt.Errorf("Invalid response.")
	}

	return resp.PDU[28:], err
}

// EcDoRPCAbk makes a request for NSPI addressbook
// Not fully implemented
// TODO: complete this
func EcDoRPCAbk(MAPI []byte, l int) ([]byte, error) {
	RPCWriteN(MAPI, uint32(l), 0x03)
	//RPCWrite(req.Marshal())

	resp, err := RPCRead(callcounter - 1)

	if err != nil {
		return nil, err
	}
	fmt.Printf("%x\n", resp.PDU)
	return resp.PDU, err
}

// DoConnectExRequest makes our connection request. After this we can use
// EcDoRPCExt2 to make our MAPI requests
func DoConnectExRequest(MAPI []byte, auxLen uint32) ([]byte, error) {

	callcounter += 2

	RPCWriteN(MAPI, auxLen, 0x0a)

	resp, err := RPCRead(callcounter - 1)
	if err == nil && len(resp.PDU) < 20 {
		resp, err = RPCRead(callcounter - 1)
	}
	if err != nil {
		return nil, err
	}
	var dec []byte
	//decrypt response PDU
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		dec, _ = rpcntlmsession.UnSeal(resp.PDU[8:])
		AuthSession.ContextHandle = dec[4:20] //decrypted
	} else {
		AuthSession.ContextHandle = resp.PDU[12:28]
	}

	if utils.DecodeUint32(AuthSession.ContextHandle[0:4]) == 0x0000 {
		utils.Debug.Printf("%s\n%x\n", string(dec), resp)
		return nil, fmt.Errorf("\nUnable to obtain a session context\nTry again using the --encrypt flag. It is possible that the target requires 'Encrypt traffic between Outlook and Exchange' to be enabled")
	}

	return resp.Body, err
}

// RPCDummy is used to check if we can communicate with the server
func RPCDummy() {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.MaxFrag = 0xFFFF
	req.MaxRecv = 0x0000
	req.Header = header
	req.Command = []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	pdu := PDUData{}
	pdu.ContextHandle = AuthSession.ContextHandle
	pdu.AuxOut = 0x000001008
	req.PduData = pdu.Marshal()
	req.Header.FragLen = uint16(len(req.Marshal()))
	RPCWrite(req.Marshal())
}

// RPCDisconnect fucntion
func RPCDisconnect() {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.MaxFrag = 0xFFFF
	req.MaxRecv = 0x0000
	req.Header = header
	req.Command = []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00} //opnum 0x01
	pdu := PDUData{}
	pdu.ContextHandle = AuthSession.ContextHandle
	pdu.AuxOut = 0x000001008
	req.PduData = pdu.Marshal()
	req.Header.FragLen = uint16(len(req.Marshal()))
	RPCWrite(req.Marshal())
	rpcInConn.Close()
	rpcOutConn.Close()
}

// RPCWriteN function writes to our RPC_IN_DATA channel
func RPCWriteN(MAPI []byte, auxlen uint32, opnum byte) {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.Header = header

	req.MaxRecv = 0x1000
	req.Command = []byte{0x00, 0x00, opnum, 0x00} //command 10

	pdu := PDUData{}
	if opnum != 0x0a {
		req.Command = []byte{0x00, 0x00, opnum, 0x00, 0x00, 0x00, 0x00, 0x00} //command 10
		pdu.ContextHandle = AuthSession.ContextHandle
	}
	pdu.Data = MAPI

	pdu.CbAuxIn = uint32(auxlen)
	pdu.AuxOut = 0x000001000

	req.PduData = pdu.Marshal() //MAPI
	req.MaxFrag = uint16(len(pdu.Marshal()) + 24)
	req.Header.FragLen = uint16(len(req.Marshal()))

	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		var data []byte
		if opnum != 0x0a {
			req.Command = []byte{0x01, 0x00, opnum, 0x00}
			data = append([]byte{0x00, 0x00, 0x00, 0x00}, req.PduData...)
		} else {
			req.Command[0] = 0x01 //set CTX context id
			data = req.PduData
		}

		//pad if necessary
		pad := (4 - (len(data) % 4)) % 4

		data = append(data, bytes.Repeat([]byte{0xBB}, pad)...)
		req.PduData = data
		req.Header.FragLen += 24 //account for AuthData

		//add sectrailer
		secTrail := RTSSec{}
		secTrail.AuthLevel = AuthSession.RPCNetworkAuthLevel
		secTrail.AuthType = AuthSession.RPCNetworkAuthType
		secTrail.AuthPadLen = uint8(pad)
		secTrail.AuthCTX = 0

		req.SecTrailer = secTrail.Marshal()
		req.Header.AuthLen = 16

		//seal data, sign pdu
		//Sign the whole pdu, but encrypt just the PduData, not the dcerpc header.
		sealed, sign, _ := rpcntlmsession.SealV2(data, req.Marshal())

		req.AuthData = sign
		req.PduData = sealed
	}
	callcounter++

	writemutex.Lock() //lets be safe, don't think this is strictly necessary
	rpcInW.Write(req.Marshal())
	writemutex.Unlock()

	//previous versions were writing to the channel faster than the RPC proxy could handle the data. This caused issues...
	time.Sleep(time.Millisecond * 300)
}

// RPCWrite function writes to our RPC_IN_DATA channel
func RPCWrite(data []byte) {
	callcounter++
	writemutex.Lock() //lets be safe, don't think this is strictly necessary
	rpcInW.Write(data)
	writemutex.Unlock()
	time.Sleep(time.Millisecond * 300)
}

// RPCOutWrite function writes to the RPC_OUT_DATA channel,
// this should only happen once, for ConnA1
func RPCOutWrite(data []byte) {
	if rpcOutConn != nil {
		writemutex.Lock() //lets be safe, don't think this is strictly necessary
		rpcOutConn.Write(data)
		writemutex.Unlock()
		time.Sleep(time.Millisecond * 300)
	}
}

// RPCRead function takes a call ID and searches for the response in
// our list of received responses. Blocks until it finds a response
func RPCRead(callID int) (RPCResponse, error) {
	c := make(chan RPCResponse, 1)

	go func() {
		stop := false
		for stop != true {
			for k, v := range responses {
				//if the PFCFlags is set to 1, this is a fragmented packet. wait to update it first
				if v.Header.CallID == uint32(callID) && v.Header.PFCFlags != 1 {
					responses = append(responses[:k], responses[k+1:]...)
					stop = true
					c <- v
					break
				}
			}
		}
	}()

	select {
	case resp := <-c:
		return resp, nil
	case <-time.After(time.Second * 15): // call timed out
		utils.Error.Println("RPC Timeout")
		//check if there is a 401 or other error message
		for k, v := range httpResponses {
			st := string(v)
			if er := strings.Split(strings.Split(st, "\r\n")[0], " "); len(er) > 1 && er[1] != "200" {
				utils.Debug.Println(st)
				return RPCResponse{}, fmt.Errorf("Invalid HTTP response: %s", er)
			} else if len(er) <= 1 {
				utils.Debug.Println(st)
				return RPCResponse{}, fmt.Errorf("Invalid HTTP response: %s", st)
			}
			httpResponses = append(httpResponses[:k], httpResponses[k+1:]...)
		}
		return RPCResponse{}, fmt.Errorf("Time-out reading from RPC")
	}

}

// SplitData is used to scan through the input stream and split data into individual responses
func SplitData(data []byte, atEOF bool) (advance int, token []byte, err error) {
	//check if HTTP response
	if string(data[0:4]) == "HTTP" {
		for k := range data {
			if bytes.Equal(data[k:k+4], []byte{0x0d, 0x0a, 0x0d, 0x0a}) {
				return k + 4, data[0:k], nil //return the HTTP packet
			}
		}
	}

	// get rpc packet
	// strip trailing {0x0d, 0x0a} bytes
	end := bytes.LastIndex(data, []byte{0x0d, 0x0a})
	if end != -1 {
		data = data[0:end]

		start := bytes.LastIndex(data, []byte{0x0d, 0x0a})
		if start != -1 {
			start += 2
			data = data[start:len(data)]
		}

		if len(data) < 12 { //check that we have enough data
			return 0, nil, nil
		}

		//get the length of the RPC packet
		if len(data) < int(utils.DecodeUint16(data[8:10])) { //check that we have enough data
			return 0, nil, nil
		}

		return start + len(data) + 2, data, nil //return current position and rpc packet
	}

	// some data may remain
	if !atEOF {
		return 0, nil, nil
	}

	// EOF
	return 0, nil, bufio.ErrFinalToken
}
