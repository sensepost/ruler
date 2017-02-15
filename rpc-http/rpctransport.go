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
var rpcntlmsession ntlm.ClientSession

//AuthSession Keep track of session data
var AuthSession *utils.Session

func setupHTTPNTLM(rpctype string, URL string, full bool) (net.Conn, error) {
	u, err := url.Parse(URL)
	var connection net.Conn
	if u.Scheme == "http" {
		connection, err = net.Dial("tcp", fmt.Sprintf("%s:80", u.Host))
	} else {
		conf := tls.Config{InsecureSkipVerify: true}
		connection, err = tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), &conf)
	}

	if err != nil {
		return nil, err
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
		fmt.Printf("[x] Failed with initial setup for %s trying again...\n", rpctype)
		return setupHTTPNTLM(rpctype, URL, false)
	}

	parts := strings.Split(string(data), "\r\n")
	ntlmChallengeHeader := ""
	for _, v := range parts {
		if n := strings.Split(v, ": "); len(n) > 0 {
			if n[0] == "WWW-Authenticate" {
				ntlmChallengeHeader = n[1]
				break
			}
		}
	}

	ntlmChallengeString := strings.Replace(ntlmChallengeHeader, "NTLM ", "", 1)
	challengeBytes, err := utils.DecBase64(ntlmChallengeString)
	if err != nil {
		if full == false {
			return nil, fmt.Errorf("Failed with initial setup for %s : %s\n", rpctype, err)
		}
		fmt.Printf("[x] Failed with initial setup for %s trying again...\n", rpctype)
		return setupHTTPNTLM(rpctype, URL, false)
	}

	session.SetUserInfo(AuthSession.User, AuthSession.Pass, AuthSession.Domain)
	if len(AuthSession.NTHash) > 0 {
		session.SetNTHash(AuthSession.NTHash)
	}

	// parse NTLM challenge
	challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
	if err != nil {
		//panic(err)
		return nil, err
	}
	err = session.ProcessChallengeMessage(challenge)
	if err != nil {
		//panic(err)
		return nil, err
	}
	// authenticate user
	authenticate, err := session.GenerateAuthenticateMessage()
	if err != nil {
		//panic(err)
		return nil, err
	}
	if rpctype == "RPC_IN_DATA" {
		request = fmt.Sprintf("%sContent-Length: 1073741824\r\n", request)
	} else if rpctype == "RPC_OUT_DATA" {
		request = fmt.Sprintf("%sContent-Length: 76\r\n", request)
	}
	request = fmt.Sprintf("%sAuthorization: NTLM %s\r\n\r\n", request, utils.EncBase64(authenticate.Bytes()))
	if cookiestr != "" {
		request = fmt.Sprintf("%sCookie: %s\r\n", request, cookiestr)
	}
	connection.Write([]byte(request))

	return connection, nil
}

//RPCOpen opens HTTP for RPC_IN_DATA and RPC_OUT_DATA
func RPCOpen(URL string, readySignal chan bool, errOccurred chan error) (err error) {
	//I'm so damn frustrated at not being able to use the http client here
	//can't find a way to keep the write channel open (other than going over to http/2, which isn't valid here)
	//so this is some damn messy code, but screw it

	rpcInConn, err = setupHTTPNTLM("RPC_IN_DATA", URL, true)

	if err != nil {
		readySignal <- false
		errOccurred <- err
		return err
	}

	//open the RPC_OUT_DATA channel, receive a "ready" signal when this is setup
	//this will be sent back to the caller through "readySignal", while error is sent through errOccurred
	go RPCOpenOut(URL, readySignal, errOccurred)

	for {
		data := make([]byte, 2048)
		n, err := rpcInR.Read(data)
		if n > 0 {
			_, err = rpcInConn.Write(data[:n])
		}
		if err != nil && err != io.EOF {
			fmt.Println(err)
			break
		}
	}
	return nil
}

//RPCOpenOut function opens the RPC_OUT_DATA channel
//starts our listening "loop" which scans for new responses and pushes
//these to our list of recieved responses
func RPCOpenOut(URL string, readySignal chan bool, errOccurred chan error) (err error) {
	rpcOutConn, err = setupHTTPNTLM("RPC_OUT_DATA", URL, true)
	if err != nil {
		readySignal <- false
		errOccurred <- err
		return err
	}
	readySignal <- true
	scanner := bufio.NewScanner(rpcOutConn)
	scanner.Split(SplitData)

	for scanner.Scan() {
		if b := scanner.Bytes(); b != nil {
			r := RPCResponse{}
			r.Unmarshal(b)
			r.Body = b
			responses = append(responses, r)
		}
	}
	return nil
}

//RPCBind function establishes our session
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

	RPCRead(0)
	RPCRead(0)

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
			fmt.Println("we panic here")
			panic(err)
		}
		err = rpcntlmsession.ProcessChallengeMessage(challenge)
		if err != nil {
			fmt.Println("we panic here with challenge")
			panic(err)
		}

		// authenticate user
		authenticate, err := rpcntlmsession.GenerateAuthenticateMessageAV()

		if err != nil {
			fmt.Println("we panic here with authen")
			return err
		}

		//send auth setup complete bind
		au := Auth3(AuthSession.RPCNetworkAuthLevel, AuthSession.RPCNetworkAuthType, authenticate.Bytes())
		RPCWrite(au.Marshal())
	}
	return nil
}

//RPCPing fucntion
func RPCPing() {
	rpcInW.Write(Ping().Marshal())
}

//EcDoRPCExt2 does our actual RPC request returns the mapi data
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
			return nil, fmt.Errorf("[x] Invalid response received. Please try again")
		}
		dec, _ := rpcntlmsession.UnSeal(resp.PDU[8:])
		sec := RTSSec{}
		sec.Unmarshal(resp.SecTrailer, int(resp.Header.AuthLen))
		return dec[20:], err
	}
	return resp.PDU[28:], err
}
func obfuscate(data []byte) []byte {
	bnew := make([]byte, len(data))
	for k := range data {
		bnew[k] = data[k] ^ 0xA5
	}
	return bnew
}

//DoConnectExRequest makes our connection request. After this we can use
//EcDoRPCExt2 to make our MAPI requests
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

	//decrypt response PDU
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		dec, _ := rpcntlmsession.UnSeal(resp.PDU[8:])
		AuthSession.ContextHandle = dec[4:20] //decrypted
	} else {
		AuthSession.ContextHandle = resp.PDU[12:28]
	}

	if utils.DecodeUint32(AuthSession.ContextHandle[0:4]) == 0x0000 {
		return nil, fmt.Errorf("\n[x] Unable to obtain a session context\n[*] Try again using the --encrypt flag. It is possible that the target requires 'Encrypt traffic between Outlook and Exchange' to be enabled")
	}

	return resp.Body, err
}

//RPCDummy is used to check if we can communicate with the server
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

//RPCDisconnect fucntion
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

//RPCWriteN function writes to our RPC_IN_DATA channel
func RPCWriteN(MAPI []byte, auxlen uint32, opnum byte) {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.Header = header

	req.MaxRecv = 0x0000
	req.Command = []byte{0x00, 0x00, opnum, 0x00} //command 10

	pdu := PDUData{}
	if opnum != 0x0a {
		req.Command = []byte{0x00, 0x00, opnum, 0x00, 0x00, 0x00, 0x00, 0x00} //command 10
		pdu.ContextHandle = AuthSession.ContextHandle
	}
	pdu.Data = MAPI
	pdu.CbAuxIn = uint32(auxlen)
	pdu.AuxOut = 0x000001008

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
	rpcInW.Write(req.Marshal())
}

//RPCWrite function writes to our RPC_IN_DATA channel
func RPCWrite(data []byte) {
	callcounter++
	rpcInW.Write(data)
}

//RPCOutWrite function writes to the RPC_OUT_DATA channel,
//this should only happen once, for ConnA1
func RPCOutWrite(data []byte) {
	rpcOutConn.Write(data)
}

//RPCRead function takes a call ID and searches for the response in
//our list of received responses. Blocks until it finds a response
func RPCRead(callID int) (RPCResponse, error) {
	c := make(chan RPCResponse, 1)
	go func() {
		stop := false
		for stop != true {
			for k, v := range responses {
				if v.Header.CallID == uint32(callID) {
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
	case <-time.After(time.Second * 10): // call timed out
		return RPCResponse{}, fmt.Errorf("[x] Time-out reading from RPC")
	}

}

//SplitData is used to scan through the input stream and split data into individual responses
func SplitData(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	//check if HTTP response
	if string(data[0:4]) == "HTTP" {
		for k := range data {
			if data[k] == 0x0d && data[k+1] == 0x0a && data[k+2] == 0x0d && data[k+3] == 0x0a {
				return k + 4, nil, nil //data[0:k], nil
			}
		}
	}

	//proud of this bit, not 100% sure why it works but it works a charm
	if data[0] != 0x0d { //check if we've hit the start of a new sequence
		start := -1
		end := -1
		var dbuf []byte

		for k := range data {
			if data[k] == 0x0d && data[k+1] == 0x0a {
				if start == -1 {
					start = k + 2
				} else {
					end = k - 1
					if start == end {
						dbuf = data[start : end+1]
						start, end = -1, -1
					} else {
						break
					}
				}
			}
		}

		if start == -1 { //we didn't find the start of the string, reset the head of the scanner and try again
			return 0, nil, nil
		}
		//fmt.Println(start, end, len(data))
		if start > end {
			return 0, nil, nil
		}
		return end + 2, append(dbuf, data[start:end]...), nil
	}
	if atEOF {
		return len(data), data, nil
	}

	return
}
