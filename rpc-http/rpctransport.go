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

func setupHTTPNTLM(rpctype string, URL string) (net.Conn, error) {
	u, err := url.Parse(URL)
	var connection net.Conn
	if u.Scheme == "http" {
		connection, err = net.Dial("tcp", fmt.Sprintf("%s:80", u.Host))
	} else {
		conf := tls.Config{InsecureSkipVerify: true}
		connection, err = tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), &conf)
	}

	if err != nil {
		fmt.Println("Could not connect")
		return nil, err
	}

	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", rpctype, u.RequestURI(), u.Host)
	request = fmt.Sprintf("%sUser-Agent: MSRPC\r\n", request)
	request = fmt.Sprintf("%sCache-Control: no-cache\r\n", request)
	request = fmt.Sprintf("%sAccept: application/rpc\r\n", request)
	request = fmt.Sprintf("%sConnection: keep-alive\r\n", request)

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
	connection.Read(data)

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
		return nil, err
	}

	session.SetUserInfo(AuthSession.User, AuthSession.Pass, AuthSession.Domain)
	//fmt.Printf("Challenge: %x\n\n", challengeBytes)
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

	connection.Write([]byte(request))

	return connection, nil
}

//RPCOpen opens HTTP for RPC_IN_DATA and RPC_OUT_DATA
func RPCOpen(URL string, readySignal chan bool) (err error) {
	//I'm so damn frustrated at not being able to use the http client here
	//can't find a way to keep the write channel open (other than going over to http/2, which isn't valid here)
	//so this is some damn messy code, but screw it

	rpcInConn, _ = setupHTTPNTLM("RPC_IN_DATA", URL)

	//open the RPC_OUT_DATA channel, receive a "ready" signal when this is setup
	//this will be sent back to the caller through "c", whi
	go RPCOpenOut(URL, readySignal)

	for {
		data := make([]byte, 2048)
		n, err := rpcInR.Read(data)
		if n > 0 {
			//fmt.Printf("sending some data: %x\n", data[:n])
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
func RPCOpenOut(URL string, readySignal chan bool) error {
	rpcOutConn, _ = setupHTTPNTLM("RPC_OUT_DATA", URL)

	//signal that the RPC_OUT_DATA channel has been setup. This means both channels should be ready to go
	readySignal <- true

	scanner := bufio.NewScanner(rpcOutConn)
	scanner.Split(SplitData)

	for scanner.Scan() {
		if b := scanner.Bytes(); b != nil {
			//add to list of responses
			r := RPCResponse{}
			r.Unmarshal(b)
			r.Body = b
			responses = append(responses, r)
		}
	}
	return nil
}

//RPCBind function establishes our session
func RPCBind() {
	var err error
	//Generate out-channel cookie
	//20 byte channel cookie for out-channel
	connB1 := ConnB1()
	//Send CONN/A1
	connA1 := ConnA1(connB1.VirtualConnectCookie.Cookie)
	RPCOutWrite(connA1.Marshal())

	//send CONN/B1
	RPCWrite(connB1.Marshal())

	//I should change this to an object, but it never changes, so I guess it's ok for now to leave it hardcoded
	//dataout := []byte{0x05, 0x00, 0x0b, 0x13, 0x10, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf8, 0x0f, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	//RPCWrite(dataout)
	//should check if we use Version1 or Version2
	rpcntlmsession, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
	if err != nil {
		panic(err)
	}

	bind := Bind(AuthSession.RPCNetworkAuthLevel, AuthSession.RPCNetworkAuthType, &rpcntlmsession)

	RPCWrite(bind.Marshal())

	RPCRead(0)
	RPCRead(0)

	//parse out and setup security
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		resp, err := RPCRead(1)
		//fmt.Printf("Security setup: %x\n\n%x\n", resp.PDU, resp.SecTrailer)
		sec := RTSSec{}
		sec.Unmarshal(resp.SecTrailer, int(resp.Header.AuthLen))

		challengeBytes := append(sec.Data[:len(sec.Data)-1], []byte{0x00}...)

		rpcntlmsession.SetUserInfo(AuthSession.User, AuthSession.Pass, AuthSession.Domain)

		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		//fmt.Println(challenge)
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
		authenticate, err := rpcntlmsession.GenerateAuthenticateMessage()

		if err != nil {
			fmt.Println("we panic here with authen")
			panic(err)
		}
		AuthSession.RPCNtlmSessionKey = authenticate.ClientChallenge()
		//fmt.Println(authenticate)
		//send auth setup complete bind
		au := Auth3(AuthSession.RPCNetworkAuthLevel, AuthSession.RPCNetworkAuthType, authenticate.Bytes())
		RPCWrite(au.Marshal())

		//RPCRead(1)
		//save session key and set that all requests should be encrypted/signed
	}
}

//RPCPing fucntion
func RPCPing() {
	rpcInW.Write(Ping().Marshal())
}

//EcDoRPCExt2 does our actual RPC request returns the mapi data
func EcDoRPCExt2(mapi []byte, auxLen uint32) ([]byte, error) {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.MaxFrag = 0xFFFF
	req.MaxRecv = 0x0000
	req.Header = header
	req.Command = []byte{0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00} //opnum 0x0b
	pdu := PDUData{}
	pdu.ContextHandle = AuthSession.ContextHandle
	pdu.Data = mapi
	pdu.CbAuxIn = auxLen
	pdu.AuxOut = 0x000001008

	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		data := pdu.Marshal()

		//pad if necessary
		pad := 0 //(4-(len(data)%4)) % 4
		//data = append(data, bytes.Repeat([]byte{0xBB}, pad)...)

		sealed, sign, _ := rpcntlmsession.Seal(data)
		//NTLM seal and add sectrailer
		fmt.Printf("Seal: %x\nMAC: %x\n", sealed, sign)
		secTrail := RTSSec{}
		secTrail.AuthLevel = AuthSession.RPCNetworkAuthLevel
		secTrail.AuthType = AuthSession.RPCNetworkAuthType
		secTrail.AuthPadLen = uint8(pad)
		secTrail.Data = sign
		req.Header.AuthLen = uint16(len(secTrail.Data))
		req.SecTrailer = secTrail.Marshal()
		req.PduData = sealed
	} else {
		req.PduData = pdu.Marshal() //MAPI
	}

	req.Header.FragLen = uint16(len(req.Marshal()))
	RPCWrite(req.Marshal())
	resp, err := RPCRead(callcounter - 1)

	//decrypt response PDU
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		return resp.PDU[28:], err
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
func DoConnectExRequest(MAPI []byte, auxlen uint32) ([]byte, error) {

	callcounter += 2
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.Header = header
	req.MaxFrag = 0xffff
	req.MaxRecv = 0x0000
	req.Command = []byte{0x00, 0x00, 0x0a, 0x00} //command 10

	pdu := PDUData{}
	pdu.Data = MAPI
	pdu.CbAuxIn = uint32(auxlen)
	pdu.AuxOut = 0x000001008

	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {

		data := pdu.Marshal()
		//pad if necessary
		pad := (4 - (len(data) % 4)) % 4
		data = append(data, bytes.Repeat([]byte{0x00}, pad)...)
		fmt.Println("Padding: ", pad)
		sealed, sign, _ := rpcntlmsession.Seal(data)

		//NTLM seal and add sectrailer
		secTrail := RTSSec{}
		secTrail.AuthLevel = AuthSession.RPCNetworkAuthLevel
		secTrail.AuthType = AuthSession.RPCNetworkAuthType

		secTrail.Data = sign
		req.Header.AuthLen = uint16(len(secTrail.Data))
		req.SecTrailer = secTrail.Marshal()

		secTrail.AuthPadLen = uint8(pad)
		req.PduData = sealed
	} else {
		req.PduData = pdu.Marshal() //MAPI
	}

	req.Header.FragLen = uint16(len(req.Marshal()))

	RPCWrite(req.Marshal())
	RPCRead(1)

	resp, err := RPCRead(callcounter - 1)

	//decrypt response PDU
	if AuthSession.RPCNetworkAuthLevel == RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
		AuthSession.ContextHandle = resp.PDU[12:28] //decrypt
	} else {
		AuthSession.ContextHandle = resp.PDU[12:28]
	}

	if utils.DecodeUint32(AuthSession.ContextHandle[0:4]) == 0x0000 {
		return nil, fmt.Errorf("-- Unable to obtain a session context")
	}
	return resp.Body, err
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

	RPCWrite(req.Marshal())
	rpcInConn.Close()
	rpcOutConn.Close()
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
	for {
		for k, v := range responses {
			if v.Header.CallID == uint32(callID) {
				responses = append(responses[:k], responses[k+1:]...)
				return v, nil
			}
		}
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
				return k + 4, nil, nil //data[k+4:], nil
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
		return end + 2, append(dbuf, data[start:end]...), nil
	}
	if atEOF {
		return len(data), data, nil
	}

	return
}
