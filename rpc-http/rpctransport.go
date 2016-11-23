package rpchttp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	"github.com/sensepost/ruler/utils"
)

var rpcInConn net.Conn
var rpcOutConn net.Conn
var rpcInR, rpcInW = io.Pipe()
var rpcOutR, rpcOutW = io.Pipe()
var rpcRespBody *bufio.Reader
var callcounter int
var responses = make([]RPCResponse, 0)

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

	//add NTML Authorization header
	requestInit := fmt.Sprintf("%sAuthorization: NTLM %s\r\n", request, utils.EncBase64(utils.NegotiateSP()))
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
	//we should probably extract the NTLM type from the server response and use appropriate
	session, err := ntlm.CreateClientSession(ntlm.Version1, ntlm.ConnectionlessMode)
	if err != nil {
		return nil, err
	}

	session.SetUserInfo(AuthSession.User, AuthSession.Pass, AuthSession.Domain)

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
			r.CallID = utils.DecodeUint16(b[12:14])
			r.Body = b
			responses = append(responses, r)
		}
	}
	return nil
}

//RPCBind function establishes our session
func RPCBind() {
	//Generate out-channel cookie
	//20 byte channel cookie for out-channel
	connB1 := ConnB1()
	//Send CONN/A1
	connA1 := ConnA1(connB1.VirtualConnectCookie.Cookie)
	RPCOutWrite(connA1.Marshal())

	//send CONN/B1
	RPCWrite(connB1.Marshal())

	//I should change this to an object, but it never changes, so I guess it's ok for now to leave it hardcoded
	dataout := []byte{0x05, 0x00, 0x0b, 0x13, 0x10, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf8, 0x0f, 0xf8, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xdb, 0xf1, 0xa4, 0x47, 0xca, 0x67, 0x10, 0xb3, 0x1f, 0x00, 0xdd, 0x01, 0x06, 0x62, 0xda, 0x00, 0x00, 0x51, 0x00, 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	RPCWrite(dataout)

	//bind := Bind(RPC_C_AUTHN_LEVEL_NONE)
	//RPCWrite(bind.Marshal())

	RPCRead(0)
	RPCRead(0)

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
	req.Version = []byte{0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00} //opnum 0x0b
	req.ContextHandle = AuthSession.ContextHandle
	req.Data = mapi
	req.CbAuxIn = auxLen
	req.AuxOut = 0x000001008

	req.Header.FragLen = uint16(len(req.Marshal()))
	RPCWrite(req.Marshal())

	return RPCRead(callcounter - 1)
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
func DoConnectExRequest(MAPI []byte) ([]byte, error) {

	callcounter += 2
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := ConnectExRequest{}
	req.Header = header
	req.MaxFrag = 0xffff
	req.MaxRecv = 0x0000
	req.ContextHandle = []byte{0x00, 0x00, 0x0a, 0x00} //opnum 0x0a

	req.Data = MAPI

	//AUXBuffer here
	auxbuf := AUXBuffer{}
	auxbuf.RPCHeader = RPCHeader{Version: 0x0000, Flags: 0x04}

	clientInfo := AUXPerfClientInfo{AdapterSpeed: 0x000186a0, ClientID: 0x0001, AdapterNameOffset: 0x0020, ClientMode: 0x0002, MachineName: utils.UniString("Ethernet 2")}
	clientInfo.Header = AUXHeader{Version: 0x01, Type: 0x02}
	clientInfo.Header.Size = uint16(len(clientInfo.Marshal()))

	accountInfo := AUXPerfAccountInfo{ClientID: 0x0001, Account: CookieGen()}
	accountInfo.Header = AUXHeader{Version: 0x01, Type: 0x18}
	accountInfo.Header.Size = uint16(len(accountInfo.Marshal()))

	sessionInfo := AUXTypePerfSessionInfo{SessionID: 0x0001, SessionGUID: CookieGen(), ConnectionID: 0x00000001b}
	sessionInfo.Header = AUXHeader{Version: 0x02, Type: 0x04}
	sessionInfo.Header.Size = uint16(len(sessionInfo.Marshal()))

	processInfo := AUXTypePerfProcessInfo{ProcessID: 0x01, ProcessGUID: CookieGen(), ProcessNameOffset: 0x004f, ProcessName: utils.UniString("OUTLOOK.EXE")}
	processInfo.Header = AUXHeader{Version: 0x02, Type: 0x0b}
	processInfo.Header.Size = uint16(len(processInfo.Marshal()))

	clientConnInfo := AUXClientConnectionInfo{ConnectionGUID: CookieGen(), ConnectionAttempts: 0x05, ConnectionFlags: 0x01, ConnectionContextInfo: utils.UniString("")}
	clientConnInfo.Header = AUXHeader{Version: 0x01, Type: 0x4a}
	clientConnInfo.Header.Size = uint16(len(clientConnInfo.Marshal()))

	auxbuf.Buff = []AuxInfo{clientInfo, accountInfo, sessionInfo, processInfo, clientConnInfo}
	auxbuf.RPCHeader.Size = uint16(len(auxbuf.Marshal()) - 10) //account for header size
	auxbuf.RPCHeader.SizeActual = auxbuf.RPCHeader.Size
	req.RgbAuxIn = auxbuf.Marshal()
	req.CbAuxIn = uint32(len(req.RgbAuxIn) - 2)
	req.AuxBufLen = req.CbAuxIn
	req.AuxOut = 0x000001008
	req.Header.FragLen = uint16(len(req.Marshal()))

	RPCWrite(req.Marshal())
	RPCRead(1)

	resp, err := RPCRead(callcounter - 1)

	AuthSession.ContextHandle = resp[28:44]
	if utils.DecodeUint32(AuthSession.ContextHandle[0:4]) == 0x0000 {
		return nil, fmt.Errorf("-- Unable to obtain a session context")
	}
	return resp, err
}

//RPCDisconnect fucntion
func RPCDisconnect() {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: uint32(callcounter)}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.MaxFrag = 0xFFFF
	req.MaxRecv = 0x0000
	req.Header = header
	req.Version = []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00} //opnum 0x01
	req.ContextHandle = AuthSession.ContextHandle
	req.AuxOut = 0x000001008
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
func RPCRead(callID int) ([]byte, error) {
	for {
		for k, v := range responses {
			if v.CallID == uint16(callID) {
				responses = append(responses[:k], responses[k+1:]...)
				return v.Body, nil
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
