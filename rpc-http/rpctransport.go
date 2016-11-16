package rpchttp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
	"github.com/sensepost/ruler/utils"
)

type NtlmTransport struct {
	Domain   string
	User     string
	Password string
	Insecure bool
}

func addRPCHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "MSRPC")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Accept", "application/rpc")
	req.Header.Add("Connection", "keep-alive")
}

var rpcInData *http.Response
var rpcOutData *http.Response
var rpcInConn net.Conn
var rpcOutConn net.Conn
var rpcInR, rpcInW = io.Pipe()
var rpcOutR, rpcOutW = io.Pipe()
var rpcRespBody *bufio.Reader

//AuthSession Keep track of session data
var AuthSession *utils.Session

const (
	RPCIN  = 1
	RPCOUT = 2
)

func SetupHTTPNTLM(rpctype string, URL string) (net.Conn, error) {
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

	session, err := ntlm.CreateClientSession(ntlm.Version1, ntlm.ConnectionlessMode)
	if err != nil {
		return nil, err
	}

	session.SetUserInfo(AuthSession.User, AuthSession.Pass, "")
	// parse NTLM challenge
	challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
	if err != nil {
		return nil, err
	}
	err = session.ProcessChallengeMessage(challenge)
	if err != nil {
		return nil, err
	}
	// authenticate user
	authenticate, err := session.GenerateAuthenticateMessage()
	if err != nil {
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
func RPCOpen(URL string) (err error) {
	//I'm so damn frustrated at not being able to use the http client here
	//can't find a way to keep the write channel open (other than going over to http/2, which isn't valid here)
	//so this is some damn messy code, but screw it
	//dataout := []byte{0x05, 0x00, 0x14, 0x03, 0x10, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x38, 0xd8, 0xff, 0xfc, 0x95, 0xb4, 0x6f, 0x7c, 0x40, 0xa5, 0xbe, 0xf2, 0x4d, 0xe2, 0x12, 0x13, 0x03, 0x00, 0x00, 0x00, 0x4b, 0x4b, 0x78, 0x90, 0x04, 0xb8, 0xb6, 0xe3, 0x8a, 0x05, 0x7f, 0x3f, 0x07, 0xe0, 0x5d, 0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xa5, 0xbb, 0x0f, 0xac, 0x97, 0x69, 0xf5, 0x47, 0x8b, 0x97, 0x5f, 0x9a, 0x08, 0xcd, 0x70, 0x02}
	rpcInConn, _ = SetupHTTPNTLM("RPC_IN_DATA", URL)

	go RPCOpenOut(URL)

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

func RPCOpenOut(URL string) error {
	rpcOutConn, _ = SetupHTTPNTLM("RPC_OUT_DATA", URL)

	//Generate out-channel cookie
	//20 byte channel cookie for out-channel
	connB1 := ConnB1()
	//Send CONN/A1
	connA1 := ConnA1(connB1.VirtualConnectCookie.Cookie)
	RPCOutWrite(connA1.Marshal())

	//send CONN/B1
	RPCWrite(connB1.Marshal())
	data := make([]byte, 1024)

	n, _ := rpcOutConn.Read(data) //read the 200 response
	//check we don't have part of an RPC message in here
	for k := range data {
		if len(data) > k+3 {
			if data[k] == 0x0d && data[k+1] == 0x0a && data[k+2] == 0x0d && data[k+3] == 0x0a {
				rpcOutW.Write(data[k+4 : n])
			}
		}
	}
	for {
		data := make([]byte, 1024)
		n, err := rpcOutConn.Read(data)
		if n > 0 {
			//fmt.Printf("Receving some data: %x\n", data)
			rpcOutW.Write(data[:n])
		}
		if err != nil && err != io.EOF {
			fmt.Println(err)
			break
		}
	}
	return nil
}

//RPCBind function establishes our session
func RPCBind() []byte {
	pkt := Bind()
	return pkt.Marshal()
}

//RPCPing fucntion
func RPCPing() []byte {
	pkt := Ping()
	return pkt.Marshal()
}

//RPCRequest does our actual RPC request
//returns the mapi data
func EcDoRpcExt2(mapi []byte) ([]byte, error) {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: 4}
	header.PackedDrep = 16
	req := RTSRequest{}
	req.MaxFrag = 0x0134 //784 //132
	req.MaxRecv = 0x0000
	req.Header = header
	req.Version = []byte{0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00}
	req.ContextHandle = AuthSession.ContextHandle
	req.Data = mapi
	//fmt.Printf("%x\n", mapi)
	//req.Data = append(req.Data, []byte{0x07, 0x80, 0x00, 0x00}...)

	//req.RgbAuxIn = auxbuf.Marshal() //[]byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	req.CbAuxIn = 0x00 //uint32(len(req.RgbAuxIn) - 2)
	req.AuxOut = 0x000001008

	//req.RgbAuxIn = []byte{0x07, 0x80, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x28, 0x00, 0x28, 0x00, 0x08, 0x00, 0x01, 0x01, 0x01, 0x00, 0x75, 0x00, 0x10, 0x00, 0x01, 0x0c, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x0c, 0x10, 0x00, 0x00, 0x00, 0x10}

	/*req.RgbOut = 0x74000000
	req.PcbOut = 0x30000000
	req.RgbAuxOut = 0x0000

	*/
	req.Header.FragLen = uint16(len(req.Marshal()))
	RPCWrite(req.Marshal())
	return RPCRead()
}
func obfuscate(data []byte) []byte {
	bnew := make([]byte, len(data))
	for k := range data {
		bnew[k] = data[k] ^ 0xA5
	}
	return bnew
}

func DoConnectExRequest(MAPI []byte) ([]byte, error) {
	//RPCRead()
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: 3}
	header.PackedDrep = 16
	req := ConnectExRequest{}
	req.Header = header
	req.MaxFrag = 0xffff
	req.MaxRecv = 0x0000
	req.ContextHandle = []byte{0x00, 0x00, 0x0a, 0x00} // 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00, 0x00}

	req.Data = MAPI
	//fmt.Printf("Len: %x\n", len(MAPI))
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
	req.RgbAuxIn = auxbuf.Marshal() //[]byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	req.CbAuxIn = uint32(len(req.RgbAuxIn) - 2)
	req.AuxBufLen = req.CbAuxIn
	req.AuxOut = 0x000001008
	req.Header.FragLen = uint16(len(req.Marshal()))

	RPCWrite(req.Marshal())
	resp, err := RPCRead()
	fmt.Printf("\n\n%x\n%x\n\n", resp[28:44], resp)
	AuthSession.ContextHandle = resp[28:44]
	return resp, err
}

func RPCWrite(data []byte) {
	rpcInW.Write(data)
}

func RPCOutWrite(data []byte) {
	rpcOutConn.Write(data)
}

func RPCRead() ([]byte, error) {
	buf := make([]byte, 2048)
	//var tmp []byte
	//read full request here
	response := make([]byte, 0)

	for {
		n, err := rpcOutR.Read(buf)
		if err != nil {
			return nil, err
		}
		//fmt.Printf("\nRPC READ: %x\n Resp: %x\n Buf: %x\n %d \n", buf[:n], response, buf, n)
		response = append(response, buf[:n]...)
		if n > 20 {
			break
		}
	}

	if response[3] == 0x05 {
		for k := 3; k < len(response); k++ {
			if response[k] == 0x00 {
				response = append([]byte{0x05}, response[k:len(response)-2]...)
				break
			}
		}

	}
	//fmt.Printf("\nRPC READ RESPONSE: %x\n", response)
	return response, nil
}
