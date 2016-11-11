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

func SetupHTTPNTLM(rpctype string, URL string, dataout []byte) (net.Conn, error) {
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
		request = fmt.Sprintf("%sContent-Length: %d\r\n", request, len(dataout))
	}
	request = fmt.Sprintf("%sAuthorization: NTLM %s\r\n\r\n", request, utils.EncBase64(authenticate.Bytes()))

	connection.Write([]byte(request))

	if rpctype == "RPC_OUT_DATA" {
		//connection.Write(dataout)
	}

	return connection, nil
}

//RPCOpen opens HTTP for RPC_IN_DATA and RPC_OUT_DATA
func RPCOpen(URL string) (err error) {
	//I'm so damn frustrated at not being able to use the http client here
	//can't find a way to keep the write channel open (other than going over to http/2, which isn't valid here)
	//so this is some damn messy code, but screw it
	//dataout := []byte{0x05, 0x00, 0x14, 0x03, 0x10, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x38, 0xd8, 0xff, 0xfc, 0x95, 0xb4, 0x6f, 0x7c, 0x40, 0xa5, 0xbe, 0xf2, 0x4d, 0xe2, 0x12, 0x13, 0x03, 0x00, 0x00, 0x00, 0x4b, 0x4b, 0x78, 0x90, 0x04, 0xb8, 0xb6, 0xe3, 0x8a, 0x05, 0x7f, 0x3f, 0x07, 0xe0, 0x5d, 0xb7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xa5, 0xbb, 0x0f, 0xac, 0x97, 0x69, 0xf5, 0x47, 0x8b, 0x97, 0x5f, 0x9a, 0x08, 0xcd, 0x70, 0x02}
	rpcInConn, _ = SetupHTTPNTLM("RPC_IN_DATA", URL, nil)

	go RPCOpenOut(URL)

	for {
		data := make([]byte, 2048)
		n, err := rpcInR.Read(data)
		if n > 0 {
			fmt.Printf("sending some data: %x\n", data[:n])
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

	dataout := make([]byte, 76)
	rpcOutConn, _ = SetupHTTPNTLM("RPC_OUT_DATA", URL, dataout)

	for {
		data := make([]byte, 1024)
		n, err := rpcOutConn.Read(data)
		if n > 0 {
			fmt.Printf("Receving some data: %x\n", data)
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
func RPCRequest(mapi []byte) ([]byte, error) {
	header := RTSHeader{Version: 0x05, VersionMinor: 0, Type: DCERPC_PKT_REQUEST, PFCFlags: 0x03, AuthLen: 0, CallID: 2}
	req := RTSRequest{}
	req.Header = header
	req.Flags = 0x84
	req.NumberOfCommands = 0x01
	req.DontKnow = []byte{0x00, 0x00, 0x0a, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00}
	req.Data = mapi
	//req.Sec = RTSSec{0x1008}
	req.Header.FragLen = uint16(len(req.Marshal()))
	RPCWrite(req.Marshal())
	return RPCRead()
}

func RPCWrite(data []byte) {
	rpcInW.Write(data)
}

func RPCOutWrite(data []byte) {
	rpcOutConn.Write(data)
}

func RPCRead() ([]byte, error) {
	buf := make([]byte, 2048)
	n, err := rpcOutR.Read(buf)
	if err != nil {
		return nil, err
	}
	fmt.Printf("\nThis was read here\n%x\n%s", buf[:n], err)
	return buf[:n], nil
}
