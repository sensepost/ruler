package rpchttp

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"github.com/sensepost/ruler/http-ntlm"
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

var rpcInData http.Client
var rpcOutData http.Client

//AuthSession Keep track of session data
var AuthSession *utils.Session

const (
	RPCIN  = 1
	RPCOUT = 2
)

//RPCOpen opens HTTP for RPC_IN_DATA or RPC_OUT_DATA
func RPCOpen(rpcType int, URL string) (err error) {
	var method string
	if rpcType == 1 {
		method = "RPC_IN_DATA"
	} else if rpcType == 2 {
		method = "RPC_OUT_DATA"
	} else {
		return fmt.Errorf("Bad rpc type")
	}
	r, _ := http.NewRequest(method, URL, strings.NewReader(" "))
	addRPCHeaders(r)

	rpcData := http.Client{
		Transport: &httpntlm.NtlmTransport{
			Domain:   "",
			User:     AuthSession.User,
			Password: AuthSession.Pass,
			Insecure: AuthSession.Insecure,
		},
		Jar: AuthSession.CookieJar,
	}
	resp, err := rpcData.Do(r)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			rpcInData = http.Client{}
			resp, err = rpcData.Do(r)
		} else {
			fmt.Println(err)
			return nil
		}
	}

	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		// it's necessary to reuse the same http connection
		// in order to do that it's required to read Body and close it
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			fmt.Println(err)
			return err
		}
		err = resp.Body.Close()
		if err != nil {
			fmt.Println(err)
			return err
		}
	}
	fmt.Println(resp)

	if rpcType == 1 {
		rpcInData = rpcData
	} else if rpcType == 2 {
		rpcOutData = rpcData
	}
	return err
}

//Here we need to do MSRPC setup as per docs
/**
 *           Secure Connection-Oriented RPC Packet Sequence
 *
 *     Client                                              Server
 *        |                                                   |
 *        |-------------------SECURE_BIND-------------------->|
 *        |                                                   |
 *        |<----------------SECURE_BIND_ACK-------------------|
 *        |                                                   |
 *        |--------------------RPC_AUTH_3-------------------->|
 *        |                                                   |
 *        |                                                   |
 *        |------------------REQUEST_PDU_#1------------------>|
 *        |------------------REQUEST_PDU_#2------------------>|
 *        |                                                   |
 *        |                        ...                        |
 *        |                                                   |
 *        |<-----------------RESPONSE_PDU_#1------------------|
 *        |<-----------------RESPONSE_PDU_#2------------------|
 *        |                                                   |
 *        |                        ...                        |
 */

func RPC_Bind() {
	header := RTSHeader{Version: 0x5, VersionMinor: 0x0}
	header.PTYPE = DCERPC_PKT_BIND
	header.PfcFlags = PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_SUPPORT_HEADER_SIGN
	header.PackedDREP = (1 << 4) | 0
	header.FragLength = 0
	header.AuthLength = 0
	header.CallID = 1
	fmt.Println(header)
}

//RPCAUTH allows us to do the NTLM auth inside the RPC message
func RPCAuth() (err error) {

	//resp, err = client.Do()
	//session, err := ntlm.CreateClientSession(ntlm.Version1, ntlm.ConnectionlessMode)
	//if err != nil {
	//	return nil, err
	//}
	/*
		session.SetUserInfo(t.User, t.Password, t.Domain)

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

		// set NTLM Authorization header
		//req.Header.Set("Authorization", "NTLM "+encBase64(authenticate.Bytes()))
		resp, err = client.Do(req)

		return resp, err
	*/
	return nil
}
