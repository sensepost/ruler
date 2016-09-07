package rpchttp

import (
	"crypto/tls"
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
}

var rpcInData http.Client
var rpcOutData http.Client
var AuthSession utils.Session

func RPCInDataOpen(URL string) (res *http.Response, err error) {
	r, _ := http.NewRequest("RPC_IN_DATA", URL, strings.NewReader(""))
	addRPCHeaders(r)
	r.Header.Add("Content-length", "0")
	//req.SetBasicAuth(NtlmTransport.Email, NtlmTransport.Password)

	rpcInData = http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := rpcInData.Do(r)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			rpcInData = http.Client{}
			resp, err = rpcInData.Do(r)
		} else {
			fmt.Println(err)
			return nil, nil
		}
	}

	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		// it's necessary to reuse the same http connection
		// in order to do that it's required to read Body and close it
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return nil, err
		}
		err = resp.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	return resp, err
}

func (t NtlmTransport) RPCOutDataOpen(req *http.Request) (res *http.Response, err error) {
	r, _ := http.NewRequest("RPC_OUT_DATA", req.URL.String(), strings.NewReader(""))
	addRPCHeaders(r)
	req.Header.Add("Content-length", "0")
	//req.SetBasicAuth(NtlmTransport.Email, NtlmTransport.Password)

	rpcInData := http.Client{
		Transport: &httpntlm.NtlmTransport{
			Domain:   "",
			User:     AuthSession.User,
			Password: AuthSession.Pass,
			Insecure: AuthSession.Insecure,
		},
	}
	resp, err := rpcInData.Do(r)

	if err != nil {
		return nil, err
	}
	if err == nil && resp.StatusCode == http.StatusUnauthorized {

		// it's necessary to reuse the same http connection
		// in order to do that it's required to read Body and close it
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return nil, err
		}
		err = resp.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	return resp, err
}

//RPCAUTH allows us to do the NTLM auth inside the RPC message
func RPCAUTH() (res *http.Response, err error) {
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
	return nil, nil
}
