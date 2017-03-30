package httpntlm

//Forked from https://github.com/vadimi/go-http-ntlm
//All credits go to them
//Used under MIT License -- see LICENSE for details
//Modified code --
// r.Header.Add("Authorization", "NTLM "+encBase64(negotiateSP()))
// 	session, err := ntlm.CreateClientSession(ntlm.Version1, ntlm.ConnectionlessMode)

import (
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/sensepost/ruler/utils"
	"github.com/staaldraad/go-ntlm/ntlm"
)

// NtlmTransport is implementation of http.RoundTripper interface
type NtlmTransport struct {
	Domain    string
	User      string
	Password  string
	NTHash    []byte
	Insecure  bool
	CookieJar *cookiejar.Jar
}

// RoundTrip method send http request and tries to perform NTLM authentication
func (t NtlmTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {

	session, err := ntlm.CreateClientSession(ntlm.Version1, ntlm.ConnectionlessMode)
	if err != nil {
		return nil, err
	}

	session.SetUserInfo(t.User, t.Password, t.Domain)

	if len(t.NTHash) > 0 {
		session.SetNTHash(t.NTHash)
	}

	b, _ := session.GenerateNegotiateMessage()
	// first send NTLM Negotiate header
	r, _ := http.NewRequest("GET", req.URL.String(), strings.NewReader(""))
	r.Header.Add("Authorization", "NTLM "+utils.EncBase64(b.Bytes()))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: t.Insecure},
	}

	client := http.Client{Transport: tr, Timeout: time.Minute, Jar: t.CookieJar}

	resp, err := client.Do(r)

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

		// retrieve Www-Authenticate header from response

		ntlmChallengeHeader := resp.Header.Get("WWW-Authenticate")
		if ntlmChallengeHeader == "" {
			return nil, errors.New("Wrong WWW-Authenticate header")
		}

		ntlmChallengeString := strings.Replace(ntlmChallengeHeader, "NTLM ", "", -1)
		challengeBytes, err := utils.DecBase64(ntlmChallengeString)
		if err != nil {
			return nil, err
		}

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
		//fmt.Printf("%x\n", authenticate.Bytes())
		if err != nil {
			return nil, err
		}

		// set NTLM Authorization header
		req.Header.Set("Authorization", "NTLM "+utils.EncBase64(authenticate.Bytes()))

		resp, err = client.Do(req)
	}
	return resp, err
}
