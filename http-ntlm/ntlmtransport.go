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
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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
	Proxy     string
	NTHash    []byte
	Insecure  bool
	CookieJar *cookiejar.Jar
	Hostname  string
}

var Transport http.Transport

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
	r.Header.Add("User-Agent", req.UserAgent())

	if t.Proxy == "" {
		Transport = http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: t.Insecure},
		}
	} else {
		proxyURL, e := url.Parse(t.Proxy)
		if e != nil {
			return nil, fmt.Errorf("Invalid proxy url format %s", e)
		}
		Transport = http.Transport{Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: t.Insecure},
		}
	}

	tr := &Transport

	client := http.Client{Transport: tr, Timeout: time.Minute, Jar: t.CookieJar}

	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	if err == nil && resp.StatusCode == http.StatusUnauthorized {

		// it's necessary to reuse the same http connection
		// in order to do that it's required to read Body and close it
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return nil, err
		}
		err = resp.Body.Close()
		if err != nil {
			return nil, err
		}

		// retrieve WWW-Authenticate header from response
		ntlmChallengeHeader := ""
		for _, header := range resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
			if strings.HasPrefix(header, "NTLM") {
				ntlmChallengeHeader = header
			}
		}
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
		authenticate.Workstation, err = ntlm.CreateStringPayload(t.Hostname)
		if err != nil {
			return nil, err
		}

		// set NTLM Authorization header
		req.Header.Set("Authorization", "NTLM "+utils.EncBase64(authenticate.Bytes()))

		resp, err = client.Do(req)
	}
	return resp, err
}
