package autodiscover

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/template"

	httpntlm "github.com/sensepost/ruler/http-ntlm"
	"github.com/sensepost/ruler/utils"
)

//globals

// SessionConfig holds the configuration for this autodiscover session
var SessionConfig *utils.Session
var autodiscoverStep int
var secondaryEmail string //a secondary email to use, edge case seen in office365
var Transport http.Transport
var basicAuth = false

// the xml for the autodiscover service
const autodiscoverXML = `<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
<Request><EMailAddress>{{.Email}}</EMailAddress>
<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
</Request></Autodiscover>`

func parseTemplate(tmpl string) (string, error) {
	t := template.Must(template.New("tmpl").Parse(tmpl))

	var buff bytes.Buffer
	err := t.Execute(&buff, SessionConfig)
	if err != nil {
		return "", err
	}
	return buff.String(), nil
}

// createAutodiscover generates a domain name of the format autodiscover.domain.com
// and checks if a DNS entry exists for it. If it doesn't it tries DNS for just the domain name.
// returns an empty string if no valid domain was found.
// returns the full (expected) autodiscover URL
func createAutodiscover(domain string, https bool) string {
	_, err := net.LookupHost(domain)
	if err != nil {
		return ""
	}
	if https == true {
		return fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain)
	}
	return fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain)
}

// GetMapiHTTP gets the details for MAPI/HTTP
func GetMapiHTTP(email, autoURLPtr string, resp *utils.AutodiscoverResp) (*utils.AutodiscoverResp, string, error) {
	//var resp *utils.AutodiscoverResp
	var err error
	var rawAutodiscover string

	if autoURLPtr == "" && resp == nil {
		utils.Info.Println("Retrieving MAPI/HTTP info")
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(email, "@")
		if lastBin == -1 {
			return nil, "", fmt.Errorf("The supplied email address seems to be incorrect.\n%s", err)
		}
		maildomain := email[lastBin+1:]
		resp, rawAutodiscover, err = MAPIDiscover(maildomain)
	} else if resp == nil {
		resp, rawAutodiscover, err = MAPIDiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		return nil, "", fmt.Errorf("The autodiscover service request did not complete.\n%s", err)
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		return nil, "", fmt.Errorf("The autodiscover service responded with an error.\n%s", resp.Response.Error.Message)
	}
	return resp, rawAutodiscover, nil
}

// GetRPCHTTP exports the RPC details for RPC/HTTP
func GetRPCHTTP(email, autoURLPtr string, resp *utils.AutodiscoverResp) (*utils.AutodiscoverResp, string, string, string, bool, error) {
	//var resp *utils.AutodiscoverResp
	var err error
	var rawAutodiscover string

	if autoURLPtr == "" && resp == nil {
		utils.Info.Println("Retrieving RPC/HTTP info")
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(email, "@")
		if lastBin == -1 {
			return nil, "", "", "", false, fmt.Errorf("The supplied email address seems to be incorrect.\n%s", err)
		}
		maildomain := email[lastBin+1:]
		resp, rawAutodiscover, err = Autodiscover(maildomain)
	} else if resp == nil {
		resp, rawAutodiscover, err = Autodiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		return nil, "", "", "", false, fmt.Errorf("The autodiscover service request did not complete.\n%s", err)
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		return nil, "", "", "", false, fmt.Errorf("The autodiscover service responded with an error.\n%s", resp.Response.Error.Message)
	}

	url := ""
	user := ""
	ntlmAuth := false
	firstExHTTPResp := true

	for _, v := range resp.Response.Account.Protocol {
		// use the first available Outlook provider and skip the others
		if url == "" {
			// ExHTTP (Exchange 2013+)
			// the first ExHTTP answer is for internal Outlook clients
			// and the second one is for external Outlook clients
			// EXPR (Exchange 2007/2010) is for external Outlook clients
			if v.Type == "EXHTTP" || v.Type == "EXPR" {
				if v.Type == "EXHTTP" {
					// skip the first answer
					if firstExHTTPResp == true {
						firstExHTTPResp = false
						continue
					}
				}

				if SessionConfig.Verbose == true {
					utils.Trace.Printf("%s provider was selected", v.Type)
				}

				if v.SSL == "Off" {
					url = "http://" + v.Server
				} else {
					url = "https://" + v.Server
				}

				if SessionConfig.Basic == true {
					basicAuth = true
				} else {
					if v.AuthPackage == "Ntlm" || v.AuthPackage == "Negotiate" { //set the encryption on if the server specifies NTLM or Negotiate auth
						ntlmAuth = true
					}
				}
			}
		}
		// EXCH (Exchange 2007/2010) is for internal Outlook clients
		if v.Type == "EXCH" {
			user = v.Server
		}
	}

	if SessionConfig.Verbose == true {
		if ntlmAuth == true {
			utils.Trace.Printf("Authentication scheme is NTLM")
		} else {
			utils.Trace.Printf("Authentication scheme is Basic")
		}
	}

	//possibly office365 with forced RPC/HTTP
	if user == "" {
		if resp.Response.Account.MicrosoftOnline == true {
			lindex := strings.LastIndex(resp.Response.Account.Protocol[0].MailStore.ExternalUrl, "=")
			user = resp.Response.Account.Protocol[0].MailStore.ExternalUrl[lindex+1:]
			if user == "" {
				return nil, "", "", "", false, fmt.Errorf("The user is undefined")
			}

			url = "https://outlook.office365.com"
		}

		return nil, "", "", "", false, fmt.Errorf("The user is undefined")
	}

	RPCURL := fmt.Sprintf("%s/rpc/rpcproxy.dll?%s:6001", url, user)

	utils.Trace.Printf("RPC URL set: %s\n", RPCURL)

	return resp, rawAutodiscover, RPCURL, user, ntlmAuth, nil
}

// CheckCache checks to see if there is a stored copy of the autodiscover record
func CheckCache(email string) *utils.AutodiscoverResp {
	//check the cache folder for a stored autodiscover record
	email = strings.Replace(email, "@", "_", -1)
	email = strings.Replace(email, ".", "_", -1)
	path := fmt.Sprintf("./logs/%s.cache", email)

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		utils.Error.Println(err)
		return nil
	}
	utils.Info.Println("Found cached Autodiscover record. Using this (use --nocache to force new lookup)")
	data, err := os.ReadFile(path)
	if err != nil {
		utils.Error.Println("Error reading stored record ", err)
		return nil
	}
	autodiscoverResp := utils.AutodiscoverResp{}
	autodiscoverResp.Unmarshal(data)
	return &autodiscoverResp
}

// CreateCache function stores the raw autodiscover record to file
func CreateCache(email, autodiscover string) {

	if autodiscover == "" { //no autodiscover record passed in, don't try write
		return
	}
	email = strings.Replace(email, "@", "_", -1)
	email = strings.Replace(email, ".", "_", -1)
	path := fmt.Sprintf("./logs/%s.cache", email)
	if _, err := os.Stat("./logs"); err != nil {
		if os.IsNotExist(err) {
			//create the logs directory
			if err := os.MkdirAll("./logs", 0711); err != nil {
				utils.Error.Println("Couldn't create a cache directory")
			}
			//return nil
		}
	}
	fout, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0666)
	_, err := fout.WriteString(autodiscover)
	if err != nil {
		utils.Error.Println("Couldn't write to file for some reason..", err)
	}
}

// Autodiscover function to retrieve mailbox details using the autodiscover mechanism from MS Exchange
func Autodiscover(domain string) (*utils.AutodiscoverResp, string, error) {
	if SessionConfig.Proxy == "" {
		Transport = http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: SessionConfig.Insecure},
		}
	} else {
		proxyURL, err := url.Parse(SessionConfig.Proxy)
		if err != nil {
			return nil, "", fmt.Errorf("Invalid proxy url format %s", err)
		}
		Transport = http.Transport{Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: SessionConfig.Insecure},
		}
	}
	return autodiscover(domain, false)
}

// MAPIDiscover function to do the autodiscover request but specify the MAPI header
// indicating that the MAPI end-points should be returned
func MAPIDiscover(domain string) (*utils.AutodiscoverResp, string, error) {
	//set transport
	if SessionConfig.Proxy == "" {
		Transport = http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: SessionConfig.Insecure},
		}
	} else {
		proxyURL, err := url.Parse(SessionConfig.Proxy)
		if err != nil {
			return nil, "", fmt.Errorf("Invalid proxy url format %s", err)
		}
		Transport = http.Transport{Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: SessionConfig.Insecure},
		}
	}
	return autodiscover(domain, true)
}

func autodiscover(domain string, mapi bool) (*utils.AutodiscoverResp, string, error) {
	//replace Email with the email from the config
	r, _ := parseTemplate(autodiscoverXML)
	autodiscoverResp := utils.AutodiscoverResp{}
	//for now let's rely on autodiscover.domain/autodiscover/autodiscover.xml
	//var client http.Client
	client := http.Client{Transport: &Transport}

	if SessionConfig.Basic == false {
		//check if this is a first request or a redirect
		//create an ntml http client

		client = http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:    SessionConfig.Domain,
				User:      SessionConfig.User,
				Password:  SessionConfig.Pass,
				NTHash:    SessionConfig.NTHash,
				Insecure:  SessionConfig.Insecure,
				CookieJar: SessionConfig.CookieJar,
				Proxy:     SessionConfig.Proxy,
				Hostname:  SessionConfig.Hostname,
			},
			Jar: SessionConfig.CookieJar,
		}

	}

	var autodiscoverURL string
	//check if this is just a domain, a redirect or a url (starts with http[s]://)
	if m, _ := regexp.Match("http[s]?://", []byte(domain)); m == true {
		autodiscoverURL = domain
	} else {
		//create the autodiscover url
		if autodiscoverStep == 0 {
			autodiscoverURL = createAutodiscover(fmt.Sprintf("autodiscover.%s", domain), true)
			if autodiscoverURL == "" {
				autodiscoverStep++
			}
		}
		if autodiscoverStep == 1 {
			autodiscoverURL = createAutodiscover(fmt.Sprintf("autodiscover.%s", domain), false)
			if autodiscoverURL == "" {
				autodiscoverStep++
			}
		}
		if autodiscoverStep == 2 {
			autodiscoverURL = createAutodiscover(domain, true)
			if autodiscoverURL == "" {
				return nil, "", fmt.Errorf("Invalid domain or no autodiscover DNS record found")
			}
		}
	}
	utils.Trace.Printf("Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)

	req, err := http.NewRequest("POST", autodiscoverURL, strings.NewReader(r))
	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("User-Agent", SessionConfig.UserAgent)

	if mapi == true {
		req.Header.Add("X-MapiHttpCapability", "1")            //we want MAPI info
		req.Header.Add("X-AnchorMailbox", SessionConfig.Email) //we want MAPI info
	}

	if SessionConfig.Basic == true {
		if SessionConfig.Domain != "" {
			req.SetBasicAuth(SessionConfig.Domain+"\\"+SessionConfig.User, SessionConfig.Pass)
		} else {
			req.SetBasicAuth(SessionConfig.Email, SessionConfig.Pass)
		}
	}

	//request the autodiscover url
	resp, err := client.Do(req)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			client = http.Client{Transport: InsecureRedirectsO365{User: SessionConfig.Email, Pass: SessionConfig.Pass, Insecure: SessionConfig.Insecure}}
			resp, err = client.Do(req)
			if err != nil {
				return nil, "", err
			}
			basicAuth = true
		} else {
			if autodiscoverStep < 2 {
				autodiscoverStep++
				return autodiscover(domain, mapi)
			}
			//we've done all three steps of autodiscover and all three failed
			return nil, "", err
		}
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	//check if we got a 200 response
	if resp.StatusCode == 200 {
		if basicAuth == true { // don't overwrite --basic as pointed out here: https://github.com/sensepost/ruler/issues/67
			SessionConfig.Basic = basicAuth
		}
		err := autodiscoverResp.Unmarshal(body)
		if err != nil {
			if SessionConfig.Verbose == true {
				utils.Error.Printf("%s\n", err)
			}
			if autodiscoverStep < 2 {
				autodiscoverStep++
				return autodiscover(domain, mapi)
			}
			return nil, "", fmt.Errorf("Error in autodiscover response, %s", err)
		}
		SessionConfig.NTLMAuth = req.Header.Get("Authorization")

		//check if we got a RedirectAddr ,
		//if yes, get the new autodiscover url
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			rediraddr := autodiscoverResp.Response.Account.RedirectAddr
			redirAddrs := strings.Split(rediraddr, "@") //regexp.MustCompile(".*@").Split(rediraddr, 2)

			secondaryEmail = fmt.Sprintf("%s@%s", redirAddrs[0], domain)
			red, err := redirectAutodiscover(redirAddrs[1])
			if err != nil {
				return nil, "", err
			}
			return autodiscover(red, mapi)
		}
		return &autodiscoverResp, string(body), nil
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		//for office365 we might need to use a different email address, try this
		if resp.StatusCode == 401 && secondaryEmail != "" {
			utils.Trace.Printf("Authentication failed with primary email, trying secondary email [%s]\n", secondaryEmail)
			SessionConfig.Email = secondaryEmail
			return autodiscover(domain, mapi)
		}

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			var authMethods []string
			var currentAuthMethod string
			var found = false

			if SessionConfig.Basic == true {
				currentAuthMethod = "Basic"
			} else {
				currentAuthMethod = "NTLM"
			}

			for _, header := range resp.Header[http.CanonicalHeaderKey("WWW-Authenticate")] {
				authMethods = append(authMethods, header)

				if strings.HasPrefix(header, currentAuthMethod) {
					found = true
				}
			}

			if !found {
				if SessionConfig.Verbose == true {
					utils.Trace.Printf("Available authentication scheme(s): %s", strings.Join(authMethods, ", "))
				}

				err := "It looks like that this authentication scheme is not supported"
				if SessionConfig.Basic == true {
					err += ". Try to remove --basic option or specify --rpc option"
				}

				return nil, "", fmt.Errorf(err)
			}

			return nil, autodiscoverURL, fmt.Errorf("Access denied. Check your credentials")
		}

		if m, _ := regexp.Match("http[s]?://", []byte(domain)); m == true {
			return nil, "", fmt.Errorf("Failed to authenticate: StatusCode [%d]\n", resp.StatusCode)
		}
		if autodiscoverStep < 2 {
			autodiscoverStep++
			return autodiscover(domain, mapi)
		}
		return nil, "", fmt.Errorf("Permission Denied or URL not found: StatusCode [%d]\n", resp.StatusCode)
	}
	if SessionConfig.Verbose == true {
		utils.Error.Printf("Failed, StatusCode [%d]\n", resp.StatusCode)
	}
	if autodiscoverStep < 2 {
		autodiscoverStep++
		return autodiscover(domain, mapi)
	}
	return nil, "", fmt.Errorf("Got an unexpected result: StatusCode [%d] %s\n", resp.StatusCode, body)
}

func redirectAutodiscover(redirdom string) (string, error) {
	utils.Trace.Printf("Redirected with new address [%s]\n", redirdom)
	//create the autodiscover url
	autodiscoverURL := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", redirdom)
	req, _ := http.NewRequest("GET", autodiscoverURL, nil)
	var DefaultTransport = &Transport
	resp, err := DefaultTransport.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	utils.Trace.Printf("Authenticating through: %s\n", string(resp.Header.Get("Location")))
	//return the new autodiscover server location
	return resp.Header.Get("Location"), nil
}

// InsecureRedirectsO365 allows forwarding the Authorization header even when we shouldn't
type InsecureRedirectsO365 struct {
	Transport http.RoundTripper
	User      string
	Pass      string
	Insecure  bool
}

// RoundTrip custom redirector that allows us to forward the auth header, even when the domain changes.
// This is needed as some office365 domains will redirect from autodiscover.domain.com to autodiscover.outlook.com
// and Go does not forward Sensitive headers such as Authorization (https://golang.org/src/net/http/client.go#41)
func (l InsecureRedirectsO365) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	t := l.Transport

	if t == nil {
		t = &Transport
	}
	resp, err = t.RoundTrip(req)
	if err != nil {
		return
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect:

		utils.Trace.Printf("Request for %s redirected. Following to %s\n", req.URL, resp.Header.Get("Location"))

		URL, _ := url.Parse(resp.Header.Get("Location"))
		r, _ := parseTemplate(autodiscoverXML)
		//if the domains are different, we need to force the auth cookie to be passed along.. this is for redirects to office365
		client := http.Client{Transport: t}

		req, err = http.NewRequest("POST", URL.String(), strings.NewReader(r))
		req.Header.Add("Content-Type", "text/xml")
		req.Header.Add("User-Agent", SessionConfig.UserAgent)

		req.Header.Add("X-MapiHttpCapability", "1") //we want MAPI info
		req.Header.Add("X-AnchorMailbox", l.User)   //we want MAPI info

		req.URL, _ = url.Parse(resp.Header.Get("Location"))
		req.SetBasicAuth(l.User, l.Pass)

		resp, err = client.Do(req)

	}
	return
}
