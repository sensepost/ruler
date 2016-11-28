package autodiscover

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/sensepost/ruler/http-ntlm"
	"github.com/sensepost/ruler/utils"
)

//globals

//SessionConfig holds the configuration for this autodiscover session
var SessionConfig *utils.Session
var autodiscoverStep int

//the xml for the autodiscover service
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

//createAutodiscover generates a domain name of the format autodiscover.domain.com
//and checks if a DNS entry exists for it. If it doesn't it tries DNS for just the domain name.
//returns an empty string if no valid domain was found.
//returns the full (expected) autodiscover URL
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

//Autodiscover function to retrieve mailbox details using the autodiscover mechanism from MS Exchange
func Autodiscover(domain string) (*utils.AutodiscoverResp, error) {
	return autodiscover(domain, false)
}

//MAPIDiscover function to do the autodiscover request but specify the MAPI header
//indicating that the MAPI end-points should be returned
func MAPIDiscover(domain string) (*utils.AutodiscoverResp, error) {
	fmt.Println("[*] Doing Autodiscover for domain")
	return autodiscover(domain, true)
}

func autodiscover(domain string, mapi bool) (*utils.AutodiscoverResp, error) {
	//replace Email with the email from the config
	r, _ := parseTemplate(autodiscoverXML)
	autodiscoverResp := utils.AutodiscoverResp{}
	//for now let's rely on autodiscover.domain/autodiscover/autodiscover.xml
	//var client http.Client
	client := http.Client{}
	if SessionConfig.Basic == false {
		//check if this is a first request or a redirect
		//create an ntml http client
		client = http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:   SessionConfig.Domain,
				User:     SessionConfig.User,
				Password: SessionConfig.Pass,
				NTHash:   SessionConfig.NTHash,
				Insecure: SessionConfig.Insecure,
			},
		}
	}

	var autodiscoverURL string
	//check if this is just a domain or a redirect (starts with http[s]://)

	if m, _ := regexp.Match("http[s]?://", []byte(domain)); m == true {
		autodiscoverURL = domain
	} else {
		//create the autodiscover url
		if autodiscoverStep == 0 {
			autodiscoverURL = createAutodiscover(domain, true)
			if autodiscoverURL == "" {
				autodiscoverStep++
			}
		}
		if autodiscoverStep == 1 {
			autodiscoverURL = createAutodiscover(fmt.Sprintf("autodiscover.%s", domain), true)
			if autodiscoverURL == "" {
				autodiscoverStep++
			}
		}
		if autodiscoverStep == 2 {
			autodiscoverURL = createAutodiscover(fmt.Sprintf("autodiscover.%s", domain), false)
			if autodiscoverURL == "" {
				return nil, fmt.Errorf("[x] Invalid domain or no autodiscover DNS record found")
			}
		}
	}
	if SessionConfig.Verbose == true {
		fmt.Printf("[*] Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)
	}
	req, err := http.NewRequest("POST", autodiscoverURL, strings.NewReader(r))
	req.Header.Add("Content-Type", "text/xml")

	if mapi == true {
		req.Header.Add("X-MapiHttpCapability", "1")            //we want MAPI info
		req.Header.Add("X-AnchorMailbox", SessionConfig.Email) //we want MAPI info
	}

	//if we have been redirected to outlook, change the auth header to basic auth
	if SessionConfig.Basic == false {
		req.SetBasicAuth(SessionConfig.Email, SessionConfig.Pass)
		SessionConfig.BasicAuth = req.Header.Get("WWW-Authenticate")
	} else {
		req.SetBasicAuth(SessionConfig.User, SessionConfig.Pass)
	}
	//request the autodiscover url
	resp, err := client.Do(req)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			client = http.Client{}
			resp, err = client.Do(req)
			if err != nil {
				return nil, err
			}
		} else {
			if autodiscoverStep < 2 {
				autodiscoverStep++
				return autodiscover(domain, mapi)
			}
			//we've done all three steps of autodiscover and all three failed

			return nil, err
		}
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	//check if we got a 200 response
	if resp.StatusCode == 200 {

		err := autodiscoverResp.Unmarshal(body)
		if err != nil {
			if autodiscoverStep < 2 {
				autodiscoverStep++
				return autodiscover(domain, mapi)
			}
			return nil, fmt.Errorf("[x] Error in autodiscover response, %s", err)
		}
		SessionConfig.NTLMAuth = req.Header.Get("Authorization")
		if SessionConfig.Verbose == true {

			fmt.Println(string(body))
		}
		//check if we got a RedirectAddr ,
		//if yes, get the new autodiscover url
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			rediraddr := autodiscoverResp.Response.Account.RedirectAddr
			rediraddr = regexp.MustCompile(".*@").Split(rediraddr, 2)[1]
			return autodiscover(redirectAutodiscover(rediraddr), mapi)
		}
		return &autodiscoverResp, nil
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		if autodiscoverStep < 2 {
			autodiscoverStep++
			return autodiscover(domain, mapi)
		}
		return nil, fmt.Errorf("[x] Permission Denied or URL not found: StatusCode [%d]\n", resp.StatusCode)
	}
	if autodiscoverStep < 2 {
		autodiscoverStep++
		return autodiscover(domain, mapi)
	}
	return nil, fmt.Errorf("[x] Got an unexpected result: StatusCode [%d] %s\n", resp.StatusCode, body)
}

func redirectAutodiscover(redirdom string) string {
	fmt.Printf("[*] Redirected with new address [%s]\n", redirdom)
	//create the autodiscover url
	autodiscoverURL := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", redirdom)
	req, _ := http.NewRequest("GET", autodiscoverURL, nil)
	var DefaultTransport http.RoundTripper = &http.Transport{}
	resp, _ := DefaultTransport.RoundTrip(req)
	defer resp.Body.Close()
	fmt.Printf("[*] Authenticating through: %s\n", string(resp.Header.Get("Location")))
	//return the new autodiscover server location
	return resp.Header.Get("Location")

}
