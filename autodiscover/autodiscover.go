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
var SessionConfig *utils.Config

//the xml for the autodiscover service
const autodiscoverXML = `<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
<Request><EMailAddress>{{.Email}}</EMailAddress>
<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
</Request></Autodiscover>`

//Config containing the session variables
type Config struct {
	Domain   string
	User     string
	Pass     string
	Email    string
	Insecure bool
}

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
func createAutodiscover(domain string) string {
	//create autodiscover.domain.com
	autodiscoverDomain := fmt.Sprintf("autodiscover.%s", domain)
	_, err := net.LookupHost(autodiscoverDomain) //check if valid autodiscover domain

	if err != nil {
		_, err = net.LookupHost(domain)
		if err != nil {
			return ""
		}
		return fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain)
	}
	return fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", autodiscoverDomain)

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
				Domain:   "",
				User:     SessionConfig.User,
				Password: SessionConfig.Pass,
				Insecure: SessionConfig.Insecure,
			},
		}
	}

	var autodiscoverURL string
	//check if this is just a domain or a redirect (starts with http[s]://)
	if m, _ := regexp.Match("http[s]://", []byte(domain)); m == true {
		autodiscoverURL = domain
	} else {
		//create the autodiscover url
		autodiscoverURL = createAutodiscover(domain)
		if autodiscoverURL == "" {
			return nil, fmt.Errorf("[x] Invalid domain or no autodiscover DNS record found")
		}
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
		//fmt.Println(string(body))
		err := autodiscoverResp.Unmarshal(body)
		//fmt.Println(string(body))
		if err != nil {
			return nil, fmt.Errorf("[x] Error in autodiscover response, %s", err)
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
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("[x] Permission Denied: StatusCode [%d]\n", resp.StatusCode)
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

	//return the new autodiscover server location
	return resp.Header.Get("Location")

}
