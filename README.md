# Introduction

Ruler is a tool that allows you to interact with Exchange servers remotely, through either the MAPI/HTTP or RPC/HTTP protocol. The main aim is abuse the client-side Outlook features and gain a shell remotely.

The full low-down on how Ruler was implemented and some background regarding MAPI can be found in our blog posts:
* [Ruler release]
* [Pass the Hash with Ruler]
* [Outlook forms and shells].

For a demo of it in action: [Ruler on YouTube]

## What does it do?

Ruler has multiple functions and more are planned. These include

* Enumerate valid users
* Create new malicious mail rules
* Dump the Global Address List (GAL)
* VBScript execution through forms

Ruler attempts to be semi-smart when it comes to interacting with Exchange and uses the Autodiscover service (just as your Outlook client would) to discover the relevant information.

# Getting Started

Compiled binaries for Linux, OSX and Windows are available. Find these in [Releases]
information about setting up Ruler from source is found in the [getting-started guide].

# Usage

Ruler has multiple functions, these have their own documentation that can be found in the [wiki]:

* [BruteForce] -- discover valid user accounts
* [Rules] -- perform the traditional, rule based attack
* [Forms] -- execute VBScript through forms
* [GAL] -- grab the Global Address List

# Attacking Exchange

The library included with Ruler allows for the creation of custom message using MAPI. This along with the Exchnage documentation is a great starting point for new research. For an example of using this library in another project, see [SensePost Liniaal].

# License
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](http://creativecommons.org/licenses/by-nc-sa/4.0/)

Ruler is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (http://creativecommons.org/licenses/by-nc-sa/4.0/) Permissions beyond the scope of this license may be available at http://sensepost.com/contact/.


[Ruler Release]: <https://sensepost.com/blog/2016/mapi-over-http-and-mailrule-pwnage/>
[Pass the hash with Ruler]: <https://sensepost.com/blog/2017/pass-the-hash-with-ruler/>
[Outlook forms and shells]: <https://sensepost.com/blog/2017/outlook-forms-and-shells/>
[Ruler on YouTube]:<https://www.youtube.com/watch?v=C07GS4M8BZk>
[Releases]: <https://github.com/sensepost/ruler/releases>
[SensePost Liniaal]:<https://github.com/sensepost/liniaal>
[wiki]:<https://github.com/sensepost/ruler/wiki>
[BruteForce]:<https://github.com/sensepost/ruler/wiki/Brute-Force>
[Rules]:<https://github.com/sensepost/ruler/wiki/Rules>
[Forms]:<https://github.com/sensepost/ruler/wiki/Forms>
[GAL]:<https://github.com/sensepost/ruler/wiki/GAL>
[getting-started guide]:<https://github.com/sensepost/ruler/wiki/Getting-Started>
