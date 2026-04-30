# Skynet

## Quick nmap scan:
```
# nmap -Pn -sV -sC <targetIP>
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
Shortlist of SMB shares available

```
root@ip-10-144-94-86:~# smbclient -L //10.144.136.168
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

Find out more about smb by running nmap scripts to enumerate users, shares, and OS discovery.

```
# nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery <targetIP>
...
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.144.136.168\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.144.136.168\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.144.136.168\milesdyson: 
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.144.136.168\print$: 
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

Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
root@ip-10-144-94-86:~# 
```
They the anonymous user milesdyson required a password

```
root@ip-10-144-94-86:~# smbclient \\\\10.144.136.168\\anonymous
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 26 16:04:00 2020
  ..                                  D        0  Tue Sep 17 08:20:17 2019
  attention.txt                       N      163  Wed Sep 18 04:04:59 2019
  logs                                D        0  Wed Sep 18 05:42:16 2019

		9204224 blocks of size 1024. 5831484 blocks available
smb: \> GET attention.txt
getting file \attention.txt of size 163 as attention.txt (53.1 KiloBytes/sec) (average 53.1 KiloBytes/sec)
smb: \> cd logs
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 05:42:16 2019
  ..                                  D        0  Thu Nov 26 16:04:00 2020
  log2.txt                            N        0  Wed Sep 18 05:42:13 2019
  log1.txt                            N      471  Wed Sep 18 05:41:59 2019
  log3.txt                            N        0  Wed Sep 18 05:42:16 2019

		9204224 blocks of size 1024. 5831484 blocks available
```


```
root@ip-10-144-94-86:~# cat log1.txt 
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
root@ip-10-144-94-86:~# cat log2.txt
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
root@ip-10-144-94-86:~# cat log3.txt
root@ip-10-144-94-86:~# ls -la
```

```
root@ip-10-144-94-86:~# cat attention.txt 
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
root@ip-10-144-94-86:~# 
```

## Q1 What is Miles password for his emails?
O
n close inspection after nmap scan pop3 was present and smtp. SMTP appeared to unable to connect to but pop3 seemed to be accessible using a simple netcat ip and port check.
The pop3 service is likely worth trying a hydra password crack using the log1.txt wordlist.
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Tool_Instructions]
└─$ nc 10.48.140.141 25 
(UNKNOWN) [10.48.140.141] 25 (smtp) : Connection refused
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Tool_Instructions]
└─$ nc 10.48.140.141 110                                 
+OK Dovecot ready.
^C
```

Gobuster to search directories:

```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Tool_Instructions]
└─$ gobuster dir -u "THM_Target" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64     
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://THM_Target
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
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
===============================================================
```
Squirrelmail seemed worth a look so tried in the browswer and there was a login screen for squirrel mail. The version on the page was 1.4.23. Through exploit-db there was one RCE exploit present that suited SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692). The catch was a password and username was required to access it which is why hydra seemed worth a shot. 

- For some unknown reason no joy with hydra. 

- Burpesuite seemed like next best option.
	- I simply ip/squirrelmail to access login page
 	- Started burpesuite then initiated foxy proxy
  	- used milesdyson as the username as its likely same name for email account
  	- Then just one sniper attack on the one variable
  	- The password was found in the list. Its listed twice.
  Answer: cyborg007haloterminator

