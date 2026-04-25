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
