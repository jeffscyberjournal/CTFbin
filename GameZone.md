# Game Zone
Understand how to use SQLMap, crack some passwords, reveal services using a reverse SSH tunnel and escalate your privileges to root!
# Task 1

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
