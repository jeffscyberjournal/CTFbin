# WGEL CTF
## Objectives:
- Obtain the user flag
- Obtain the root flag

Start with nmap scan:
- root@ip-10-201-64-140:~# nmap -A -p20-10000 10.201.98.216

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2025-11-19 15:23 GMT
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.201.98.216
Host is up (0.00071s latency).
Not shown: 9979 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 16:FF:F0:D4:EE:AD (Unknown)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.10 - 3.13
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.71 ms 10.201.98.216

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds
root@ip-10-201-64-140:~# 
```
##This tells use: 
- SSH with openssh7.2p2
- OpenSSH 7.2p2 — Known Vulnerabilities
    - OpenSSH 7.2p2, released in 2016, has several documented weaknesses:
    - CVE-2016-0777 & CVE-2016-0778: Vulnerabilities in the roaming feature could allow information leakage and remote code execution. These were severe enough to prompt emergency patches.
![OpenSSH 7.2p2](WGEL_OPENSHH_EXPLOIT_DB.png)
- CVE-2016-10009: A flaw in privilege separation could allow local privilege escalation.
- CVE-2016-1908: A race condition in sshd could lead to denial of service.
### Recommendation: Disable the roaming feature (if not already patched) and upgrade to a newer OpenSSH version (e.g., 9.x) to mitigate these risks.

- Exploit-db did have one option, an unverified method to enumerate, however a username jessie is determined in the index.html from a comment later on.
Seachsploit also shows two exploits both enumeration related.


![WGEL Searchsploit OpenSSH Screenshot](WGEL_SEARCHSPLOIT_OPENSSH.png)

- HTTP Apache httpd 2.4.18
  Apache HTTP Server 2.4.18 — Known Vulnerabilities
     Apache 2.4.18 has been affected by several CVEs over the years. Key issues include:
	• CVE-2018-17189: HTTP/2 slow request handling could tie up server threads, similar to a Slowloris attack.
	• CVE-2019-0196: HTTP/2 request handling could access freed memory, leading to potential crashes or data leaks.
	• CVE-2024-40725 & CVE-2024-40898: Affect versions up to 2.4.61, including 2.4.18. These allow HTTP request smuggling and SSL client authentication bypass, potentially leading to unauthorized access.
	• Multiple DoS and memory corruption issues have been reported between 2016 and 2025, with varying severity.
     Recommendation: Upgrade to Apache 2.4.58 or later, which includes fixes for recent HTTP/2 vulnerabilities.


Before we consider vulnerabilities let's check the webserver has content:
The website appear to be normal default apache website:
![Apache2 default screen](WGEL_Default_apache_page.png)

The only thing unusual is the comment inside:
Jessie might be worth using later.

![Potential User name found in html code](WGEL_Default_apache_page_jessie_comment.png)

Let's run dirbuster to gain idea of what directory structure and files are directly accessible from IP address only/.

- gobuster dir -u http://TARGET-IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -x php,txt,html -e -k
```text
root@ip-ATTACKBOXIP:/usr/share/wordlists/SecLists/Discovery/Web-Content# gobuster dir -u http://TARGET-IP -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -x php,txt,html -e -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.98.216
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.201.98.216/sitemap              (Status: 301) [Size: 316] [--> http://10.201.98.216/sitemap/]
http://10.201.98.216/index.html           (Status: 200) [Size: 11374]
http://10.201.98.216/server-status        (Status: 403) [Size: 278]
http://10.201.98.216/.html                (Status: 403) [Size: 278]
Progress: 84649 / 120004 (70.54%)[ERROR] parse "http://10.201.98.216/besalu\t.txt": net/url: invalid control character in URL
[ERROR] parse "http://10.201.98.216/besalu\t.html": net/url: invalid control character in URL
[ERROR] parse "http://10.201.98.216/besalu\t.php": net/url: invalid control character in URL
Progress: 90837 / 120004 (75.69%)[ERROR] parse "http://10.201.98.216/error\x1f_log": net/url: invalid control character in URL
[ERROR] parse "http://10.201.98.216/error\x1f_log.php": net/url: invalid control character in URL
[ERROR] parse "http://10.201.98.216/error\x1f_log.txt": net/url: invalid control character in URL
[ERROR] parse "http://10.201.98.216/error\x1f_log.html": net/url: invalid control character in URL
Progress: 120000 / 120004 (100.00%)
===============================================================
Finished
===============================================================
```

index.html looks of interest here. But accessing the website by IP takes us there by default.
Sitemap however looked like worth a try:


