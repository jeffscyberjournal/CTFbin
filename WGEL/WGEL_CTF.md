# WGEL CTF
## Objectives:
- Obtain the user flag
- Obtain the root flag

Start with nmap scan:
- root@AttackerIP:~# nmap -A -p20-10000 <target>

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2025-11-19 15:23 GMT
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for targetip
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
1   0.71 ms targetip

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds
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
	- CVE-2018-17189: HTTP/2 slow request handling could tie up server threads, similar to a Slowloris attack.
	- CVE-2019-0196: HTTP/2 request handling could access freed memory, leading to potential crashes or data leaks.
	- CVE-2024-40725 & CVE-2024-40898: Affect versions up to 2.4.61, including 2.4.18. These allow HTTP request smuggling and SSL client authentication bypass, potentially leading to unauthorized access.
	- Multiple DoS and memory corruption issues have been reported between 2016 and 2025, with varying severity.
    - Recommendation: Upgrade to Apache 2.4.58 or later, which includes fixes for recent HTTP/2 vulnerabilities.


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
[+] Url:                     http://targetip
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
http://targetip/sitemap              (Status: 301) [Size: 316] [--> http://targetip/sitemap/]
http://targetip/index.html           (Status: 200) [Size: 11374]
http://targetip/server-status        (Status: 403) [Size: 278]
http://targetip/.html                (Status: 403) [Size: 278]
Progress: 84649 / 120004 (70.54%)[ERROR] parse "http://targetip/besalu\t.txt": net/url: invalid control character in URL
[ERROR] parse "http://targetip/besalu\t.html": net/url: invalid control character in URL
[ERROR] parse "http://targetip/besalu\t.php": net/url: invalid control character in URL
Progress: 90837 / 120004 (75.69%)[ERROR] parse "http://targetip/error\x1f_log": net/url: invalid control character in URL
[ERROR] parse "http://targetip6/error\x1f_log.php": net/url: invalid control character in URL
[ERROR] parse "http://targetip/error\x1f_log.txt": net/url: invalid control character in URL
[ERROR] parse "http://targetip/error\x1f_log.html": net/url: invalid control character in URL
Progress: 120000 / 120004 (100.00%)
===============================================================
Finished
===============================================================
```

index.html looks of interest here. But accessing the website by IP takes us there by default.
Sitemap however looked like worth a try:

![Sitemap](WGEL_Sitemap.png)

An alternate dirbuster scan with (Same results more or less).

```text
root@AttackerIP:~# gobuster dir -u http://targetip/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html -e -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://targetip/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
...Several lines of                       (Status: 403) [Size: 278]
...
http://targetip/index.html           (Status: 200) [Size: 11374]
http://targetip/index.html           (Status: 200) [Size: 11374]
...
http://targetip/sitemap              (Status: 301) [Size: 316] [--> http://targetip/sitemap/]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
```

This time check sitemap directory and try a different

```text
root@AttackerIP:~# gobuster dir -u http://targetip/sitemap/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html -e -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://target/sitemap/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
...Several lines of                               (Status: 403) [Size: 278]
...
http://targetip/sitemap/.ssh                 (Status: 301) [Size: 321] [--> http://targetip/sitemap/.ssh/]
... Several more lines
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
root@AttackerIP:~#
```

Just checking that folder seems to have the same status as images and fonts folders. Sure enough it could be accessed.

![Sitemap directory](WGEL_SitemapDirectory.png)

pening in new window: This appears to be a private key that we can use to access the server.

```text
  GNU nano 4.8                                        key                                                   
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2mujeBv3MEQFCel8yvjgDz066+8Gz0W72HJ5tvG8bj7Lz380
... Several lines later
jL8g9yBg4vPB8dHC6JeJpFFE06vxQMFzn6vjEab9GhnpMihrSCod
-----END RSA PRIVATE KEY-----
```

Use key of jessie to gain access.

![Use found ssh key](WGEL_USE_PRIVATE_SSH_KEY_FROM_SITEMAP_FOLDER.png)

Search around and found the user flag in Documents folder of jessie. Also checked the sudo -l for sudo privileges the user has.

![Get flag and check what privilege user has](WGEL_Find_jessie_FLAG.png)

Here wget has root privilege and makes it suitable to use to obtain the root flag using what we can find in gtfobins

Shell break out might be option but its not necessary a simple file transfer of passwd and shadow might be all that necessary. To gain root access.

![WGEL_USE_PRIVATE_SSH_KEY_FROM_SITEMAP_FOLDER.png](WGEL_GTFOBIN_WGET.png)

Not viable as --use-askpass not part of wget version used. Note found using wget --help | grep --askpass either

![No askpass function](WGEL_NO_ASKPASS_FUNCTION.png)

Uploading or downloading file is option but its just flag and might be easier to just ready in existing shell so skip this option, same with SUID or SUDO upgrade as WGET already allows root privilege to access the file.

![GET UPLOAD DOWNLOAD for wget](WGEL_GTFO_Upload_download.png)

The method to obtain the file transferred here requires a nc listener, so here I just used nc -lvp 4444 on attacker end. Then use the wget method with the full extension for wget to transfer the file /etc/shadow to obtain root privilege. Not surprising it requires permissions to access the shadow file.

![WGEL_GTFO_Upload_download.png](WGEL_GTFOBIN_POST.png)

Save this file on the attacker PC.
```text
...
usbmux:*:17954:0:99999:7:::
jessie:$6$0wv9XLy.$HxqSdXgk7JJ6n9oZ9Z52qxuGCdFqp0qI/9X.a4VRJt860njSusSuQ663bXfIV7y.ywZxeOinj4Mckj8/uvA7U.:18195:0:99999:7:::
```
Create a new hash and password to insert into this table.

![WGEL_CREATE_NEW_HASH_FOR_jessie2.png](WGEL_CREATE_NEW_HASH_FOR_jessie2.png)

Insert into jessie row in the shadow file.

![Python Server](WGEL_Python_server.png)

Upload the file and save to the original /etc/shadow file 
Then use sudo /bin/bash to upgrade to. This runs a shell as a command in sudo command making it privileged shell running with root privilege. Remember the sudo -l shows "User root may run the following commands on CorpOne:" 
	- (ALL : ALL) → You can run commands as any user and as any group.
The final ALL → You can run any command.

![WGEL_USE_PRIVATE_SSH_KEY_FROM_SITEMAP_FOLDER.png](WGEL_Upgrade_root.png))
