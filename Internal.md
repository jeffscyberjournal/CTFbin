# Internal

You are assigned to perform a black‑box penetration test on a virtual environment scheduled for production in three weeks.

The assessment must include:
- External testing
- Web application testing
- Internal network testing

The client provides minimal information to simulate a real attacker.

Your objectives:
- Modify your hosts file to resolve internal.thm
- Use any tools or techniques (full offensive freedom)
- Identify and document all vulnerabilities
- Obtain two proof‑of‑compromise flags:
    - user.txt
    - root.txt

Submit the flags to the dashboard

Only the assigned target IP is in scope.

- You are encouraged to treat this as a real engagement and produce a professional report (exec summary, findings, exploitation steps, remediation). If time permits.

# Start enumeration with NMAP
```
└─$ nmap -Pn -sV -sC THM_Target                     
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
```
Just 2 services to look at on Linux OS
Quick browse of ip shows apache web server default screen.

GoBuster and feroxbuster similar but gobuster summed it up better:
```
└─$ sudo gobuster dir -u "http://THM_Target:80" -w /usr/share/wordlists/dirb/common.txt -t 10 --timeout 10s
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://THM_Target:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/blog                 (Status: 301) [Size: 311] [--> http://10.49.134.48/blog/]                                                                           
/index.html           (Status: 200) [Size: 10918]
/javascript           (Status: 301) [Size: 317] [--> http://10.49.134.48/javascript/]                                                                     
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.49.134.48/phpmyadmin/]                                                                     
/server-status        (Status: 403) [Size: 277]
/wordpress            (Status: 301) [Size: 316] [--> http://10.49.134.48/wordpress/]
Progress: 4613 / 4613 (100.00%)
===============================================================              
```
