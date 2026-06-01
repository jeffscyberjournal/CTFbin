# BrainPan

Brainpan is perfect for OSCP practice and has been highly recommended to complete before the exam. Exploit a buffer overflow vulnerability by analyzing a Windows executable on a Linux machine. 

# Initial Enumeration:

### NMAP

```
# nmap -Pn -sV -sC THM_TARGET
...
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
| _|                                                                 _|      
| _|_|_|   _|  _|_|   _|_|_|   _|_|_|   _|_|_|   _|_|_|   _|_|_|   _|_|_|    
| _|    _|  _|  _|   _|    _|  _|    _|  _|    _|  _|    _|  _|    _|    _|  
| _|    _|  _|  _|   _|    _|  _|    _|  _|    _|  _|    _|  _|    _|    _|  
| _|_|_|   _|  _|_|   _|_|_|   _|_|_|   _|_|_|   _|_|_|   _|  _|   _|    _|  
|
[________________________ WELCOME TO BRAINPAN _________________________]
                        ENTER THE PASSWORD
                                >>

10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=5/31%Time=6A1C692E%P=x86_64-pc-linux-gnu%r(NU
...
```
Two ports: 9999 abyss? likely a running process similar to earlier CTF running on 9999. Tested with netcat IP 9999 and sure enought the same screen appeared to ascii art from nmap requesting password.
Port 10000 was a simpleHTTPServer accessible via web browser. Displaying web page "Are you practicing safe coding?" referencing 2011 as proved to be year of the hack suggesting old content.

### Gobuster 
A quick search of port 10000 showed one folder of interest and its contents accessible via browser.
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/openvpn-troubleshooting-2025-infra-upgrades]
└─$ gobuster dir -u http://10.49.167.39:10000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.167.39:10000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
bin                  (Status: 301) [Size: 0] [--> /bin/]
```
In IP:10000/bin/ was a single exe file brainpan.exe. 
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/BrainPan]
└─$ file brainpan.exe                     
brainpan.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 5 sections
```
PE32 executable
It’s a Windows binary, 32‑bit, compiled for x86.

Windows 4.00
This corresponds to Windows NT 4.0 era toolchains — extremely old.
