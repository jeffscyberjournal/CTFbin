# Brainstorm

Reverse engineer a chat program and write a script to exploit a Windows machine.

Task 1 Deploy Machine and Scan Network

## Q1 How many open ports?

### Answer Q1: 3 from nmap scan

Nmap scan with no ping to determine the ports and services open.
```
root@ip-10-48-97-163:~# nmap -Pn -sV 10.48.172.173
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-21 20:06 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for internal.thm (10.48.172.173)
Host is up (0.00047s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
3389/tcp open  tcpwrapped
9999/tcp open  abyss?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=5/21%Time=6A0F57C4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter
SF:\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequest
SF:,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x
SF:20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mes
SF:sage:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x2
SF:0to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usern
SF:ame\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(J
SF:avaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20e
SF:nter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\
SF:x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20cha
SF:t\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20ch
SF:aracters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\x
SF:20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20user
SF:name\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(
SF:RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x2
SF:0enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20
SF:a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brainst
SF:orm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x
SF:2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReques
SF:tTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ent
SF:er\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x2
SF:0message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(bet
SF:a\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\)
SF::\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x20
SF:Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20
SF:\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Terminal
SF:ServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPleas
SF:e\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write
SF:\x20a\x20message:\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Just the three ports
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
3389/tcp open  tcpwrapped
9999/tcp open  abyss?

### What is abyss on 9999

Nmap found a custom service on port 9999.
It doesn’t know what it is, so it prints the banner and asks if you want to submit it.
In your case, port 9999 is running a custom chat server:
```
Welcome to Brainstorm chat (beta)
...
Please enter your username (max 20 characters):
```
Nmap doesn’t recognise it, so it dumps the fingerprint.

# Task 2 Accessing files

FTP was available on port 21 so first off try anonymous and a few test names

starting with username:password anonymous:anonymous, anonymous worked but not admin:admin and other combinations no success.
```
└─$ ftp THM_Target
Connected to THM_Target.
220 Microsoft FTP Service
Name (THM_Target:hostusername): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
```
- Tried to access any files but initially download failed when run, requiring 'binary' command to ensure downloads run later with get or mget were successful. 
- 'passive' command required to accept commands first.
- Note: If the files you downloaded from FTP are twice the size, that is a classic symptom of downloading binary files in ASCII mode. Windows executables, DLLs, ZIPs, and any non‑text files get corrupted when transferred in ASCII. This is where binary command ensures downloads are binary not ascii comes useful.
```
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> binary
200 Type set to I.
ftp> ls
200 EPRT command successful.
150 Opening ASCII mode data connection.
08-29-19  08:36PM       <DIR>          chatserver
226 Transfer complete.
ftp> cd chatserver
250 CWD command successful.
ftp> ls
200 EPRT command successful.
150 Opening ASCII mode data connection.
08-29-19  10:26PM                43747 chatserver.exe
08-29-19  10:27PM                30761 essfunc.dll
226 Transfer complete.
ftp> get essfunc.dll
local: essfunc.dll remote: essfunc.dll
200 EPRT command successful.
150 Opening BINARY mode data connection.
100% |***************| 30761       15.91 KiB/s    00:00 ETA
226 Transfer complete.
30761 bytes received in 00:01 (15.89 KiB/s)
ftp> get chatserver.exe
local: chatserver.exe remote: chatserver.exe
200 EPRT command successful.
150 Opening BINARY mode data connection.
100% |***************| 43747       18.45 KiB/s    00:00 ETA
226 Transfer complete.
43747 bytes received in 00:02 (18.09 KiB/s)
ftp> bye
```
mget is if download for many files allowing wild cards like *, or *.txt, *.zip 
```
ftp> mget *
mget chatserver.exe [anpqy?]? y
200 EPRT command successful.
150 Opening BINARY mode data connection.
100% |***************| 43747       18.53 KiB/s    00:00 ETA
226 Transfer complete.
43747 bytes received in 00:02 (18.29 KiB/s)
mget essfunc.dll [anpqy?]? y
200 EPRT command successful.
125 Data connection already open; Transfer starting.
100% |***************| 30761       16.25 KiB/s    00:00 ETA
226 Transfer complete.
30761 bytes received in 00:01 (16.23 KiB/s)
ftp> 
```

Telnet tried initially before FTP but traversing directories did not work 
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/BrainStorm]
└─$ telnet 10.49.174.168 21
Trying 10.49.174.168...
Connected to 10.49.174.168.
Escape character is '^]'.
220 Microsoft FTP Service
...
USER admin
331 Password required for admin.
PASS admin
530 User cannot log in.
USER anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
PASS anonymous
230 User logged in.
...
quit
```   

Server Side (Windows 8 – chatserver.exe)
```
C:\Users\Administrator\Desktop\binary\chatserver.exe

Chat Server started!
Called essential function dll version 1.00

Waiting for connections..
Received a client connection from <netcat_terminal_IP>:52332
Client <netcat_terminal_IP>:52332 selected username: THM_USER
```
Client Side (Netcat Terminal – Linux)
```
(hacktopuser@hacktop) ~/Desktop
$ nc <chatserver-IP> 9999

Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): THM_USER
Write a message: TEST INPUT TEXT

Fri May 29 02:46:35 2026
THM_USER said: TEST INPUT TEXT

Write a message: TEST2 TEXT

Fri May 29 02:47:01 2026
THM_USER said: TEST2 TEXT
```

