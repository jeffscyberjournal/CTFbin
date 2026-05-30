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
