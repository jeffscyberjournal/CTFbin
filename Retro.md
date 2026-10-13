# Retro d

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
root@ip-10-67-76-166:~# 
```
User.txt contains 3b99fbdc6d430bfb51c72c651a261927. 

**Taking look in recycling bin there is a file hhupd so what is it? **

hhupd.exe is a Windows executable that has been associated with CVE-2019-1388, a UAC bypass technique. Researchers and training material often use hhupd.exe as an example of an elevated GUI application that can be abused to obtain an Administrator shell.

Full explanation: https://sotharo-meas.medium.com/cve-2019-1388-windows-privilege-escalation-through-uac-22693fa23f5f

This however is broken for this module the idea is right click run as administrator then view a link in default browser as or app and since neither can be selected even when you set default web browser to google chrome/or iexplorer. This should lead to browser launched with as "System with a 404 Verisign" website being displayed. Save the webpage by clicking on the gear, File, Save as… You will be prompted with and error “Location is not available.” Click OK. Then go to windows\system32 folder and select the cmd.exe and open with right click. From there CMD access with user level NT Authority\system.

Alternatively there dozens of methods to reverse shell access, such as via the wordpress appearance>theme editor using a Ivan Sincek php shell from revshells.com, or meterpreter payloads with msfvenom but had trouble escalating (getsystem failed). 

So had a closer look

systeminfo and wmic qfe and found:

**wmic qfe** re-organised make it easier to view
Installed Hotfixes
==================

HotFix ID     : KB3192137
Description   : Update
Installed By  : NT AUTHORITY\SYSTEM
Installed On  : 09/12/2016
System        : RETROWEB

Microsoft KB  : https://support.microsoft.com/?kbid=3192137


C:\Users\Wade>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393

C:\Users\Wade> 

Observation:
  Very few updates installed.
  Build 14393 is a known target for CVE-2017-0213.
  Investigated CVE-2017-0213 as a potential local privilege escalation vector.
