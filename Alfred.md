# Alfred
Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.

In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made changes to it). After which, we'll use an interesting privilege escalation method to get full system access. 

Task 1 Initial Access:

In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made changes to it). After which, we'll use an interesting privilege escalation method to get full system access. 

Since this is a Windows application, we'll be using Nishang(opens in new tab) to gain initial access. The repository contains a useful set of scripts for initial access, enumeration and privilege escalation. In this case, we'll be using the reverse shell scripts(opens in new tab).

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

NMAP scan (no ping Pn): 
```root@ip-10-49-106-177:~# nmap -sT -sC 10.49.135.47
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-03 17:40 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 4.36 seconds
root@ip-10-49-106-177:~# nmap -sT -Pn -sC 10.49.135.47
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-03 17:41 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.49.135.47
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
root@ip-10-49-106-177:~# curl http://10.49.135.47:8080/robots.txt
# we don't want robots to click "build" links
User-agent: *

```
## Q1: number of TCP ports:
Answer: 3

Trying several things, looking at code in url pages, basic gobuster scan of directories, and exiftools not a lot showed up. Only
alfred@wayneenterprises.com visible on the main page, the <target-ip>:8080 showed image of jenkins but could not be saved. In the code there was a reference to j_acegi_security_check.


It’s a tell‑tale sign of an old Java web application using Acegi Security, which is the predecessor of Spring Security. When you see this string in a login form or request, it indicates:

acegi refers to Acegi Security, which was the original name of Spring Security, the Java security framework used in many older web applications.

The application is using old Spring Security (pre‑2008)
✔ The login form is posting to the default Acegi authentication endpoint.
✔ The app is likely running on Java / Tomcat / JSP.
✔ It may be vulnerable depending on how outdated the framework is.

## Q2 What is the username and password for the login panel? (in the format username:password):

Considering the answer expected is *****:*****, with consideration of the names found on the site and common names you would expect  with wayne, bruce and admin, were likely expected to be one of options, password I considerd common list i decided not to try a common wordlist as these were enough to guess it. But should there have been more the process is simple with burpe suite community edition. 
- Set up proxy in browser like foxy proxy. Turn intercept on in proxy configuration on burpse suite.
- Fill user name and password box with easily identifiable locators, the select "sign in".
- That is captured in burpe suite check the login details are listed and forward to intruder.
- Use cluster bomb not sniper mode as more than one variable and assign wordlists to each variable then start attack.
- The output will all be status code 302, but the headers are what vary, only admin:admin are successful.

Unsuccessful (admin:wayne)
```
HTTP/1.1 302 Found
Date: Sun, 05 Apr 2026 11:42:40 GMT
X-Content-Type-Options: nosniff
Set-Cookie: JSESSIONID.a7acbf59=node0culm1u2k46xraz96yxi7hhci19.node0;Path=/;HttpOnly
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Set-Cookie: ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE=;Path=/;Expires=Thu, 01-Jan-1970 00:00:00 GMT;Max-Age=0;HttpOnly
Location: http://10.49.152.15:8080/loginError
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
Location: http://10.49.152.15:8080/
Content-Length: 0
Server: Jetty(9.4.z-SNAPSHOT)
```

