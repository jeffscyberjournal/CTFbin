# Daily Bugle
Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.

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
curl README.txt shows version 3.7
```
Joomla! 3.7 version history - https://docs.joomla.org/Joomla_3.7_version_history
```
More specific its found int the file:
curl TargetIP/administrator/language/en-GB/en-GB.xml | grep "3.7"
<version>3.7.0</version>
