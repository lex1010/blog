## 解题流程


1\. 尝试访问 `/api` 最后得到 `/api/v1/user` 和 `/api/v1/admin` 接口，同时扫描得到 `/docs` 接口

2\. 通过 `/api/v1/user/1` 可以获得管理员的信息,  `/api/v1/admin` 接口需要授权

3\. 使用工具扫描 `/api/v1/user/FUZZ` 接口，得到 `login` 和 `signup` 接口

4\. 首先通过 `signup` 来注册一个普通用户，然后使用 `login` 接口进行登录，返回 `jwt` ，通过 `jwt` 得到服务器使用 `HS256` 进行签名
```json
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUzMTU4NjE1LCJpYXQiOjE2NTI0Njc0MTUsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.5hXsWCyH_rucxrXzDvGS6Cbae11hP31PtPyNf7Ot7oU","token_type":"bearer"}
```

5\. 使用注册的账号的 `jwt` 登录 `/docs` 接口，得到 `api` 的说明文档

```
/api/v1/user/{user_id}
/api/v1/user/login
/api/v1/user/signup
/api/v1/user/SecretFlagEndpoint
/api/v1/user/updatepass
/api/v1/admin/
/api/v1/admin/file
/api/v1/admin/exec/{command}
```

6\. 使用 `/api/v1/user/SecretFlagEndpoint` 可以获得` user.txt` 的` flag `

7\. 使用` /api/v1/user/updatepass` 接口修改密码时候，可以越权修改管理员的密码

8\. 修改管理员密码之后，使用管理员` JWT `来使用` admin `接口

9\.  /api/v1/admin/file 接口存在文件读取，通过文件读取获得关键信息

``` 
/etc/passwd
/proc/self/cmdline
/proc/self/environment
/home/htb/.viminfo
/home/htb/uhc/auth.log
```  

10\. 使用文件读取的接口得到服务器部分源码后，进行分析得到 `JWT` 签名的密钥以及运行 `/api/v1/admin/exec/{command}` 接口的条件
   
只要 `jwt`的 `payload` 中存在 `debug` 这个 `key` 值就可以成功执行命令
   

11\. 使用密钥签发一个可以执行命令的 `jwt`，然后执行命令获得一个反弹 `shell `

12\. 在服务器上找到 `root` 用户的密码得到最后的 `flag `