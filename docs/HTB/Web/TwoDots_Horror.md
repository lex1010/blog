## 分析

首先看`index.js`文件

```
app.use(function(req, res, next) {
	res.setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;")
	next();
});
```

上面这串代码设置了`CSP`安全策略，接着看`routes/index.js`文件

```js
router.get('/review', async (req, res, next) => {               // 这个接口只有内部才可访问，并且渲染 review.html 页面
	if(req.ip != '127.0.0.1') return res.redirect('/');

	return db.getPosts(0)
		.then(feed => {
			res.render('review.html', { feed });
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});
```

```html
<div class="main-area">
    {% for post in feed %}
    <div class="nes-container is-post with-title">
        <p class="title"><span class="title1">{{ post.author }}</span><span class="title1">{{ post.created_at }}</span></p>
        <p>{{ post.content|safe }}</p>  <!-- 这里使用了safe过滤器，传入的数据不会进行转义 -->
    </div>
    <button class="nes-btn is-primary">Approve</button> <button class="nes-btn is-error">Delete</button><br />
    <br />
    {% endfor %}
</div>
```


```js
router.post('/api/submit', AuthMiddleware, async (req, res) => {
	return db.getUser(req.data.username)
		.then(user => {
			if (user === undefined) return res.redirect('/'); 
			const { content } = req.body;
			if(content){
				twoDots = content.match(/\./g);		// 提交的数据只能包含两个 .
				if(twoDots == null || twoDots.length != 2){
					return res.status(403).send(response('Your story must contain two sentences! We call it TwoDots Horror!'));
				}
				return db.addPost(user.username, content)
					.then(() => {
						bot.purgeData(db);          // 提交完成后调用 bot.purgeData
						res.send(response('Your submission is awaiting approval by Admin!'));
					});
			}
			return res.status(403).send(response('Please write your story first!'));
		})
		.catch(() => res.status(500).send(response('Something went wrong!')));
});

...
...
...

async function purgeData(db){		// 该函数在内部设置了cookie，然后调用review接口
	const browser = await puppeteer.launch(browser_options);
	const page = await browser.newPage();

	await page.goto('http://127.0.0.1:1337/');
	await page.setCookie(...cookies);

	await page.goto('http://127.0.0.1:1337/review', {
		waitUntil: 'networkidle2'
	});

	await browser.close();
	await db.migrate();
};
```

到这里，攻击思路就已经清晰了：通过 `submit` 接口把我们的 `XSS payload` 保存到后端，当后端 `bot` 发起访问的时候，盗取`cookie`。

但是从代码中可以看到，服务端设置了`CSP`策略，无法从外部获取`JS`文件，同时`payload`又被限制了只能包含两个`.`。


我们继续看`routes/index.js`文件，可以看到存在一个上传的功能

```
router.post('/api/upload', AuthMiddleware, async (req, res) => {
	return db.getUser(req.data.username)
		.then(user => {
			if (user === undefined) return res.redirect('/');
			if (!req.files) return res.status(400).send(response('No files were uploaded.'));
			return UploadHelper.uploadImage(req.files.avatarFile)
				.then(filename => {
					return db.updateAvatar(user.username,filename)
						.then(()  => {
							res.send(response('Image uploaded successfully!'));
							if(user.avatar != 'default.jpg') 
								fs.unlinkSync(path.join(__dirname, '/../uploads',user.avatar)); // remove old avatar
						})
				})
		})
		.catch(err => res.status(500).send(response(err.message)));
});
```

可以想到通过图片来进行`XSS`攻击，所以这里我们构造一个带有`xss payload`的图片，图片上传后，使用`<script>`标签来加载这个图片，然后通过`submit`提交到后端，即可触发漏洞。


## 参考链接
1. [https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs)

2. [https://mozilla.github.io/nunjucks/templating.html#safe](https://mozilla.github.io/nunjucks/templating.html#safe)

3. [https://github.com/s-3ntinel/imgjs_polygloter](https://github.com/s-3ntinel/imgjs_polygloter)