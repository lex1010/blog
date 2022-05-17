## 分析

首先查看源代码的路由部分

```php
public function getRouteParameters($route)
{
    $params = [];
    $uri = explode('/', strtok(urldecode($_SERVER['REQUEST_URI']), '?'));
    $route = explode('/', $route);

    foreach ($route as $key => $value)
    {
        if ($uri[$key] == $value) continue;
        if ($value == '{param}')
        {
            if ($uri[$key] == '')
            {
                $this->abort(404);
            }
            $params[] = urldecode($uri[$key]);
        }
    }

    return $params;
}
```

可以明显看到这里使用`urldecode`进行了两次解码

接着看路由 
```php
$router->new('GET', '/', 'LandingController@index');
$router->new('GET', '/miner/{param}', 'MinerController@show');
$router->new('GET', '/info', function(){
	return phpinfo();
});

```

查看 `/miner/{param}` 对应的控制代码
```php
class MinerController 
{
    public function show($router, $params) 
    {   
        $miner_id = $params[0];
        include("./miners/${miner_id}");
        if (empty($minerLog))
        {
            return $router->abort(400);
        }
        return $router->view('miner', ['log' => $minerLog]);
    }
}
```

这里存在一个本地包含的漏洞 `include("./miners/${miner_id}");`


从`/info`路由中，我们能得知`phpinfo`的一些关键信息

```
session.auto_start	Off
session.upload_progress.cleanup	Off
```

当`auto_start=off`的时候，我们可以操控`PHP_SESSION_UPLOAD_PROGRESS`来发起一个`multipart POST`请求，可以上传任意文件到`PHP SESSION`的`TMP`目录

```bash
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange'
$ ls -a /var/lib/php/sessions/
. ..
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -d 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'
$ ls -a /var/lib/php/sessions/
. ..
$ curl http://127.0.0.1/ -H 'Cookie: PHPSESSID=iamorange' -F 'PHP_SESSION_UPLOAD_PROGRESS=blahblahblah'  -F 'file=@/etc/passwd'
$ ls -a /var/lib/php/sessions/
. .. sess_iamorange

In the last example the session will contain the string blahblahblah
```

这里存在着条件竞争，因为上传上去的临时文件会很快被删除。但是题目的`session.upload_progress.cleanup=off`，删除时间会很慢。

所以现在我们存在着 ***任意文件上传*** 和 ***本地文件包含***

但是`disable_function`禁用了大部分的执行命令的
```
exec, system, popen, proc_open, shell_exec, passthru, ini_set, putenv, pfsockopen, fsockopen, socket_create
```

从配置文件中可以看到服务器使用了`php-fpm`，那么可以使用`php-fpm`加载任意扩展名文件来进行命令执行

思路是先上传一个共享链接库文件`exec.so`，然后再上传一个`php-fpm.php`的客户端文件，客户端文件指定了`exec.so`为可执行的扩展文件，最后使用`lfi`包含客户端`php`文件即可。



# 参考链接


[https://d4rkstat1c.medium.com/mr-burns-hackthebox-writeup-c06f90a22fa9](https://d4rkstat1c.medium.com/mr-burns-hackthebox-writeup-c06f90a22fa9)

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-dl-function](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-dl-function)

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-fpm-fastcgi#fuckfastgci](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-fpm-fastcgi#fuckfastgci)

