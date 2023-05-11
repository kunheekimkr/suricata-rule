site = ["google.com", "youtube.com", "baidu.com", "bilibili.com", "facebook.com", "qq.com", "twitter.com", "zhihu.com", "wikipedia.org", "amazon.com", "instagram.com", "linkedin.com", "reddit.com", "whatsapp.com", "openai.com", "yahoo.com", "bing.com", "taobao.com", "163.com", "yandex.ru" ]
f= open ("test.rules","w+")

for i, s in enumerate(site):
    # alert tcp any any -> any 80 (msg:"google.com access (HTTP)"; content:"GET /"; content:"Host: "; content:"google.com"; sid:10001; rev:1;)
    data = f'alert tcp any any -> any 80 (msg:"{s} access (HTTP)"; content:"GET /"; content:"Host: "; content:"{s}"; sid:{10000+ 2*i +1}; rev:1;)\n'
    # alert tls any any -> any 443 (msg:"google.com access (HTTPS)";  tls_sni; content:"google.com"; sid:10002; rev:1;)
    data += f'alert tls any any -> any 443 (msg:"{s} access (HTTPS)";  tls_sni; content:"{s}"; sid:{10000+ 2*i +2}; rev:1;)\n'
    f.write(data)