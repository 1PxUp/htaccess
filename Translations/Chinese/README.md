# .htaccess Snippets
有用的 `.htaccess` 伪静态片段大集合。

**注意**: `.htaccess` 伪静态文件适用于，无权编辑主服务配置文件的用户。与使用主服务配置相比，它们本质上更慢，更复杂。 请查看 [httpd 入门文档](https://httpd.apache.org/docs/current/howto/htaccess.html) 获取更多细节。

**免责声明**: 虽然大多数情况下，将代码片段放到 `.htaccess` 伪静态文件中就足够了，但是也有一些情况需要进行某些修改。使用风险请自负。

**重要**: Apache 2.4 引入了一些重大改动，尤其是在访问控制配置中。 更多相关信息，请检查 [升级文档](https://httpd.apache.org/docs/2.4/upgrading.html) 以及 [这个问题](https://github.com/phanan/htaccess/issues/2).

## 致谢
我们在此所做的，主要是从整个网络中收集有用的代码片段 (例如, 很大一部分来自于 [Apache 服务配置](https://github.com/h5bp/server-configs-apache)) 。 我们一直在尝试致谢，但可能会漏掉一些。如果您认为这里有什么是您的工作成果，并且应该得到致谢，请告诉我们，或提交一个 PR 即可。

## 目录
- [重写与重定向](#rewrite-and-redirection)
    - [强制带 www](#force-www)
    - [通用方式强制带 www](#force-www-in-a-generic-way)
    - [强制不带 www](#force-non-www)
    - [通用方式强制不带 www](#force-non-www-in-a-generic-way)
    - [强制 HTTPS](#force-https)
    - [通过代理强制 HTTPS](#force-https-behind-a-proxy)
    - [强制末尾斜线](#force-trailing-slash)
    - [移除末尾斜线](#remove-trailing-slash)
    - [重定向到单页](#redirect-a-single-page)
    - [使用定向匹配重定向](#redirect-using-redirectmatch)
    - [简单目录设置别名](#alias-a-single-directory)
    - [脚本设置别名路径](#alias-paths-to-script)
    - [Redirect an Entire Site](#redirect-an-entire-site)
    - [Alias "Clean" URLs](#alias-clean-urls)
    - [Exclude a URL from Redirection](#exclude-url-from-redirection)
- [安全](#security)
    - [Deny All Access](#deny-all-access)
    - [Deny All Access Except Yours](#deny-all-access-except-yours)
    - [Allow All Access Except Spammers'](#allow-all-access-except-spammers)
    - [Deny Access to Hidden Files and Directories](#deny-access-to-hidden-files-and-directories)
    - [Deny Access to Backup and Source Files](#deny-access-to-backup-and-source-files)
    - [Disable Directory Browsing](#disable-directory-browsing)
    - [Disable Image Hotlinking](#disable-image-hotlinking)
    - [Disable Image Hotlinking for Specific Domains](#disable-image-hotlinking-for-specific-domains)
    - [Password Protect a Directory](#password-protect-a-directory)
    - [Password Protect a File or Several Files](#password-protect-a-file-or-several-files)
    - [Block Visitors by Referrer](#block-visitors-by-referrer)
    - [Prevent Framing the Site](#prevent-framing-the-site)
- [性能](#performance)
    - [Compress Text Files](#compress-text-files)
    - [Set Expires Headers](#set-expires-headers)
    - [Turn eTags Off](#turn-etags-off)
- [其它](#miscellaneous)
    - [Set PHP Variables](#set-php-variables)
    - [Custom Error Pages](#custom-error-pages)
    - [Force Downloading](#force-downloading)
    - [Prevent Downloading](#prevent-downloading)
    - [Allow Cross-Domain Fonts](#allow-cross-domain-fonts)
    - [Auto UTF-8 Encode](#auto-utf-8-encode)
    - [Switch to Another PHP Version](#switch-to-another-php-version)
    - [Disable Internet Explorer Compatibility View](#disable-internet-explorer-compatibility-view)
    - [Serve WebP Images](#serve-webp-images)

## <a name="rewrite-and-redirection">重写与重定向 
注意: 这里假定你已经安装并激活 `mod_rewrite` 模块。

### <a name="force-www">强制带 www
``` apacheconf
RewriteEngine on
RewriteCond %{HTTP_HOST} ^example\.com [NC]
RewriteRule ^(.*)$ http://www.example.com/$1 [L,R=301,NC]
```

### <a name="force-www-in-a-generic-way">通用方式强制带 www
``` apacheconf
RewriteCond %{HTTP_HOST} !^$
RewriteCond %{HTTP_HOST} !^www\. [NC]
RewriteCond %{HTTPS}s ^on(s)|
RewriteRule ^ http%1://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
```
以上方法适用于 _任何_ 域名。 [来源](https://stackoverflow.com/questions/4916222/htaccess-how-to-force-www-in-a-generic-way)

### <a name="force-non-www">强制不带 www
无论是带 www 还是不带 www，各方[仍](http://www.sitepoint.com/domain-www-or-no-www/) [然](https://devcenter.heroku.com/articles/apex-domains) [在](http://yes-www.org/) [辩论](http://no-www.org/)中， 如果碰巧你是不带 www 的粉丝， 这样做：
``` apacheconf
RewriteEngine on
RewriteCond %{HTTP_HOST} ^www\.example\.com [NC]
RewriteRule ^(.*)$ http://example.com/$1 [L,R=301]
```

### <a name="force-non-www-in-a-generic-way">通用方式强制不带 www
``` apacheconf
RewriteEngine on
RewriteCond %{HTTP_HOST} ^www\.
RewriteCond %{HTTPS}s ^on(s)|off
RewriteCond http%1://%{HTTP_HOST} ^(https?://)(www\.)?(.+)$
RewriteRule ^ %1%3%{REQUEST_URI} [R=301,L]
```

### <a name="force-https">强制 HTTPS
``` apacheconf
RewriteEngine on
RewriteCond %{HTTPS} !on
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}

# 注意：同时还建议启用 HTTP 严格传输安全协议 (HSTS)
# 帮助你的 HTTPS 网站防止中间人攻击。
# 请看 https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
<IfModule mod_headers.c>
    # Remove "includeSubDomains" if you don't want to enforce HSTS on all subdomains
    Header always set Strict-Transport-Security "max-age=31536000;includeSubDomains"
</IfModule>
```

### <a name="force-https-behind-a-proxy">通过代理强制 HTTPS
如果通过代理给你的服务提供 TLS 支持，则生效。
Useful if you have a proxy in front of your server performing TLS termination.
``` apacheconf
RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
```

### <a name="force-trailing-slash">强制末尾斜线
``` apacheconf
RewriteCond %{REQUEST_URI} /+[^\.]+$
RewriteRule ^(.+[^/])$ %{REQUEST_URI}/ [R=301,L]
```

### <a name="remove-trailing-slash">移除末尾斜线
这代码段会将以斜杠结尾的路径，重定向到非斜杠终止的路径 （真实目录除外）， 例如：`http://www.example.com/blog/` 到 `http://www.example.com/blog`. 这对 SEO 很重要， 因为这里[建议](http://overit.com/blog/canonical-urls)每个页面都有一个规范的 URL.
``` apacheconf
RewriteCond %{REQUEST_FILENAME} !-d
RewriteCond %{REQUEST_URI} (.+)/$
RewriteRule ^ %1 [R=301,L]
```
[来源](https://stackoverflow.com/questions/21417263/htaccess-add-remove-trailing-slash-from-url#27264788)

### <a name="redirect-a-single-page">重定向到单页
``` apacheconf
Redirect 301 /oldpage.html http://www.example.com/newpage.html
Redirect 301 /oldpage2.html http://www.example.com/folder/
```
[来源](http://css-tricks.com/snippets/htaccess/301-redirects/)

### <a name="redirect-using-redirectmatch">使用定向匹配重定向
``` apacheconf
RedirectMatch 301 /subdirectory(.*) http://www.newsite.com/newfolder/$1
RedirectMatch 301 ^/(.*).htm$ /$1.html
RedirectMatch 301 ^/200([0-9])/([^01])(.*)$ /$2$3
RedirectMatch 301 ^/category/(.*)$ /$1
RedirectMatch 301 ^/(.*)/htaccesselite-ultimate-htaccess-article.html(.*) /htaccess/htaccess.html
RedirectMatch 301 ^/(.*).html/1/(.*) /$1.html$2
RedirectMatch 301 ^/manual/(.*)$ http://www.php.net/manual/$1
RedirectMatch 301 ^/dreamweaver/(.*)$ /tools/$1
RedirectMatch 301 ^/z/(.*)$ http://static.askapache.com/$1
```
[来源](http://www.askapache.com/htaccess/301-redirect-with-mod_rewrite-or-redirectmatch.html#301_Redirects_RedirectMatch)

### <a name="alias-a-single-directory">简单目录设置别名
``` apacheconf
RewriteEngine On
RewriteRule ^source-directory/(.*) /target-directory/$1 [R=301,L]
```

### <a name="alias-paths-to-script">脚本设置别名路径
``` apacheconf
FallbackResource /index.fcgi
```
这个例子在某个目录中有 `index.fcgi` 文件， 并且该目录中任何无法解析的文件名/目录请求，都将被发送到 `index.fcgi` 脚本。 It’s good if you want `baz.foo/some/cool/path` to be handled by `baz.foo/index.fcgi` (which also supports requests to `baz.foo`) while maintaining `baz.foo/css/style.css` and the like. Get access to the original path from the PATH_INFO environment variable, as exposed to your scripting environment.

``` apacheconf
RewriteEngine On
RewriteRule ^$ index.fcgi/ [QSA,L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.fcgi/$1 [QSA,L]
```
This is a less efficient version of the FallbackResource directive (because using `mod_rewrite` is more complex than just handling the `FallbackResource` directive), but it’s also more flexible.

### 重定向到网站
``` apacheconf
Redirect 301 / http://newsite.com/
```
This way does it with links intact. That is `www.oldsite.com/some/crazy/link.html` will become `www.newsite.com/some/crazy/link.html`. This is extremely helpful when you are just “moving” a site to a new domain. [Source](http://css-tricks.com/snippets/htaccess/301-redirects/)

### Alias “Clean” URLs
This snippet lets you use “clean” URLs -- those without a PHP extension, e.g. `example.com/users` instead of `example.com/users.php`.
``` apacheconf
RewriteEngine On
RewriteCond %{SCRIPT_FILENAME} !-d
RewriteRule ^([^.]+)$ $1.php [NC,L]
```
[Source](http://www.abeautifulsite.net/access-pages-without-the-php-extension-using-htaccess/)

### Exclude URL from Redirection
This snippet allows you to exclude a URL from redirection.  For example, if you have redirection rules setup but want to exclude robots.txt so search engines can access that URL as expected.
``` apacheconf
RewriteEngine On
RewriteRule ^robots.txt - [L]
```

## 安全
### 拒绝所有访问
``` apacheconf
## Apache 2.2
Deny from all

## Apache 2.4
# Require all denied
```

但是，这也会使你无法反问内容！因此介绍...

### 拒绝除您之外的所有访问
``` apacheconf
## Apache 2.2
Order deny,allow
Deny from all
Allow from xxx.xxx.xxx.xxx

## Apache 2.4
# Require all denied
# Require ip xxx.xxx.xxx.xxx
```
`xxx.xxx.xxx.xxx` 是你的 IP. 如果你用例如 `0/12` 替换最后三位数字， 这将在同一网络中指定 IP 范围，从而省去了分别列出所有允许的 IP 的麻烦。 [来源](http://speckyboy.com/2013/01/08/useful-htaccess-snippets-and-hacks/)

当然这里有一个相反的版本：

### 允许除垃圾邮件发送者之外的所有访问权限
``` apacheconf
## Apache 2.2
Order deny,allow
Deny from xxx.xxx.xxx.xxx
Deny from xxx.xxx.xxx.xxy

## Apache 2.4
# Require all granted
# Require not ip xxx.xxx.xxx.xxx
# Require not ip xxx.xxx.xxx.xxy
```

### 拒绝访问隐藏的文件和目录
隐藏的文件和目录（名称以点号 `.` 开头），应该， 即使不是全部，在大多数情况下，也应该得到保护。 例如： `.htaccess`, `.htpasswd`, `.git`, `.hg`...
``` apacheconf
RewriteCond %{SCRIPT_FILENAME} -d [OR]
RewriteCond %{SCRIPT_FILENAME} -f
RewriteRule "(^|/)\." - [F]
```

或者，你可以抛出一个 “Not Found” 错误，使攻击者没有任何线索：
``` apacheconf
RedirectMatch 404 /\..*$
```

### 拒绝访问备份和源文件
这些文件可能由某些 text/HTML 编辑器 （如 Vi/Vim） 遗留，如果公开暴露，构成极大的安全隐患。
``` apacheconf
<FilesMatch "(\.(bak|config|dist|fla|inc|ini|log|psd|sh|sql|swp)|~)$">
    ## Apache 2.2
    Order allow,deny
    Deny from all
    Satisfy All

    ## Apache 2.4
    # Require all denied
</FilesMatch>
```
[来源](https://github.com/h5bp/server-configs-apache)

### 禁用目录浏览
``` apacheconf
Options All -Indexes
```

### Disable Image Hotlinking
``` apacheconf
RewriteEngine on
# Remove the following line if you want to block blank referrer too
RewriteCond %{HTTP_REFERER} !^$

RewriteCond %{HTTP_REFERER} !^https?://(.+\.)?example.com [NC]
RewriteRule \.(jpe?g|png|gif|bmp)$ - [NC,F,L]

# If you want to display a “blocked” banner in place of the hotlinked image,
# replace the above rule with:
# RewriteRule \.(jpe?g|png|gif|bmp) http://example.com/blocked.png [R,L]
```

### Disable Image Hotlinking for Specific Domains
Sometimes you want to disable image hotlinking from some bad guys only.
``` apacheconf
RewriteEngine on
RewriteCond %{HTTP_REFERER} ^https?://(.+\.)?badsite\.com [NC,OR]
RewriteCond %{HTTP_REFERER} ^https?://(.+\.)?badsite2\.com [NC,OR]
RewriteRule \.(jpe?g|png|gif|bmp)$ - [NC,F,L]

# If you want to display a “blocked” banner in place of the hotlinked image,
# replace the above rule with:
# RewriteRule \.(jpe?g|png|gif|bmp) http://example.com/blocked.png [R,L]
```

### Password Protect a Directory
First you need to create a `.htpasswd` file somewhere in the system:
``` bash
htpasswd -c /home/fellowship/.htpasswd boromir
```

Then you can use it for authentication:
``` apacheconf
AuthType Basic
AuthName "One does not simply"
AuthUserFile /home/fellowship/.htpasswd
Require valid-user
```

### Password Protect a File or Several Files
``` apacheconf
AuthName "One still does not simply"
AuthType Basic
AuthUserFile /home/fellowship/.htpasswd

<Files "one-ring.o">
Require valid-user
</Files>

<FilesMatch ^((one|two|three)-rings?\.o)$>
Require valid-user
</FilesMatch>
```

### Block Visitors by Referrer
This denies access for all users who are coming from (referred by) a specific domain.
[Source](http://www.htaccess-guide.com/deny-visitors-by-referrer/)
``` apacheconf
RewriteEngine on
# Options +FollowSymlinks
RewriteCond %{HTTP_REFERER} somedomain\.com [NC,OR]
RewriteCond %{HTTP_REFERER} anotherdomain\.com
RewriteRule .* - [F]
```

### Prevent Framing the Site
This prevents the website to be framed (i.e. put into an `iframe` tag), when still allows framing for a specific URI.
``` apacheconf
SetEnvIf Request_URI "/starry-night" allow_framing=true
Header set X-Frame-Options SAMEORIGIN env=!allow_framing
```

## Performance
### Compress Text Files
``` apacheconf
<IfModule mod_deflate.c>

    # Force compression for mangled headers.
    # https://developer.yahoo.com/blogs/ydn/pushing-beyond-gzipping-25601.html
    <IfModule mod_setenvif.c>
        <IfModule mod_headers.c>
            SetEnvIfNoCase ^(Accept-EncodXng|X-cept-Encoding|X{15}|~{15}|-{15})$ ^((gzip|deflate)\s*,?\s*)+|[X~-]{4,13}$ HAVE_Accept-Encoding
            RequestHeader append Accept-Encoding "gzip,deflate" env=HAVE_Accept-Encoding
        </IfModule>
    </IfModule>

    # Compress all output labeled with one of the following MIME-types
    # (for Apache versions below 2.3.7, you don't need to enable `mod_filter`
    #  and can remove the `<IfModule mod_filter.c>` and `</IfModule>` lines
    #  as `AddOutputFilterByType` is still in the core directives).
    <IfModule mod_filter.c>
        AddOutputFilterByType DEFLATE application/atom+xml \
                                      application/javascript \
                                      application/json \
                                      application/rss+xml \
                                      application/vnd.ms-fontobject \
                                      application/x-font-ttf \
                                      application/x-web-app-manifest+json \
                                      application/xhtml+xml \
                                      application/xml \
                                      font/opentype \
                                      image/svg+xml \
                                      image/x-icon \
                                      text/css \
                                      text/html \
                                      text/plain \
                                      text/x-component \
                                      text/xml
    </IfModule>

</IfModule>
```
[Source](https://github.com/h5bp/server-configs-apache)


### Set Expires Headers
_Expires headers_ tell the browser whether they should request a specific file from the server or just grab it from the cache. It is advisable to set static content's expires headers to something far in the future.

If you don’t control versioning with filename-based cache busting, consider lowering the cache time for resources like CSS and JS to something like 1 week. [Source](https://github.com/h5bp/server-configs-apache)
``` apacheconf
<IfModule mod_expires.c>
    ExpiresActive on
    ExpiresDefault                                      "access plus 1 month"

  # CSS
    ExpiresByType text/css                              "access plus 1 year"

  # Data interchange
    ExpiresByType application/json                      "access plus 0 seconds"
    ExpiresByType application/xml                       "access plus 0 seconds"
    ExpiresByType text/xml                              "access plus 0 seconds"

  # Favicon (cannot be renamed!)
    ExpiresByType image/x-icon                          "access plus 1 week"

  # HTML components (HTCs)
    ExpiresByType text/x-component                      "access plus 1 month"

  # HTML
    ExpiresByType text/html                             "access plus 0 seconds"

  # JavaScript
    ExpiresByType application/javascript                "access plus 1 year"

  # Manifest files
    ExpiresByType application/x-web-app-manifest+json   "access plus 0 seconds"
    ExpiresByType text/cache-manifest                   "access plus 0 seconds"

  # Media
    ExpiresByType audio/ogg                             "access plus 1 month"
    ExpiresByType image/gif                             "access plus 1 month"
    ExpiresByType image/jpeg                            "access plus 1 month"
    ExpiresByType image/png                             "access plus 1 month"
    ExpiresByType video/mp4                             "access plus 1 month"
    ExpiresByType video/ogg                             "access plus 1 month"
    ExpiresByType video/webm                            "access plus 1 month"

  # Web feeds
    ExpiresByType application/atom+xml                  "access plus 1 hour"
    ExpiresByType application/rss+xml                   "access plus 1 hour"

  # Web fonts
    ExpiresByType application/font-woff2                "access plus 1 month"
    ExpiresByType application/font-woff                 "access plus 1 month"
    ExpiresByType application/vnd.ms-fontobject         "access plus 1 month"
    ExpiresByType application/x-font-ttf                "access plus 1 month"
    ExpiresByType font/opentype                         "access plus 1 month"
    ExpiresByType image/svg+xml                         "access plus 1 month"
</IfModule>
```

### Turn eTags Off
By removing the `ETag` header, you disable caches and browsers from being able to validate files, so they are forced to rely on your `Cache-Control` and `Expires` header. [Source](http://www.askapache.com/htaccess/apache-speed-etags.html)
``` apacheconf
<IfModule mod_headers.c>
    Header unset ETag
</IfModule>
FileETag None
```

## Miscellaneous

### Set PHP Variables
``` apacheconf
php_value <key> <val>

# For example:
php_value upload_max_filesize 50M
php_value max_execution_time 240
```

### Custom Error Pages
``` apacheconf
ErrorDocument 500 "Houston, we have a problem."
ErrorDocument 401 http://error.example.com/mordor.html
ErrorDocument 404 /errors/halflife3.html
```

### Force Downloading
Sometimes you want to force the browser to download some content instead of displaying it.
``` apacheconf
<Files *.md>
    ForceType application/octet-stream
    Header set Content-Disposition attachment
</Files>
```

Now there is a yang to this yin:

### Prevent Downloading
Sometimes you want to force the browser to display some content instead of downloading it.
``` apacheconf
<FilesMatch "\.(tex|log|aux)$">
    Header set Content-Type text/plain
</FilesMatch>
```

### Allow Cross-Domain Fonts
CDN-served webfonts might not work in Firefox or IE due to [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing). This snippet solves the problem.
``` apacheconf
<IfModule mod_headers.c>
    <FilesMatch "\.(eot|otf|ttc|ttf|woff|woff2)$">
        Header set Access-Control-Allow-Origin "*"
    </FilesMatch>
</IfModule>
```
[Source](https://github.com/h5bp/server-configs-apache/issues/32)

### Auto UTF-8 Encode
Your text content should always be UTF-8 encoded, no?
``` apacheconf
# Use UTF-8 encoding for anything served text/plain or text/html
AddDefaultCharset utf-8

# Force UTF-8 for a number of file formats
AddCharset utf-8 .atom .css .js .json .rss .vtt .xml
```
[Source](https://github.com/h5bp/server-configs-apache)

### Switch to Another PHP Version
If you’re on a shared host, chances are there are more than one version of PHP installed, and sometimes you want a specific version for your website. The following snippet should switch the PHP version for you.

``` apacheconf
AddHandler application/x-httpd-php56 .php

# Alternatively, you can use AddType
AddType application/x-httpd-php56 .php
```

### Disable Internet Explorer Compatibility View
Compatibility View in IE may affect how some websites are displayed. The following snippet should force IE to use the Edge Rendering Engine and disable the Compatibility View.

``` apacheconf
<IfModule mod_headers.c>
    BrowserMatch MSIE is-msie
    Header set X-UA-Compatible IE=edge env=is-msie
</IfModule>
```

### Serve WebP Images
If [WebP images](https://developers.google.com/speed/webp/?csw=1) are supported and an image with a .webp extension and the same name is found at the same place as the jpg/png image that is going to be served, then the WebP image is served instead.

``` apacheconf
RewriteEngine On
RewriteCond %{HTTP_ACCEPT} image/webp
RewriteCond %{DOCUMENT_ROOT}/$1.webp -f
RewriteRule (.+)\.(jpe?g|png)$ $1.webp [T=image/webp,E=accept:1]
```
[Source](https://github.com/vincentorback/WebP-images-with-htaccess)
