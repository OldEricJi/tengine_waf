RulePath = "/etc/openresty/j-waf/rule-config/"
logdir = "/var/log/nginx/waf/"
black_fileExt={"php","jsp"}

onlyCheck="off"
attackLog="on"
urlMatch="on"
postMatch="on" 
cookieMatch="on"
whiteUrlMatch="on" 
denyCC="on"
whiteIPMatch="on"
blackIPMatch="on"


html=[[
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Web Firewall</title>
</head>
<body>
<h1 align="center">Forbidden</h1>
</body></html>
]]
