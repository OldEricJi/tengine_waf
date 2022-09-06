RulePath = "/usr/local/tengine/conf/wafconf/"
logdir = "/usr/local/tengine/logs/"
black_fileExt={"php","jsp"}

OnlyCheck="off"
AttackLog="on"
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
