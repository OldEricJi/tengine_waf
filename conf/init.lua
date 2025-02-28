require 'config'

local match = string.match
local ngxmatch=ngx.re.find
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir
rulepath = RulePath
UrlDeny = optionIsOn(urlMatch)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteUrlMatch)

WhiteIPCheck = optionIsOn(whiteIPMatch)
CCDeny = optionIsOn(denyCC)
BlockIPCheck = optionIsOn(blackIPMatch)
OnlyCheck = optionIsOn(onlyCheck) 
AttackLog = optionIsOn(attackLog)


function write(logfile, msg)
    local io = require 'io'
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method,rule,data)
    if AttackLog then
        local realIp = ngx.var.remote_addr
        --local ua = ngx.var.http_user_agent
        local uri = ngx.var.request_uri
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        line = realIp.." ["..time.."] \""..method.." "..servername..uri.."\" \""..rule.."\"  \""..data.."\"\n"
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end

------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    local io = require 'io'
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url.rule')
argsrules=read_rule('args.rule')
uarules=read_rule('user-agent.rule')
wturlrules=read_rule('whiteurl.rule')
postrules=read_rule('post.rule')
ckrules=read_rule('cookie.rule')
whiteiprules=read_rule('whiteip.rule')
blockiprules=read_rule('blockip.rule')
denyccrules=read_rule('denycc.rule')

function say_html(msg)
    if OnlyCheck  then
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        if nil ~= msg then
            ngx.say(msg)
        else
            ngx.say(html)
        end
        ngx.exit(ngx.status)
    end
end


function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end

function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext=string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext,rule,"isjo") then
            log('POST deny',rule,ext)
            say_html("black file deny")
            end
        end
    end
    return false
end

function Set (list)
  local set = {}
  for _, l in ipairs(list) do set[l] = true end
  return set
end

function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                if val ~= false then
                    data=table.concat(val, " ")
                end
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('GET deny',rule,unescape(data))
                say_html("GET deny")
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('GET deny',rule,"-")
                say_html("Url deny")
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"isjo") then
                log('UA deny',rule,ua)
                say_html("UA deny")
            return true
            end
        end
    end
    return false
end

function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
                log('POST deny',rule,unescape(data))
                say_html("POST deny")
            return true
        end
    end
    return false
end

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie deny',rule,ck)
                say_html("Cookie deny")
            return true
            end
        end
    end
    return false
end

function gettoken(data)
    if string.match(data,'+.*+') then
        local str1 = myeval(string.match(data,'(.*)+.*+.*'))
        local str2 = myeval(string.match(data,'.*+(.*)+.*'))
        local str3 = myeval(string.match(data,'.*+.*+(.*)'))
        if str1 ~= nil and str2 ~= nil and str3 ~= nil then
            return str1..str2..str3
        else
            return nil
        end
    elseif string.match(data,'+') then
        local str1 = myeval(string.match(data,'(.*)+'))
        local str2 = myeval(string.match(data,'+(.*)'))
        if str1 ~= nil and str2 ~= nil then
            return str1..str2
        else
            return nil
        end
    else
        return myeval(data)
    end	
end

function myeval(data)
    if data == nil then
    return nil
    end
    local param=""
    if data == "ip" then
        return ngx.var.remote_addr

    elseif data == "domain" then
        return ngx.var.host
    elseif ngxmatch(data,"^uri","isjo") then
        param = string.match(data,'uri:(.*)')
        if data == "uri" then
            return ngx.var.uri
        elseif ngxmatch(ngx.var.uri,param,"isjo") then
            return param
        else
            return nil
        end
    elseif ngxmatch(data,"^header:","isjo") then
        param = string.match(data,'header:(.*)')
        local str = ngx.req.get_headers()[param]
        if str ~= nil then
            return str
        else
            return nil
        end
    elseif ngxmatch(data,"^GetParam:","isjo") then
        param = string.match(data,'GetParam:(.*)')
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
        if key == param then
            return val
        end
    end
    return nil
    elseif ngxmatch(data,"^PostParam:","isjo") then
        param = string.match(data,':(.*)')
        local args = ngx.req.get_post_args()
        for key, val in pairs(args) do
                    if key == param then
                            return val
                    end
            end
        return nil
    elseif ngxmatch(data,"^CookieParam:","isjo") then
        param = string.match(data,':(.*)')
        local cookie = ngx.var.http_cookie
        if param ~=nil and cookie ~= nil then
            local ck = string.match(cookie,param..'=([%w_]+)')
            return ck
        end
    else
        return nil
    end
end

function denycc()
    if CCDeny then
        local blockiplimit = ngx.shared.blockiplimit
        local clientip=ngx.var.remote_addr
        --判断是否存在
        local blockipreq,_=blockiplimit:get(clientip)
        if 	blockipreq then
            log('CC deny',"-",clientip)
            say_html("IP deny:"..clientip)
            return true 
        end
    
        for _,rule in pairs(denyccrules) do
            if rule ~="" and string.sub(rule,1,1) ~= "#" then
                local data = string.match(rule,'(.*)%s+%d+/%d+%s+%d+')
                local CCrate = string.match(rule,'.*%s+(%d+/%d+)%s+%d+')
                local bantime = tonumber(string.match(rule,'.*%s+.*%s+(%d+)'))
                if data ~= nil and CCrate ~=nil and bantime ~=nil then
                    local token=gettoken(data)
                    if token ~=nil then
                        local CCcount=tonumber(string.match(CCrate,'(.*)/'))
                        local CCseconds=tonumber(string.match(CCrate,'/(.*)'))
                        local limit = ngx.shared.limit
                        local req,_=limit:get(token)
                        if req then
                            if req > CCcount then
                                log('CC deny2',rule,req)
                                blockiplimit:set(clientip,1,bantime)
                                say_html("CC deny:"..clientip)
                                return true
                            else
                                limit:incr(token,1)
                            end
                        else
                            limit:set(token,1,CCseconds)
                        end
                    end
                end          
            end
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if WhiteIPCheck then
        local clientip=ngx.var.remote_addr
        for _,rule in pairs(whiteiprules) do
            
            -- if string.sub(clientip,1,5) == "40.77" then
            --     log('whiteip check',rule,clientip)
            -- end
            
            if rule ~="" and string.sub(rule,1,1) ~= "#" and ngxmatch(clientip,rule,"isjo") then
                -- log('whiteip',rule,clientip)
                return true
            end
        end
        return false
    end
end


function blockip()
    if BlockIPCheck then
        local clientip=ngx.var.remote_addr
        for _,rule in pairs(blockiprules) do
            if rule ~="" and string.sub(rule,1,1) ~= "#" and ngxmatch(clientip,rule,"isjo") then
                    log('blockip deny',rule,'-')
                    say_html("block ip:"..clientip)
                    return true
            end
        end
        return false
    end
end
