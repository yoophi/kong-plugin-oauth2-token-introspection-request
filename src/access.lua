local http = require "resty.http"
local base64 = require "base64"
local cjson = require "cjson"
local re_gmatch = ngx.re.gmatch

local _M = {}

function table_to_string(tbl)
    local result = ""
    for k, v in pairs(tbl) do
        -- Check the key type (ignore any numerical keys - assume its an array)
        if type(k) == "string" then
            result = result .. "[\"" .. k .. "\"]" .. "="
        end

        -- Check the value type
        if type(v) == "table" then
            result = result .. table_to_string(v)
        elseif type(v) == "boolean" then
            result = result .. tostring(v)
        else
            result = result .. "\"" .. v .. "\""
        end
        result = result .. ","
    end
    -- Remove leading commas from the result
    if result ~= "" then
        result = result:sub(1, result:len() - 1)
    end
    return result
end

function _M.execute(conf)
    local res, ok, err
    local scheme, host, port, path = unpack(http:parse_uri(conf.token_introspect_url))
    local token = _M.get_token()
    if not token then
        return kong.response.exit(401, { message = "unauthorized" })
    end

    local httpc = http.new()
    httpc:set_timeout(conf.timeout)
    httpc:connect(host, port)
    if scheme == "https" then
        ok, err = httpc:ssl_handshake()
        if not ok then
            kong.log.err(err)
            return kong.response.exit(500, { message = "An unexpected error occurred" })
        end
    end

    local auth_request = _M.new_auth_request(
            host, port, path, conf.client_id, conf.client_secret, token, conf.keepalive_timeout, 
            conf.auth_method)
    if not auth_request then 
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    res, err = httpc:request(auth_request)
    if not res then
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    if res.status > 299 then
        return kong.response.exit(res.status, res.body)
    end

    local response_body = res:read_body()
    local status, response_json = pcall(cjson.decode, response_body)

    if not status then
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    if not response_json['active'] then
        return kong.response.exit(401, { message = "Unauthorized" })
    end

    for _, name in ipairs(conf.auth_response_headers_to_forward) do
        if response_json[name] then
            kong.service.request.set_header(name, response_json[name])
        end
    end
end

function _M.get_token()
    local authorization_header = kong.request.get_header("authorization")
    if authorization_header then
        local iterator, iter_err = re_gmatch(
                authorization_header, "\\s*[Bb]earer\\s+(.+)")

        if not iterator then
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            return nil, err
        end

        if m and #m > 0 then
            return m[1]
        end
    end
end

function _M.new_auth_request(host, port, path, client_id, client_secret, token, keepalive_timeout, auth_method)
    if not token then
        return nil
    end

    local hostname = host
    if port ~= 80 and port ~= 443 then
        hostname = hostname .. ":" .. tostring(port)
    end

    local headers = {
        charset = "utf-8",
        ["content-type"] = "application/x-www-form-urlencoded; charset=utf-8",
        ["Host"] = hostname,
    }

    local payload = "token=" .. token

    if auth_method == "client_secret_basic" then 
        headers.authorization = "Basic " .. base64.encode( client_id .. ":" .. client_secret )
    else
        payload = payload .. "&client_id=" .. client_id .. "&client_secret=" .. client_secret 
    end

    return {
        method = "POST",
        path = path,
        headers = headers,
        body = payload,
        keepalive_timeout = keepalive_timeout
    }
end

return _M


