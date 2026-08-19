-- lua-nginx-edge-backend: Request sanitization module for OpenResty

local _M = {}
local cjson = require "cjson"

local SUSPICIOUS_HEADERS = {
    "x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-proto",
    "x-original-url", "x-rewrite-url", "forwarded"
}

local SANITIZE_PATTERNS = {
    {pattern = "[<>]", replacement = ""},
    {pattern = "javascript:", replacement = ""},
    {pattern = "vbscript:", replacement = ""},
    {pattern = "on%w+%s*=", replacement = ""},
}

function _M.sanitize_input(input)
    if not input then return "" end
    local out = input
    for _, rule in ipairs(SANITIZE_PATTERNS) do
        out = ngx.re.gsub(out, rule.pattern, rule.replacement, "i")
    end
    return out
end

function _M.sanitize_headers()
    local headers = ngx.req.get_headers()
    for _, h in ipairs(SUSPICIOUS_HEADERS) do
        if headers[h] then
            ngx.req.clear_header(h)
        end
    end
end

function _M.sanitize_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body then
        local sanitized = _M.sanitize_input(body)
        if sanitized ~= body then
            ngx.req.set_body_data(sanitized)
        end
    end
end

function _M.apply()
    _M.sanitize_headers()
    _M.sanitize_body()
end

return _M