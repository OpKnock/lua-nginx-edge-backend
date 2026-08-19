-- lua-nginx-edge-backend: WAF and security modules for OpenResty
-- These modules implement core security logic in Lua for nginx/OpenResty

local _M = {}
local cjson = require "cjson"

local WAF_RULES = {
    {id = "sql-1", pattern = "(?i)(union|select|insert|update|delete|drop)\\s+.*\\s+(from|into|table)"},
    {id = "sql-2", pattern = "(?i)('|\\bOR\\b|\\bAND\\b)\\s*=\\s*['\"]?\\s*['\"]?"},
    {id = "xss-1", pattern = "(?i)<script[^>]*>.*</script>"},
    {id = "xss-2", pattern = "(?i)on(load|error|click|mouseover)\\s*="},
    {id = "lfi-1", pattern = "\\.\\./"},
    {id = "rce-1", pattern = "(?i)(system|exec|shell_exec|passthru)\\s*\\("},
}

local function match_waf_rules(input)
    local hits = {}
    for _, rule in ipairs(WAF_RULES) do
        local m = ngx.re.match(input, rule.pattern)
        if m then
            table.insert(hits, rule.id)
        end
    end
    return hits
end

function _M.inspect_request()
    local hits = {}
    -- Check query string
    local args = ngx.req.get_uri_args()
    for k, v in pairs(args) do
        local val = type(v) == "table" and table.concat(v, ",") or v
        local rule_hits = match_waf_rules(k .. "=" .. val)
        for _, h in ipairs(rule_hits) do table.insert(hits, h) end
    end
    -- Check body for POST
    if ngx.req.get_method() == "POST" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body then
            local rule_hits = match_waf_rules(body)
            for _, h in ipairs(rule_hits) do table.insert(hits, h) end
        end
    end
    if #hits > 0 then
        return false, hits
    end
    return true, {}
end

function _M.block_if_malicious()
    local ok, hits = _M.inspect_request()
    if not ok then
        ngx.log(ngx.WARN, "WAF blocked: ", table.concat(hits, ", "))
        ngx.exit(403)
    end
end

return _M