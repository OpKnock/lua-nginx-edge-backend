-- lua-nginx-edge-backend: Rate limiting module for OpenResty

local _M = {}
local resty_lock = require "resty.lock"

local function make_key(prefix, identifier)
    return prefix .. ":" .. identifier
end

function _M.limit(config)
    local lock = resty_lock:new("ratelimit_locks")
    local key = make_key(config.key_prefix or "rl", config.identifier or ngx.var.remote_addr)
    local elapsed, err = lock:lock(key)
    if not elapsed then
        ngx.log(ngx.ERR, "failed to acquire lock: ", err)
        return false
    end
    local dict = ngx.shared[config.dict_name or "ratelimit"]
    local count = dict:get(key) or 0
    if count >= (config.max_requests or 100) then
        lock:unlock()
        return false
    end
    dict:incr(key, 1, 0, config.window_seconds or 60)
    lock:unlock()
    return true
end

function _M.check_limit(config)
    local ok = _M.limit(config)
    if not ok then
        ngx.exit(429)
    end
end

return _M