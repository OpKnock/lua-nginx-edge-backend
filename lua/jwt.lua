-- lua-nginx-edge-backend: JWT validation module for OpenResty

local _M = {}
local cjson = require "cjson"
local jwt = require "resty.jwt"

local function b64url_decode(input)
    local rem = #input % 4
    if rem > 0 then
        input = input .. string.rep("=", 4 - rem)
    end
    input = input:gsub("-", "+"):gsub("_", "/")
    return ngx.decode_base64(input)
end

local function verify_hs256(payload, signature, secret)
    local signing_input = payload
    local expected = ngx.hmac_sha256(secret, signing_input)
    return expected == signature
end

function _M.validate(token, secret)
    if not token or not secret then
        return nil, "missing token or secret"
    end
    local parts = {}
    for part in token:gmatch("[^%.]+") do
        table.insert(parts, part)
    end
    if #parts ~= 3 then
        return nil, "malformed token"
    end
    local header_b64, payload_b64, sig_b64 = parts[1], parts[2], parts[3]
    local header = cjson.decode(b64url_decode(header_b64))
    local payload = cjson.decode(b64url_decode(payload_b64))
    if header.alg ~= "HS256" then
        return nil, "unsupported algorithm: " .. (header.alg or "none")
    end
    local signing_input = header_b64 .. "." .. payload_b64
    local signature = b64url_decode(sig_b64)
    if not verify_hs256(signing_input, signature, secret) then
        return nil, "invalid signature"
    end
    local now = ngx.time()
    if payload.exp and now > payload.exp then
        return nil, "token expired"
    end
    if payload.nbf and now < payload.nbf then
        return nil, "token not yet valid"
    end
    return payload, nil
end

function _M.require_auth(secret)
    local auth = ngx.var.http_authorization
    if not auth then
        ngx.exit(401)
    end
    local token = auth:match("^Bearer%s+(.+)$")
    if not token then
        ngx.exit(401)
    end
    local payload, err = _M.validate(token, secret)
    if not payload then
        ngx.log(ngx.WARN, "JWT validation failed: ", err)
        ngx.exit(401)
    end
    ngx.ctx.jwt_payload = payload
    return payload
end

return _M