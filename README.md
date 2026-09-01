# Lua Nginx Edge Backend

Lua modules for OpenResty/ngx_lua: WAF rules, rate limiting, JWT validation, and request sanitization. Includes a Python reference port for CI testing since Lua runtime may not be available.

## Overview

The Lua Nginx Edge Backend is an educational toolkit designed to demonstrate OpenResty Lua module development, web application firewall (WAF) rules, rate limiting techniques, and request sanitization patterns. This toolkit helps developers and security researchers understand how to extend OpenResty/ngx_lua with security-focused modules in a controlled, educational environment.

**Important:** This tool is intended solely for educational and authorized OpenResty development purposes. Only test and evaluate Lua modules on systems you own or have explicit written permission to test. Unauthorized modification of web server configurations may violate applicable policies and regulations.

## Features

### WAF Rules

The module includes educational Web Application Firewall rules designed to demonstrate common protection patterns:

- **SQL injection detection**: Pattern-based detection of common SQL injection attempts
- **Cross-site scripting (XSS) prevention**: Detection and blocking of XSS payloads
- **Path traversal protection**: Prevention of directory traversal attacks
- **Request size limiting**: Configuration options for limiting request sizes
- **Header validation**: Validation of request headers for common attacks

### Rate Limiting

Educational rate limiting demonstrations:

- **Token bucket algorithm**: Implementation of the token bucket rate limiting algorithm
- **Leaky bucket algorithm**: Alternative rate limiting approach
- **Configurable limits**: Per-IP and per-route rate limit configurations
- **Burst handling**: Configuration of allowed burst traffic

### JWT Validation

Lua-based JWT validation demonstrations:

- **Header inspection**: JWT header analysis and validation
- **Basic claim verification**: Educational claim checking patterns
- **Signature verification concepts**: Demonstrating JWT signature validation architecture
- **Token revocation patterns**: Educational approaches to token invalidation

### Request Sanitization

Request data sanitization techniques:

- **Input escaping**: HTML escaping and sanitization patterns
- **Parameter validation**: Input validation schemas and patterns
- **Output encoding**: Context-appropriate output encoding
- **Malicious payload detection**: Pattern-based detection of common attack payloads

### Python Reference Port

- **CI testing compatibility**: Python reference implementation for environments without Lua runtime
- **Test suite**: Comprehensive pytest test coverage
- **Feature parity**: Core functionality mirrored from Lua implementation
- **Educational focus**: Demonstrates equivalent patterns in Python

## Installation

### Requirements

- **OpenResty** 1.19+ (for Lua module deployment)
- **Lua 5.1+** (standard with OpenResty)
- **Python 3.8+** (for reference port and CI testing)

### Lua Module Installation

```bash
# Clone the repository
git clone https://github.com/OpKnock/lua-nginx-edge-backend.git

# Build with OpenResty
cd lua-nginx-edge-backend
./build.sh          # Or use your OpenResty build system

# Enable module in OpenResty configuration
# Add to openresty.conf:
# lua_package_path ";/path/to/lua-nginx-edge-backend/?.lua;"

# Restart OpenResty
```

### Python Reference Port

```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# Install with test dependencies
pip install -e .[test]
```

### Verify Installation

```bash
# Check Lua module
luarocks list | grep lua-nginx-edge

# Check Python reference
python -m pytest --version
python -m lua_nginx_edge --help  # If entry point exists
```

## Usage Examples

### Lua Module Usage

```lua
-- Example: Basic WAF rule integration
access_by_lua_block {
    local waf = require("lua_nginx_edge_backend.waf")
    if waf.check_request() == false then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
}

-- Example: Rate limiting configuration
access_by_lua_block {
    local rate_limit = require("lua_nginx_edge_backend.rate_limit")
    rate_limit.apply({ rate = "10-r/s", burst = 20 })
}

-- Example: JWT validation
access_by_lua_block {
    local jwt_validator = require("lua_nginx_edge_backend.jwt_validator")
    if not jwt_validator.verify() then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("Invalid JWT token")
        return ngx.exit()
    end
}
```

### Python Reference Port

```bash
# Run the test suite
python -m pytest

# Run specific tests
python -m pytest test_waf.py -v
python -m pytest test_rate_limit.py -v
```

## Safety and Ethics

### Critical Safety Guidelines

This tool must only be used for authorized OpenResty development and testing.

- **Only test Lua modules on systems you own or have explicit permission to modify**
- **Unauthorized modification of web server configurations** may violate Computer Fraud and Abuse Act (CFAA), telecommunications regulations, and equivalent laws
- **Always test in isolated development environments** before production deployment
- **Keep OpenResty and Lua versions updated** to avoid known vulnerabilities in the runtime itself

### Educational Value

Understanding OpenResty Lua module development helps:

- Build more secure web applications and APIs
- Design effective WAF rules and rate limiting
- Implement proper request validation and sanitization
- Contribute to open-source security modules for nginx

### Production Deployment Considerations

- **Performance impact**: Evaluate Lua module impact on request latency
- **Memory usage**: Monitor Lua VM memory consumption
- **Error handling**: Proper error handling in Lua critical sections
- **Security scanning**: Scan Lua modules for vulnerabilities before deployment

## Technical Details

- **Language**: Lua 5.1+ (with OpenResty extensions)
- **Framework**: OpenResty (nginx + LuaJIT)
- **Cross-Platform**: Runs on any platform supporting OpenResty
- **Performance**: LuaJIT provides near-C performance for Lua code

## License

MIT - This project is free to use, modify, and distribute for authorized educational and testing purposes. See the LICENSE file for full terms and conditions.