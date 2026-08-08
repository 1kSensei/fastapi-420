-- Token bucket: refill-then-consume, atomically.
--
-- KEYS[1] = "tb:{client}"
-- ARGV[1] = capacity (bucket size / max burst)
-- ARGV[2] = refill_rate (tokens per second)
-- ARGV[3] = now (unix timestamp, float, passed in from Python so the
--           Lua VM's own clock — which can drift slightly from the
--           app server's — is never the source of truth)
-- ARGV[4] = ttl seconds for the key
--
-- Returns: {allowed (0/1), tokens_remaining*1000}

local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local raw = redis.call('GET', KEYS[1])
local tokens = capacity
local last_refill = now

if raw then
    local sep = string.find(raw, ":")
    tokens = tonumber(string.sub(raw, 1, sep - 1))
    last_refill = tonumber(string.sub(raw, sep + 1))
end

local elapsed = math.max(0, now - last_refill)
tokens = math.min(capacity, tokens + elapsed * refill_rate)

local allowed = 0
if tokens >= 1.0 then
    tokens = tokens - 1.0
    allowed = 1
end

redis.call('SET', KEYS[1], tokens .. ":" .. now, 'EX', ttl)

return {allowed, math.floor(tokens * 1000)}
