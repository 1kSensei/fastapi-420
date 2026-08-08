-- Sliding window counter: weighted average of current + previous
-- fixed window, computed and incremented in one round trip so no
-- other client can slip a request in between "read previous count"
-- and "increment current count".
--
-- KEYS[1] = current window key   "sw:{client}:{window_id}"
-- KEYS[2] = previous window key  "sw:{client}:{window_id - 1}"
-- ARGV[1] = window_seconds
-- ARGV[2] = overlap (float, precomputed in Python: how much of the
--           previous window's traffic is still "in view" of a sliding
--           window ending now)
--
-- Returns: {current_count_after_incr, previous_count, estimate*1000}
-- (estimate scaled by 1000 and truncated since Lua/Redis integers
-- can't return a float precisely; Python divides back down.)

local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1] * 2)
end

local previous = tonumber(redis.call('GET', KEYS[2]) or "0")
local overlap = tonumber(ARGV[2])
local estimate = current + previous * overlap

return {current, previous, math.floor(estimate * 1000)}
