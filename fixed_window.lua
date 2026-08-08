-- Fixed window counter, atomic increment + first-write expiry.
--
-- KEYS[1] = "fw:{client}:{window_id}"
-- ARGV[1] = window_seconds (used as the TTL so stale windows self-clean)
--
-- Returns the post-increment count. Setting the TTL only on the first
-- write of a window (count == 1) avoids resetting the expiry on every
-- request, which would otherwise let a steady trickle of traffic keep
-- a window alive forever.

local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
