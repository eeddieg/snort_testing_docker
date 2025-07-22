-- detect_ack_flood.lua

local ack_flood_tracker = {}

local threshold = 20  -- ACK packet count threshold
local time_window = 5  -- Time window in seconds

function match(packet)
  -- Only match plain ACK packets (not SYN, FIN, RST)
  if not packet.tcp or not packet.tcp.ack or packet.tcp.syn or packet.tcp.fin or packet.tcp.rst then
    return false
  end

  local src_ip = packet.ip_src
  local now = os.time()

  if not ack_flood_tracker[src_ip] then
    ack_flood_tracker[src_ip] = { count = 1, start = now }
  else
    local tracker = ack_flood_tracker[src_ip]

    if now - tracker.start <= time_window then
      tracker.count = tracker.count + 1
      if tracker.count >= threshold then
        tracker.count = 0
        tracker.start = now
        return true
      end
    else
      tracker.count = 1
      tracker.start = now
    end
  end

  return false
end

return {
  match = match
}
