-- large_http_post.lua
-- Snort 3 Lua detection script for large HTTP POST requests

function init(args)
  -- Initialization, called once at start
  return true
end

function match(args)
  -- args is a table of extracted protocol fields available in Snort 3 Lua environment

  -- Check if HTTP method is POST
  local method = args['http.method']
  if method == nil or method:upper() ~= "POST" then
    return 0 -- no match
  end

  -- Get HTTP Content-Length header (may be nil)
  local content_length = args['http.content_length']
  if content_length == nil then
    return 0 -- no content length, skip
  end

  local size = tonumber(content_length)
  if size == nil then
    return 0 -- invalid content length value
  end

  -- Threshold: 50 MB = 50 * 1024 * 1024 bytes
  if size > 50 * 1024 * 1024 then
    return 1 -- matched large POST
  end

  return 0 -- no match
end

function rule()
  return {
    id = 1000001,
    message = "Data Exfiltration via Large HTTP POST",
    severity = 3,
    category = "Data Exfiltration",
    author = "YourName",
  }
end
dd if=/dev/zero of=largefile.bin bs=1M count=51
