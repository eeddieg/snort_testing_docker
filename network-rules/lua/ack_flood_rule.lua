ips =
{
  rules =
  {
    {
      id = 910010,
      group = 1,
      match = '/usr/local/snort/etc/snort/appid/odp/lua/detect_ack_flood.lua',
      msg = '[DDoS] Possible TCP ACK flood detected',
      metadata = { 'service any', 'priority high', 'severity critical', 'category Availability' },
      classtype = 'attempted-dos',
    }
  }
}