---------------------------------------------------------------------------
-- Snort++ configuration
---------------------------------------------------------------------------

-- there are over 200 modules available to tune your policy.
-- many can be used with defaults w/o any explicit configuration.
-- use this conf as a template for your specific configuration.

-- 1. configure defaults
-- 2. configure inspection
-- 3. configure bindings
-- 4. configure performance
-- 5. configure detection
-- 6. configure filters
-- 7. configure outputs
-- 8. configure tweaks

---------------------------------------------------------------------------
-- 1. configure defaults
---------------------------------------------------------------------------

-- HOME_NET and EXTERNAL_NET must be set now
-- setup the network addresses you are protecting
HOME_NET = '192.168.229.0/24'
EXTERNAL_NET = '!$HOME_NET'

include 'snort_defaults.lua'

---------------------------------------------------------------------------
-- 2. configure inspection
---------------------------------------------------------------------------

-- mod = { } uses internal defaults
-- you can see them with snort --help-module mod

-- mod = default_mod uses external defaults
-- you can see them in snort_defaults.lua

-- the following are quite capable with defaults:

stream = { }
stream_ip = { }
stream_icmp = { }
stream_tcp = { }
stream_udp = { }
stream_user = { }
stream_file = { }

arp_spoof = { }
back_orifice = { }
dns = { }
imap = { }
netflow = {}
normalizer = { }
pop = { }
rpc_decode = { }
sip = { }
ssh = { }
ssl = { }
telnet = { }

cip = { }
dnp3 = { }
iec104 = { }
mms = { }
modbus = { }
s7commplus = { }

dce_smb = { }
dce_tcp = { }
dce_udp = { }
dce_http_proxy = { }
dce_http_server = { }

-- see snort_defaults.lua for default_*
gtp_inspect = default_gtp
port_scan = default_med_port_scan
smtp = default_smtp

ftp_server = default_ftp_server
ftp_client = { }
ftp_data = { }

http_inspect = { }
http2_inspect = { }

-- see file_magic.rules for file id rules
file_id = { rules_file = 'file_magic.rules' }
file_policy = { }

js_norm = default_js_norm

-- the following require additional configuration to be fully effective:

appid =
{
    -- appid requires this to use appids in rules
    --app_detector_dir = 'directory to load appid detectors from'
    app_detector_dir = '/usr/local/snort/etc/snort/appid',
}

--[[
reputation =
{
    -- configure one or both of these, then uncomment reputation
    -- (see also related path vars at the top of snort_defaults.lua)

    --blacklist = 'blacklist file name with ip lists'
    --whitelist = 'whitelist file name with ip lists'
}
--]]

---------------------------------------------------------------------------
-- 3. configure bindings
---------------------------------------------------------------------------

wizard = default_wizard

binder =
{
    -- port bindings required for protocols without wizard support
    { when = { proto = 'udp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '53', role='server' },  use = { type = 'dns' } },
    { when = { proto = 'tcp', ports = '111', role='server' }, use = { type = 'rpc_decode' } },
    { when = { proto = 'tcp', ports = '502', role='server' }, use = { type = 'modbus' } },
    { when = { proto = 'tcp', ports = '2123 2152 3386', role='server' }, use = { type = 'gtp_inspect' } },
    { when = { proto = 'tcp', ports = '2404', role='server' }, use = { type = 'iec104' } },
    { when = { proto = 'udp', ports = '2222', role = 'server' }, use = { type = 'cip' } },
    { when = { proto = 'tcp', ports = '44818', role = 'server' }, use = { type = 'cip' } },

    { when = { proto = 'tcp', service = 'dcerpc' },  use = { type = 'dce_tcp' } },
    { when = { proto = 'udp', service = 'dcerpc' },  use = { type = 'dce_udp' } },
    { when = { proto = 'udp', service = 'netflow' }, use = { type = 'netflow' } },

    { when = { service = 'netbios-ssn' },      use = { type = 'dce_smb' } },
    { when = { service = 'dce_http_server' },  use = { type = 'dce_http_server' } },
    { when = { service = 'dce_http_proxy' },   use = { type = 'dce_http_proxy' } },

    { when = { service = 'cip' },              use = { type = 'cip' } },
    { when = { service = 'dnp3' },             use = { type = 'dnp3' } },
    { when = { service = 'dns' },              use = { type = 'dns' } },
    { when = { service = 'ftp' },              use = { type = 'ftp_server' } },
    { when = { service = 'ftp-data' },         use = { type = 'ftp_data' } },
    { when = { service = 'gtp' },              use = { type = 'gtp_inspect' } },
    { when = { service = 'imap' },             use = { type = 'imap' } },
    { when = { service = 'http' },             use = { type = 'http_inspect' } },
    { when = { service = 'http2' },            use = { type = 'http2_inspect' } },
    { when = { service = 'iec104' },           use = { type = 'iec104' } },
    { when = { service = 'mms' },              use = { type = 'mms' } },
    { when = { service = 'modbus' },           use = { type = 'modbus' } },
    { when = { service = 'pop3' },             use = { type = 'pop' } },
    { when = { service = 'ssh' },              use = { type = 'ssh' } },
    { when = { service = 'sip' },              use = { type = 'sip' } },
    { when = { service = 'smtp' },             use = { type = 'smtp' } },
    { when = { service = 'ssl' },              use = { type = 'ssl' } },
    { when = { service = 'sunrpc' },           use = { type = 'rpc_decode' } },
    { when = { service = 's7commplus' },       use = { type = 's7commplus' } },
    { when = { service = 'telnet' },           use = { type = 'telnet' } },

    { use = { type = 'wizard' } }
}

---------------------------------------------------------------------------
-- 4. configure performance
---------------------------------------------------------------------------

-- use latency to monitor / enforce packet and rule thresholds
--latency = { }

-- use these to capture perf data for analysis and tuning
--profiler = { }
--perf_monitor = { }

---------------------------------------------------------------------------
-- 5. configure detection
---------------------------------------------------------------------------

references = default_references
classifications = default_classifications

ips =
{
    -- use this to enable decoder and inspector alerts
    --enable_builtin_rules = true,

    -- use include for rules files; be sure to set your path
    -- note that rules files can include other rules files
    -- (see also related path vars at the top of snort_defaults.lua)

    variables = default_variables,
    rules = [[
    
        include /snort-docker/network-rules/community/snort3-community.rules
        include /snort-docker/network-rules/rules_base_on_issues/4_1.rules
        include /snort-docker/network-rules/rules_base_on_issues/4_2.rules
        include /snort-docker/network-rules/rules_base_on_issues/4_4.rules
        include /snort-docker/network-rules/rules_base_on_issues/9_1.rules
        include /snort-docker/network-rules/rules_base_on_issues/12_2.rules
        include /snort-docker/network-rules/server.rules
        include /snort-docker/network-rules/test.rules
    ]]

}

-- use these to configure additional rule actions
-- react = { }
-- reject = { }

-- use this to enable payload injection utility
-- payload_injector = { }

---------------------------------------------------------------------------
-- 6. configure filters
---------------------------------------------------------------------------

-- below are examples of filters
-- each table is a list of records

--[[
suppress =
{
    -- don't want to any of see these
    { gid = 1, sid = 1 },

    -- don't want to see anything for a given host
    { track = 'by_dst', ip = '1.2.3.4' }

    -- don't want to see these for a given host
    { gid = 1, sid = 2, track = 'by_dst', ip = '1.2.3.4' },
}
--]]

--[[
event_filter =
{
    -- reduce the number of events logged for some rules
    { gid = 1, sid = 1, type = 'limit', track = 'by_src', count = 2, seconds = 10 },
    { gid = 1, sid = 2, type = 'both',  track = 'by_dst', count = 5, seconds = 60 },
}
--]]
event_filter =
{
    -- TEST ICMP rule
    { gid = 1, sid = 1000001, type = 'limit', track = 'by_dst', count = 1, seconds = 40 },
    
    -- reduce the number of events logged for some rules
    { gid = 1, sid = 122101, type = 'limit',  track = 'by_src', count = 1, seconds = 10 },
    { gid = 1, sid = 122102, type = 'limit',  track = 'by_src', count = 1, seconds = 15 },
    { gid = 1, sid = 122103, type = 'limit',  track = 'by_src', count = 1, seconds = 30 },

    -- Apache HTTP Server
    { gid = 1, sid = 10000001, type = 'limit', track = 'by_src', count = 2, seconds = 60 },
    { gid = 1, sid = 10000002, type = 'limit', track = 'by_src', count = 3, seconds = 60 },
    { gid = 1, sid = 10000003, type = 'limit', track = 'by_src', count = 3, seconds = 120 },
    { gid = 1, sid = 10000004, type = 'limit', track = 'by_src', count = 2, seconds = 60 },
    { gid = 1, sid = 10000005, type = 'limit', track = 'by_src', count = 3, seconds = 60 },

    -- Apache Tomcat Server
    { gid = 1, sid = 10000006, type = 'limit', track = 'by_src', count = 3, seconds = 60 },
    { gid = 1, sid = 10000007, type = 'limit', track = 'by_src', count = 2, seconds = 120 },
    { gid = 1, sid = 10000008, type = 'limit', track = 'by_src', count = 2, seconds = 300 },
    { gid = 1, sid = 10000009, type = 'limit', track = 'by_src', count = 2, seconds = 300 },

    -- NGINX Server
    { gid = 1, sid = 1000010,  type = 'limit', track = 'by_src', count = 3, seconds = 60 },
    { gid = 1, sid = 1000011,  type = 'limit', track = 'by_src', count = 3, seconds = 60 },
    { gid = 1, sid = 1000012,  type = 'limit', track = 'by_src', count = 2, seconds = 120 },
    { gid = 1, sid = 1000013,  type = 'limit', track = 'by_src', count = 2, seconds = 120 },

    -- Misc
    -- Suspicious Scanner
    { gid = 1, sid = 100000014, type = 'limit', track = 'by_src', count = 3, seconds = 60 },

    -- DDoS Detection: Abnormal inbound traffic spike detected
    { gid = 1, sid = 910002, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910003, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910004, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910005, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910006, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910007, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910008, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910009, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910010, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910011, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910012, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910013, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910014, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910015, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910016, type = 'limit', track = 'by_src', count = 1, seconds = 60 },
    { gid = 1, sid = 910017, type = 'limit', track = 'by_src', count = 1, seconds = 60 },

}
--]]

--[[
rate_filter =
{
    -- alert on connection attempts from clients in SOME_NET
    { gid = 135, sid = 1, track = 'by_src', count = 5, seconds = 1,
      new_action = 'alert', timeout = 4, apply_to = '[$SOME_NET]' },

    -- alert on connections to servers over threshold
    { gid = 135, sid = 2, track = 'by_dst', count = 29, seconds = 3,
      new_action = 'alert', timeout = 1 },
      
}
--]]

-- Typical lowest rates in packets per second (pps) used
rate_filter = {
    -- Set detection filters for typical packet rates per 60-second window
    -- Apache HTTP Server
    { gid = 1, sid = 10000001, track = 'by_src', count = 5, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 10000002, track = 'by_src', count = 10, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 10000003, track = 'by_src', count = 6, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 10000004, track = 'by_src', count = 4, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 10000005, track = 'by_src', count = 6, seconds = 60, new_action = 'alert', timeout = 300 },

    -- Apache Tomcat Server
    { gid = 1, sid = 10000006, track = 'by_src', count = 5, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 10000007, track = 'by_src', count = 3, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 10000008, track = 'by_src', count = 2, seconds = 300, new_action = 'alert', timeout = 600 },
    { gid = 1, sid = 10000009, track = 'by_src', count = 2, seconds = 300, new_action = 'alert', timeout = 600 },

    -- NGINX Server
    { gid = 1, sid = 1000010,  track = 'by_src', count = 8, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 1000011,  track = 'by_src', count = 8, seconds = 60, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 1000012,  track = 'by_src', count = 3, seconds = 120, new_action = 'alert', timeout = 300 },
    { gid = 1, sid = 1000013,  track = 'by_src', count = 3, seconds = 120, new_action = 'alert', timeout = 300 },

    -- Misc
    { gid = 1, sid = 100000014, track = 'by_src', count = 6, seconds = 60, new_action = 'alert', timeout = 300 },

    -- DDoS Detection: Abnormal inbound traffic spike detected
    -- TCP spike
    { sid = 910002, track = "by_src", count = 1000, seconds = 60, new_action = "alert", timeout = 300 },
    -- UDP flood
    { sid = 910003, track = "by_src", count = 10000, seconds = 60, new_action = "alert", timeout = 300 },
    -- DNS flood
    { sid = 910004, track = "by_src", count = 5000, seconds = 60, new_action = "alert", timeout = 300 },
    -- ICMP echo flood
    { sid = 910005, track = "by_src", count = 1000, seconds = 60, new_action = "alert", timeout = 300 },
    -- SMTP flood
    { sid = 910006, track = "by_src", count = 1000, seconds = 60, new_action = "alert", timeout = 300 },
    -- SYN flood
    { sid = 910007, track = "by_src", count = 5000, seconds = 60, new_action = "alert", timeout = 300 },
    -- SYN-ACK flood
    { sid = 910008, track = "by_src", count = 5000, seconds = 60, new_action = "alert", timeout = 300 },
    -- RST flood
    { sid = 910009, track = "by_src", count = 1000, seconds = 60, new_action = "alert", timeout = 300 },
    -- TCP ACK flood
    { sid = 910010, track = "by_src", count = 5000, seconds = 60, new_action = "alert", timeout = 300 },
    -- ICMP unreachable/TTL-exceeded flood
    { sid = 910011, track = "by_src", count = 1000, seconds = 60, new_action = "alert", timeout = 300 },
    -- NTP amplification
    { sid = 910012, track = "by_src", count = 10000, seconds = 60, new_action = "alert", timeout = 300 },
    -- SSDP amplification
    { sid = 910013, track = "by_src", count = 10000, seconds = 60, new_action = "alert", timeout = 300 },
    -- CHARGEN reflection
    { sid = 910014, track = "by_src", count = 10000, seconds = 60, new_action = "alert", timeout = 300 },
    -- Unsolicited UDP reflection (high port)
    { sid = 910015, track = "by_src", count = 10000, seconds = 60, new_action = "alert", timeout = 300 },
    -- Small TCP fragment flood
    { sid = 910016, track = "by_src", count = 1000, seconds = 60, new_action = "alert", timeout = 300 },
    -- HTTP GET flood (Slowloris)
    { sid = 910017, track = "by_src", count = 50, seconds = 60, new_action = "alert", timeout = 300 },
}

---------------------------------------------------------------------------
-- 7. configure outputs
---------------------------------------------------------------------------

-- event logging
-- you can enable with defaults from the command line with -A <alert_type>
-- uncomment below to set non-default configs
--alert_csv = { }
--alert_alert_fast = { }
alert_json = {
    file = true,
    fields = 'timestamp sid gid dst_port src_port pkt_num priority pkt_gen pkt_len dir src_ap dst_ap rule action msg class'
 }
--alert_full = { }
--alert_sfsocket = { }
--alert_syslog = { }
--unified2 = { }

-- packet logging
-- you can enable with defaults from the command line with -L <log_type>
--log_codecs = { }
--log_hext = { }
--log_pcap = { }

-- additional logs
--packet_capture = { }
--file_log = { }

---------------------------------------------------------------------------
-- 8. configure tweaks
---------------------------------------------------------------------------

if ( tweaks ~= nil ) then
    include(tweaks .. '.lua')
end
