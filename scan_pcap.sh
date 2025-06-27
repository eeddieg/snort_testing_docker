#!/bin/bash

# Check if a PCAP file was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <path_to_pcap>"
  exit 1
fi

PCAP_FILE="$1"

/usr/local/snort/bin/snort \
  -c /usr/local/snort/etc/snort/snort.lua \
  -r "$PCAP_FILE" \
  -A alert_json \
  -l /snort-docker/logs \
  --lua "alert_json = {file = true , fields = 'timestamp sid gid  dst_port src_port pkt_num priority  pkt_gen pkt_len dir src_ap dst_ap rule action msg class'}"
