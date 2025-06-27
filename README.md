# Build the docker image 
Run:
  - docker compose down && clear && docker compose up -d --build
  
# Monitor
  - clear && docker exec -it snort3-container snort -c snort.lua -i ens33 --pcap-show

  # Count events logged
  - clear && cat alert_json.txt | grep -E '^{.*}$' | wc -l


### Only one logger can be enabled
If alert_fast is enabled in snort.lua then warnings appear on terminal.
If alert_json is enables in snort.lua then all warnings are logged in a file.

# Debugging 
  - clear && docker logs snort3-container

## Misc
From Snort box to chekc network flow:
  - clear && sudo tcpdump -i ens33