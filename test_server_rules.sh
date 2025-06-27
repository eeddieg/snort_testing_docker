#! /bin/bash

# Color codes
RESET="\033[0m"
RED="\033[31m"
RED_BOLD="\033[1;31m"
GREEN="\033[32m"
GREEN_BOLD="\033[1;32m"
YELLOW="\033[33m"
YELLOW_BOLD="\033[1;33m"
BLUE="\033[34m"
BLUE_BOLD="\033[1;34m"
RESET="\033[0m"

clear
echo -e "\n${RED_BOLD}WARNING!!${RESET}"
echo -e "${YELLOW_BOLD}\
  This script must be run on a different machine than SNORT.\
  ${RESET}"
sleep 5
echo -e "${GREEN_BOLD}Proceeding...${RESET}"

is_valid_ip() {
  local ip=$1
  local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

  if [[ $ip =~ $regex ]]; then
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
      if ((octet < 0 || octet > 255)); then
        return 1
      fi
    done
    return 0
  else
    return 1
  fi
}

# Check if IP argument is provided
if [ $# -lt 1 ]; then
  echo -e "${RED}Error:${RESET} Please provide the SNORT_IP address."
  echo -e "${YELLOW_BOLD}Usage:${RESET} $0 <IPv4-address>"
  exit 1
fi

IP="$1"

# Validate IP
if is_valid_ip "$IP"; then
  echo -e "\n${GREEN_BOLD}Valid IP:${RESET} $IP"
else
  echo -e "${RED}Invalid IP format:${RESET} $IP"
  exit 1
fi

echo -e ""
echo -e "${BLUE_BOLD}##########################${RESET}"
echo -e "${BLUE_BOLD}### Apache HTTP Server ###${RESET}"
echo -e "${BLUE_BOLD}##########################${RESET}"
echo -e ""
echo -e "${GREEN_BOLD}.htaccess file exposure${RESET}"
curl http://$IP/.htaccess
echo -e ""
echo -e "${GREEN_BOLD}HTTP GET Request to a Suspicious URI${RESET}"
curl http://$IP/admin
echo -e ""
echo -e "${GREEN_BOLD}Directory Traversal Attempt${RESET}"
curl http://$IP/../../../../anything
echo -e ""
echo -e "${GREEN_BOLD}HTTP Basic Authentication Usage${RESET}"
curl -u user:pass http://$IP/
echo -e ""
echo -e "${GREEN_BOLD}HTTP POST to Shell Upload Locations${RESET}"
curl -X POST http://$IP/upload.php -d 'foo=bar'

echo -e "\n"
echo -e "${BLUE_BOLD}############################${RESET}"
echo -e "${BLUE_BOLD}### Apache TOMCAT Server ###${RESET}"
echo -e "${BLUE_BOLD}############################${RESET}"
echo -e ""
echo -e "${GREEN_BOLD}Apache Tomcat HTTP Request to .jsp files${RESET}"
curl -X POST http://$IP/test.jsp -d 'foo=bar'
echo -e ""
echo -e "${GREEN_BOLD}Apache Tomcat Manager Login Attempt${RESET}"
curl http://$IP/manager/html
echo -e ""
echo -e "${GREEN_BOLD}AJP Ghostcat CVE-2020-1938 exploit attempt (basic signature)${RESET}"
printf "\x12\x34\x02\x0A" | nc $IP 8009
echo -e ""
echo -e "${GREEN_BOLD}AJP Ghostcat CVE-2020-1938 exploit attempt (basic signature)${RESET}"
printf "\x0A\x0B" | nc $IP 8009

echo -e "\n"
echo -e "${BLUE_BOLD}####################${RESET}"
echo -e "${BLUE_BOLD}### NGINX Server ###${RESET}"
echo -e "${BLUE_BOLD}####################${RESET}"
echo -e ""
echo -e "${GREEN_BOLD}URI Smuggling with Double Slashes (GET //admin, GET ///api, etc)${RESET}"
curl http://$IP////etc/passwd
echo -e ""
echo -e "${GREEN_BOLD}Attempt to bypass Nginx rules using encoded slash${RESET}"
curl http://$IP////etc%2Fpasswd
echo -e ""
echo -e "${GREEN_BOLD}AAttempt to access Status Page${RESET}"
curl http://$IP/nginx_status
echo -e ""
echo -e "${GREEN_BOLD}Access to web.xml file${RESET}"
curl http://$IP/WEB-INF/web.xml

echo -e "\n"
echo -e "${BLUE_BOLD}###############${RESET}"
echo -e "${BLUE_BOLD}### VARIOUS ###${RESET}"
echo -e "${BLUE_BOLD}###############${RESET}"
echo -e ""
echo -e "${GREEN_BOLD}HTTP User-Agent with Suspicious Scanner${RESET}"
# curl -A "Nikto/2.1.6" http://$IP/
curl -H "User-Agent: Nikto" http://$IP/
