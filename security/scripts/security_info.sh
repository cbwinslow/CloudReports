#!/bin/bash

# Security Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/security_info_$TIMESTAMP.json"

# Function to collect security information
collect_security_info() {
    local output_file=$1
    
    # Collect security information
    local security_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "failed_logins": [
$(lastb | head -n -2 | while read -r line; do
  if [[ -n "$line" ]]; then
    user=$(echo "$line" | awk '{print $1}')
    tty=$(echo "$line" | awk '{print $2}')
    from=$(echo "$line" | awk '{print $3}')
    time=$(echo "$line" | cut -d' ' -f4-7)
    
    echo "    {
      \"user\": \"$user\",
      \"tty\": \"$tty\",
      \"from\": \"$from\",
      \"time\": \"$time\"
    },"
  fi
done | sed '$ s/,$//')
  ],
  "open_ports": [
$(ss -tuln | grep LISTEN | while read -r line; do
  protocol=$(echo "$line" | awk '{print $1}')
  local_addr=$(echo "$line" | awk '{print $5}')
  port=$(echo "$local_addr" | awk -F: '{print $NF}')
  
  echo "    {
      \"protocol\": \"$protocol\",
      \"address\": \"$local_addr\",
      \"port\": \"$port\"
    },"
done | sed '$ s/,$//')
  ],
  "users": [
$(getent passwd | while IFS=: read -r username password uid gid gecos home_directory shell; do
  if [[ $uid -ge 1000 && $uid -lt 65534 ]]; then
    echo "    {
      \"username\": \"$username\",
      \"uid\": $uid,
      \"gid\": $gid,
      \"home\": \"$home_directory\",
      \"shell\": \"$shell\"
    },"
  fi
done | sed '$ s/,$//')
  ],
  "sudoers": [
$(getent group sudo | cut -d: -f4 | tr ',' '\n' | while read -r user; do
  if [[ -n "$user" ]]; then
    echo "    {
      \"user\": \"$user\"
    },"
  fi
done | sed '$ s/,$//')
  ],
  "recent_auth_events": [
$(journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -i "Accepted\|Failed\|Invalid\|Session opened\|Disconnected" | tail -n 10 | while read -r line; do
  timestamp=$(echo "$line" | awk '{print $1" "$2" "$3}')
  message=$(echo "$line" | cut -d' ' -f4- | sed 's/"/\\"/g')
  echo "    {
      \"timestamp\": \"$timestamp\",
      \"message\": \"$message\"
    },"
done | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$security_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the security information
collect_security_info "$REPORT_FILE"

echo "Security information report generated: $REPORT_FILE"