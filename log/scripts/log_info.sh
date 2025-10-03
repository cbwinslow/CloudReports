#!/bin/bash

# Log Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/log_info_$TIMESTAMP.json"

# Function to collect log information
collect_log_info() {
    local output_file=$1
    
    # Collect log information
    local log_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "syslog_summary": {
    "critical": $(journalctl -p crit --since "24 hours ago" --no-pager 2>/dev/null | wc -l),
    "errors": $(journalctl -p err --since "24 hours ago" --no-pager 2>/dev/null | wc -l),
    "warnings": $(journalctl -p warning --since "24 hours ago" --no-pager 2>/dev/null | wc -l),
    "info": $(journalctl -p info --since "24 hours ago" --no-pager 2>/dev/null | wc -l)
  },
  "auth_logs": {
    "failed_logins": $(journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -i "failed\|invalid\|denied" | wc -l),
    "successful_logins": $(journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -i "accepted\|session opened" | wc -l),
    "recent_auth_events": [
$(journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -i "Accepted\|Failed\|Invalid\|Session opened" | tail -n 10 | while read -r line; do
  timestamp=$(echo "$line" | awk '{print $1" "$2" "$3}')
  message=$(echo "$line" | cut -d' ' -f4- | sed 's/"/\\"/g')
  echo "      {
        \"timestamp\": \"$timestamp\",
        \"message\": \"$message\"
      },"
done | sed '$ s/,$//')
    ]
  },
  "service_logs": [
$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | tail -n +2 | while read -r line; do
  if [[ -n "$line" ]]; then
    service=$(echo "$line" | awk '{print $1}')
    if [[ "$service" != "0 loaded units listed." ]]; then
      load_state=$(echo "$line" | awk '{print $2}')
      active_state=$(echo "$line" | awk '{print $3}')
      sub_state=$(echo "$line" | awk '{print $4}')
      description=$(echo "$line" | cut -d' ' -f5- | sed 's/"/\\"/g')
      echo "    {
      \"service\": \"$service\",
      \"load_state\": \"$load_state\",
      \"active_state\": \"$active_state\",
      \"sub_state\": \"$sub_state\",
      \"description\": \"$description\"
    },"
    fi
  fi
done | sed '$ s/,$//')
  ],
  "disk_log_size": {
    "syslog": $(du -b /var/log/syslog 2>/dev/null | cut -f1 || echo 0),
    "auth": $(du -b /var/log/auth.log 2>/dev/null | cut -f1 || echo 0),
    "kern": $(du -b /var/log/kern.log 2>/dev/null | cut -f1 || echo 0)
  }
}
EOF
)

    echo "$log_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the log information
collect_log_info "$REPORT_FILE"

echo "Log information report generated: $REPORT_FILE"