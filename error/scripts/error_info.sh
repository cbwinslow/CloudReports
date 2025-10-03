#!/bin/bash

# Error Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/error_info_$TIMESTAMP.json"

# Function to collect error information
collect_error_info() {
    local output_file=$1
    
    # Collect error information
    local error_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "recent_system_errors": [
$(dmesg --level=err,crit,alert,emerg 2>/dev/null | tail -n 20 | while read -r line; do
  timestamp=$(echo "$line" | cut -d']' -f1 | sed 's/\[//' | xargs)
  message=$(echo "$line" | cut -d']' -f2- | sed 's/^[[:space:]]*//' | sed 's/"/\\"/g')
  echo "    {
      \"timestamp\": \"$timestamp\",
      \"message\": \"$message\"
    },"
done | sed '$ s/,$//')
  ],
  "recent_system_logs_with_errors": [
$(journalctl -p err..emerg --since "24 hours ago" --no-pager 2>/dev/null | tail -n 20 | while read -r line; do
  timestamp=$(echo "$line" | awk '{print $1" "$2" "$3}')
  message=$(echo "$line" | cut -d' ' -f4- | sed 's/"/\\"/g')
  echo "    {
      \"timestamp\": \"$timestamp\",
      \"message\": \"$message\"
    },"
done | sed '$ s/,$//')
  ],
  "disk_errors": [
$(smartctl --scan | cut -d' ' -f1 | while read -r device; do
  if command -v smartctl > /dev/null 2>&1; then
    smart_result=$(smartctl -H "$device" 2>/dev/null)
    if echo "$smart_result" | grep -q "PASSED\|OK"; then
      status="OK"
    else
      status="WARNING"
      details=$(echo "$smart_result" | grep -v "^#" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/  */ /g')
      echo "    {
      \"device\": \"$device\",
      \"status\": \"$status\",
      \"details\": \"$details\"
    },"
    fi
  fi
done | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$error_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the error information
collect_error_info "$REPORT_FILE"

echo "Error information report generated: $REPORT_FILE"