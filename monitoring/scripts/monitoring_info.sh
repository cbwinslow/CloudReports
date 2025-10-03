#!/bin/bash

# Monitoring Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/monitoring_info_$TIMESTAMP.json"

# Function to collect monitoring information
collect_monitoring_info() {
    local output_file=$1
    
    # Collect monitoring information
    local monitoring_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "load_average": {
    "1min": $(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ','),
    "5min": $(uptime | awk -F'load average:' '{print $2}' | awk '{print $2}' | tr -d ','),
    "15min": $(uptime | awk -F'load average:' '{print $2}' | awk '{print $3}' | tr -d ',')
  },
  "disk_io": [
$(iostat -d 1 2 2>/dev/null | tail -n +4 | head -n -1 | while read -r line; do
  if [[ -n "$line" ]]; then
    device=$(echo "$line" | awk '{print $1}')
    tps=$(echo "$line" | awk '{print $2}')
    read_mb=$(echo "$line" | awk '{print $3}')
    write_mb=$(echo "$line" | awk '{print $4}')
    
    if [[ "$device" != "Device:" ]]; then
      echo "    {
      \"device\": \"$device\",
      \"tps\": $tps,
      \"read_mb_per_sec\": $read_mb,
      \"write_mb_per_sec\": $write_mb
    },"
    fi
  fi
done | sed '$ s/,$//')
  ],
  "network_io": [
$(cat /proc/net/dev | grep -v -E "^(Inter|face)" | while read -r line; do
  interface=$(echo "$line" | awk '{print $1}' | sed 's/://')
  if [[ "$interface" != "lo" ]]; then
    rx_bytes=$(echo "$line" | awk '{print $2}')
    tx_bytes=$(echo "$line" | awk '{print $10}')
    rx_packets=$(echo "$line" | awk '{print $3}')
    tx_packets=$(echo "$line" | awk '{print $11}')
    
    echo "    {
      \"interface\": \"$interface\",
      \"rx_bytes\": $rx_bytes,
      \"tx_bytes\": $tx_bytes,
      \"rx_packets\": $rx_packets,
      \"tx_packets\": $tx_packets
    },"
  fi
done | sed '$ s/,$//')
  ],
  "custom_checks": [
    {
      \"name\": \"root_disk_space\",
      \"status\": \"$(if [ \$(df / | awk 'NR==2 {print \$5}' | sed 's/%//') -gt 90 ]; then echo \"CRITICAL\"; elif [ \$(df / | awk 'NR==2 {print \$5}' | sed 's/%//') -gt 80 ]; then echo \"WARNING\"; else echo \"OK\"; fi)\",
      \"value\": \"\$(df / | awk 'NR==2 {print \$5}')\",
      \"threshold\": \"> 90% for CRITICAL, > 80% for WARNING\"
    },
    {
      \"name\": \"root_inode_usage\",
      \"status\": \"\$(if [ \$(df -i / | awk 'NR==2 {print \$5}' | sed 's/%//') -gt 90 ]; then echo \"CRITICAL\"; elif [ \$(df -i / | awk 'NR==2 {print \$5}' | sed 's/%//') -gt 80 ]; then echo \"WARNING\"; else echo \"OK\"; fi)\",
      \"value\": \"\$(df -i / | awk 'NR==2 {print \$5}')\",
      \"threshold\": \"> 90% for CRITICAL, > 80% for WARNING\"
    },
    {
      \"name\": \"memory_usage\",
      \"status\": \"\$(if [ \$(free | awk 'NR==2 {print \$3/\$2 * 100.0}' | cut -d. -f1) -gt 90 ]; then echo \"CRITICAL\"; elif [ \$(free | awk 'NR==2 {print \$3/\$2 * 100.0}' | cut -d. -f1) -gt 80 ]; then echo \"WARNING\"; else echo \"OK\"; fi)\",
      \"value\": \"\$(free | awk 'NR==2 {printf \"%.2f%%\", \$3/\$2 * 100.0}')\",
      \"threshold\": \"> 90% for CRITICAL, > 80% for WARNING\"
    },
    {
      \"name\": \"swap_usage\",
      \"status\": \"\$(if [ \$(free | awk 'NR==4 {print \$3/\$2 * 100.0}' | cut -d. -f1 2>/dev/null || echo 0) -gt 50 ]; then echo \"CRITICAL\"; elif [ \$(free | awk 'NR==4 {print \$3/\$2 * 100.0}' | cut -d. -f1 2>/dev/null || echo 0) -gt 25 ]; then echo \"WARNING\"; else echo \"OK\"; fi)\",
      \"value\": \"\$(free | awk 'NR==4 {printf \"%.2f%%\", \$3/\$2 * 100.0}' 2>/dev/null || echo \"0.00%\")\",
      \"threshold\": \"> 50% for CRITICAL, > 25% for WARNING\"
    }
  ],
  "service_health": [
$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | tail -n +2 | head -n 10 | while read -r line; do
  if [[ -n "$line" ]]; then
    service=$(echo "$line" | awk '{print $1}')
    if [[ "$service" != "0 loaded units listed." ]]; then
      active_since=$(systemctl show "$service" --property=ActiveEnterTimestamp --no-pager 2>/dev/null | cut -d'=' -f2-)
      description=$(echo "$line" | cut -d' ' -f5- | sed 's/"/\\"/g')
      echo "    {
      \"service\": \"$service\",
      \"state\": \"running\",
      \"active_since\": \"$active_since\",
      \"description\": \"$description\"
    },"
    fi
  fi
done | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$monitoring_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the monitoring information
collect_monitoring_info "$REPORT_FILE"

echo "Monitoring information report generated: $REPORT_FILE"