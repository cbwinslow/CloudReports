#!/bin/bash

# System Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/system_info_$TIMESTAMP.json"

# Function to collect system information
collect_system_info() {
    local output_file=$1
    
    # Collect system information
    local sys_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "os": {
    "name": "$(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')",
    "kernel": "$(uname -r)",
    "architecture": "$(uname -m)"
  },
  "uptime": "$(uptime -p)",
  "load_average": [$(uptime | awk -F'load average:' '{print $2}' | sed 's/^[[:space:]]*//' | tr ',' '\n' | sed 's/^[[:space:]]*//' | tr '\n' ',' | sed 's/,$//')],
  "cpu": {
    "model": "$(lscpu | grep "Model name" | cut -d: -f2 | sed 's/^[[:space:]]*//')",
    "cores": "$(nproc)",
    "threads": "$(lscpu | grep "CPU(s):" | head -n1 | cut -d: -f2 | sed 's/^[[:space:]]*//')"
  },
  "memory": {
    $(free -b | awk '
      NR==2 {
        total = $2
        used = $3
        free = $4
        printf "\"total_bytes\": %d,\n", total
        printf "\"used_bytes\": %d,\n", used
        printf "\"free_bytes\": %d,\n", free
        printf "\"total_gb\": %.2f,\n", total/1024/1024/1024
        printf "\"used_gb\": %.2f,\n", used/1024/1024/1024
        printf "\"free_gb\": %.2f", free/1024/1024/1024
      }
    ')
  },
  "processes": {
    "total": $(ps aux | wc -l),
    "running": $(ps aux | awk '$8 ~ /^[RD]/ {count++} END {print count+0}')
  }
}
EOF
)

    echo "$sys_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the system information
collect_system_info "$REPORT_FILE"

echo "System information report generated: $REPORT_FILE"