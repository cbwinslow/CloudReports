#!/bin/bash

# Process Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/process_info_$TIMESTAMP.json"

# Function to collect process information
collect_process_info() {
    local output_file=$1
    
    # Collect process information
    local process_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "processes": [
$(ps -eo pid,ppid,cmd,pcpu,pmem,user,etime | tail -n +2 | head -n 50 | while read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  ppid=$(echo "$line" | awk '{print $2}')
  cpu=$(echo "$line" | awk '{print $4}')
  mem=$(echo "$line" | awk '{print $5}')
  user=$(echo "$line" | awk '{print $6}')
  etime=$(echo "$line" | awk '{print $7}')
  cmd=$(echo "$line" | cut -d' ' -f8- | sed 's/"/\\"/g')
  
  echo "    {
      \"pid\": $pid,
      \"ppid\": $ppid,
      \"command\": \"$cmd\",
      \"cpu_percent\": \"$cpu\",
      \"mem_percent\": \"$mem\",
      \"user\": \"$user\",
      \"elapsed_time\": \"$etime\"
    },"
done | sed '$ s/,$//')
  ],
  "top_cpu_processes": [
$(ps -eo pid,pcpu,pmem,comm --no-headers | sort -k2 -nr | head -n 10 | while read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  cpu=$(echo "$line" | awk '{print $2}')
  mem=$(echo "$line" | awk '{print $3}')
  comm=$(echo "$line" | awk '{print $4}')
  
  echo "    {
      \"pid\": $pid,
      \"command\": \"$comm\",
      \"cpu_percent\": \"$cpu\",
      \"mem_percent\": \"$mem\"
    },"
done | sed '$ s/,$//')
  ],
  "top_mem_processes": [
$(ps -eo pid,pcpu,pmem,comm --no-headers | sort -k3 -nr | head -n 10 | while read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  cpu=$(echo "$line" | awk '{print $2}')
  mem=$(echo "$line" | awk '{print $3}')
  comm=$(echo "$line" | awk '{print $4}')
  
  echo "    {
      \"pid\": $pid,
      \"command\": \"$comm\",
      \"cpu_percent\": \"$cpu\",
      \"mem_percent\": \"$mem\"
    },"
done | sed '$ s/,$//')
  ],
  "services": [
$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | tail -n +2 | head -n 20 | while read -r line; do
  if [[ -n "$line" ]]; then
    service=$(echo "$line" | awk '{print $1}')
    load_state=$(echo "$line" | awk '{print $2}')
    active_state=$(echo "$line" | awk '{print $3}')
    sub_state=$(echo "$line" | awk '{print $4}')
    description=$(echo "$line" | cut -d' ' -f5- | sed 's/"/\\"/g')
    
    if [[ "$service" != "0 loaded units listed." ]]; then
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
  ]
}
EOF
)

    echo "$process_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the process information
collect_process_info "$REPORT_FILE"

echo "Process information report generated: $REPORT_FILE"