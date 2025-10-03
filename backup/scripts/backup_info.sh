#!/bin/bash

# Backup Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/backup_info_$TIMESTAMP.json"

# Function to collect backup information
collect_backup_info() {
    local output_file=$1
    
    # Collect backup information
    local backup_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "rsync_jobs": [
$(find /etc/cron.d/ -type f -exec grep -l "rsync" {} \; 2>/dev/null | while read -r cron_file; do
  while IFS= read -r line; do
    if [[ "$line" =~ rsync ]]; then
      cron_schedule=$(echo "$line" | awk '{print $1" "$2" "$3" "$4" "$5}')
      command=$(echo "$line" | sed 's/.*rsync/rsync/')
      echo "    {
      \"cron_file\": \"$cron_file\",
      \"schedule\": \"$cron_schedule\",
      \"command\": \"$command\"
    },"
    fi
  done < "$cron_file"
done | sed '$ s/,$//')
  ],
  "backup_directories": [
$(df -h | grep -E "(/backup|/var/backup|/home/backup|/opt/backup)" | while read -r line; do
  usage=$(echo "$line" | awk '{print $5}')
  mount_point=$(echo "$line" | awk '{print $6}')
  size=$(echo "$line" | awk '{print $2}')
  used=$(echo "$line" | awk '{print $3}')
  available=$(echo "$line" | awk '{print $4}')
  
  echo "    {
      \"mount_point\": \"$mount_point\",
      \"size\": \"$size\",
      \"used\": \"$used\",
      \"available\": \"$available\",
      \"usage_percent\": \"$usage\"
    },"
done | sed '$ s/,$//')
  ],
  "recent_backup_logs": [
$(find /var/log -name "*backup*" -o -name "*rsync*" 2>/dev/null | head -n 5 | while read -r log_file; do
  size=$(du -h "$log_file" 2>/dev/null | cut -f1)
  modified=$(stat -c %y "$log_file" 2>/dev/null)
  
  echo "    {
      \"file\": \"$log_file\",
      \"size\": \"$size\",
      \"modified\": \"$modified\"
    },"
done | sed '$ s/,$//')
  ],
  "backup_services": [
$(systemctl list-units --type=service --no-pager 2>/dev/null | grep -i backup | while read -r line; do
  service=$(echo "$line" | awk '{print $1}')
  load_state=$(echo "$line" | awk '{print $2}')
  active_state=$(echo "$line" | awk '{print $3}')
  sub_state=$(echo "$line" | awk '{print $4}')
  
  echo "    {
      \"service\": \"$service\",
      \"load_state\": \"$load_state\",
      \"active_state\": \"$active_state\",
      \"sub_state\": \"$sub_state\"
    },"
done | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$backup_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the backup information
collect_backup_info "$REPORT_FILE"

echo "Backup information report generated: $REPORT_FILE"