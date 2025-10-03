#!/bin/bash

# Filesystem Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/filesystem_info_$TIMESTAMP.json"

# Function to collect filesystem information
collect_filesystem_info() {
    local output_file=$1
    
    # Collect filesystem information
    local fs_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "mounts": [
$(df -B1 --output=source,target,fstype,size,used,avail,pcent | tail -n +2 | while read line; do
  source=$(echo $line | awk '{print $1}')
  target=$(echo $line | awk '{print $2}')
  fstype=$(echo $line | awk '{print $3}')
  size=$(echo $line | awk '{print $4}')
  used=$(echo $line | awk '{print $5}')
  avail=$(echo $line | awk '{print $6}')
  pcent=$(echo $line | awk '{print $7}' | sed 's/%//')
  
  echo "    {
      \"device\": \"$source\",
      \"mount_point\": \"$target\",
      \"type\": \"$fstype\",
      \"total_bytes\": $size,
      \"used_bytes\": $used,
      \"available_bytes\": $avail,
      \"usage_percent\": $pcent
    },"
done | sed '$ s/,$//')
  ],
  "inodes": [
$(df -i --output=source,itotal,iused,iavail,ipcent | tail -n +2 | while read line; do
  source=$(echo $line | awk '{print $1}')
  itotal=$(echo $line | awk '{print $2}')
  iused=$(echo $line | awk '{print $3}')
  iavail=$(echo $line | awk '{print $4}')
  ipcent=$(echo $line | awk '{print $5}' | sed 's/%//')
  
  echo "    {
      \"device\": \"$source\",
      \"total_inodes\": $itotal,
      \"used_inodes\": $iused,
      \"available_inodes\": $iavail,
      \"inode_usage_percent\": $ipcent
    },"
done | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$fs_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the filesystem information
collect_filesystem_info "$REPORT_FILE"

echo "Filesystem information report generated: $REPORT_FILE"