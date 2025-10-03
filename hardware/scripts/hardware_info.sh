#!/bin/bash

# Hardware Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/hardware_info_$TIMESTAMP.json"

# Function to collect hardware information
collect_hardware_info() {
    local output_file=$1
    
    # Collect hardware information
    local hardware_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "cpu": {
    "model": "$(lscpu | grep "Model name" | cut -d: -f2 | sed 's/^[[:space:]]*//' | sed 's/"/\\"/g')",
    "cores": $(nproc),
    "threads": $(lscpu | grep "CPU(s):" | head -n1 | cut -d: -f2 | sed 's/^[[:space:]]*//'),
    "architecture": "$(uname -m)",
    "vendor": "$(lscpu | grep "Vendor ID" | cut -d: -f2 | sed 's/^[[:space:]]*//')"
  },
  "memory": {
    "total_bytes": $(free -b | awk 'NR==2 {print $2}'),
    "total_gb": $(free -b | awk 'NR==2 {printf "%.2f", $2/1024/1024/1024}'),
    "slots": $(dmidecode -t memory 2>/dev/null | grep -c "Memory Device" || echo 0),
    "form_factor": "$(dmidecode -t memory 2>/dev/null | grep "Form Factor" | head -n1 | cut -d: -f2 | sed 's/^[[:space:]]*//' || echo 'Unknown')",
    "type": "$(dmidecode -t memory 2>/dev/null | grep -m1 "Type:" | cut -d: -f2 | sed 's/^[[:space:]]*//' || echo 'Unknown')"
  },
  "storage": [
$(lsblk -J 2>/dev/null | jq -r '.blockdevices[] | 
  select(.type == "disk") |
  {
    name: .name,
    type: .rota | if . == true then "HDD" else "SSD" end,
    size: .size,
    serial: (.serial // "Unknown"),
    vendor: (.vendor // "Unknown"),
    model: (.model // "Unknown")
  }' 2>/dev/null | sed 's/$/,/' | sed '$ s/,$//' || echo '{}')
  ],
  "network": [
$(lspci 2>/dev/null | grep -i ethernet | while read -r line; do
  id=$(echo "$line" | cut -d' ' -f1)
  description=$(echo "$line" | cut -d' ' -f3- | sed 's/"/\\"/g')
  echo "    {
      \"id\": \"$id\",
      \"description\": \"$description\",
      \"type\": \"ethernet\"
    },"
done | sed '$ s/,$//')
  ],
  "temperature": [
$(if command -v sensors > /dev/null 2>&1; then
  sensors | grep -E "^(coretemp|k10temp|it86" | while read -r line; do
    if [[ "$line" =~ ^[a-zA-Z].* ]]; then
      sensor=$(echo "$line" | cut -d' ' -f1)
    elif [[ "$line" =~ ^[[:space:]]* ]]; then
      temp=$(echo "$line" | grep -o "[0-9.]*°C" | head -n1)
      if [[ -n "$temp" ]]; then
        echo "    {
      \"sensor\": \"$sensor\",
      \"temperature\": \"$temp\"
    },"
      fi
    fi
  done | sed '$ s/,$//'
else
  echo "    {
      \"sensor\": \"unknown\",
      \"status\": \"sensors command not available\"
    }"
fi)
  ],
  "motherboard": {
    "product": "$(dmidecode -s system-product-name 2>/dev/null || echo 'Unknown')",
    "vendor": "$(dmidecode -s system-manufacturer 2>/dev/null || echo 'Unknown')",
    "version": "$(dmidecode -s system-version 2>/dev/null || echo 'Unknown')",
    "serial": "$(dmidecode -s system-serial-number 2>/dev/null || echo 'Unknown')"
  },
  "bios": {
    "vendor": "$(dmidecode -s bios-vendor 2>/dev/null || echo 'Unknown')",
    "version": "$(dmidecode -s bios-version 2>/dev/null || echo 'Unknown')",
    "date": "$(dmidecode -s bios-release-date 2>/dev/null || echo 'Unknown')"
  }
}
EOF
)

    echo "$hardware_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the hardware information
collect_hardware_info "$REPORT_FILE"

echo "Hardware information report generated: $REPORT_FILE"