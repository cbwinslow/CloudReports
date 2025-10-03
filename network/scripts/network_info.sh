#!/bin/bash

# Network Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/network_info_$TIMESTAMP.json"

# Function to collect network information
collect_network_info() {
    local output_file=$1
    
    # Collect network information
    local network_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "interfaces": [
$(ip -j addr show | jq -c '.[] | {
  name: .ifname,
  state: .operstate,
  mtu: .mtu,
  ip_addresses: [.addr_info[] | {family: .family, local: .local, prefixlen: .prefixlen}] | if length > 0 then . else [] end
}' | sed 's/$/,/' | sed '$ s/,$//')
  ],
  "bandwidth": [
$(cat /proc/net/dev | grep -v -E "^(Inter|face)" | while read line; do
  interface=$(echo $line | awk '{print $1}' | sed 's/://')
  if [[ "$interface" != "lo" ]]; then
    rx_bytes=$(echo $line | awk '{print $2}')
    tx_bytes=$(echo $line | awk '{print $10}')
    echo "    {
      \"interface\": \"$interface\",
      \"rx_bytes\": $rx_bytes,
      \"tx_bytes\": $tx_bytes
    },"
  fi
done | sed '$ s/,$//')
  ],
  "connections": {
    "tcp": $(ss -t state established | grep -c ESTAB || echo 0),
    "udp": $(ss -u state established | wc -l),
    "listening": $(ss -l | grep -c LISTEN || echo 0)
  },
  "routes": [
$(ip -j route show | jq -c '.[] | {
  destination: .dst,
  gateway: .gateway // "local",
  interface: .dev,
  protocol: .protocol // "kernel"
}' | sed 's/$/,/' | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$network_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the network information
collect_network_info "$REPORT_FILE"

echo "Network information report generated: $REPORT_FILE"