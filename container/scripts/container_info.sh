#!/bin/bash

# Container Information Report Script
source /home/cbwinslow/reports/config_manager.sh

OUTPUT_DIR=$(get_config "general" "output_dir")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="$OUTPUT_DIR/container_info_$TIMESTAMP.json"

# Function to collect container information
collect_container_info() {
    local output_file=$1
    
    # Check if Docker is available
    if ! command -v docker > /dev/null 2>&1; then
        echo "{}" > "$output_file"
        echo "Docker not found, generating empty report: $REPORT_FILE"
        return
    fi
    
    # Collect container information
    local container_info=$(cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "docker_info": {
$(docker info --format='{{json .}}' 2>/dev/null | jq -r '
    {
      "server_version": .ServerVersion,
      "storage_driver": .Driver,
      "logging_driver": .LoggingDriver,
      "cgroup_driver": .CgroupDriver,
      "plugins": {
        "volume": (.Plugins.Volume | join(", ")),
        "network": (.Plugins.Network | join(", ")),
        "authorization": (.Plugins.Authorization | join(", ")),
        "log": (.Plugins.Log | join(", "))
      },
      "nfd": .NFd,
      "n goroutines": .NGoroutines,
      "system_time": .SystemTime,
      "kernel_version": .KernelVersion,
      "os": .OperatingSystem,
      "architecture": .Architecture,
      "cpus": .NCPU,
      "memory_limit": .MemoryLimit,
      "swap_limit": .SwapLimit,
      "kernel_memory": .KernelMemory,
      "oom_kill_disable": .OomKillDisable,
      "cpu_cfs_period": .CPU_cfs_period,
      "cpu_cfs_quota": .CPU_cfs_quota,
      "cpu_shares": .CPUShares,
      "cpu_set": .CPUSet,
      "ipv4_forwarding": .IPv4Forwarding,
      "bridge_nf_iptables": .BridgeNfIptables,
      "bridge_nf_ip6tables": .BridgeNfIp6tables,
      "debug": .Debug,
      "file_descriptors": .NFd,
      "goroutines": .NGoroutines,
      "registry_config": .IndexServerAddress
    }' 2>/dev/null || echo '
    "status": "error",
    "message": "Could not retrieve Docker info"
')
  },
  "containers": [
$(docker ps -a --format='{{json .}}' 2>/dev/null | while read -r line; do
  if [[ -n "$line" ]]; then
    container_id=$(echo "$line" | jq -r '.ID')
    names=$(echo "$line" | jq -r '.Names')
    image=$(echo "$line" | jq -r '.Image')
    command=$(echo "$line" | jq -r '.Command' | sed 's/"/\\"/g')
    created=$(echo "$line" | jq -r '.CreatedAt')
    status=$(echo "$line" | jq -r '.Status')
    ports=$(echo "$line" | jq -r '.Ports')
    labels=$(echo "$line" | jq -r '.Labels')
    
    echo "    {
      \"id\": \"$container_id\",
      \"names\": \"$names\",
      \"image\": \"$image\",
      \"command\": \"$command\",
      \"created\": \"$created\",
      \"status\": \"$status\",
      \"ports\": \"$ports\",
      \"labels\": \"$labels\"
    },"
  fi
done | sed '$ s/,$//')
  ],
  "images": [
$(docker images --format='{{json .}}' 2>/dev/null | while read -r line; do
  if [[ -n "$line" ]]; then
    repository=$(echo "$line" | jq -r '.Repository')
    tag=$(echo "$line" | jq -r '.Tag')
    image_id=$(echo "$line" | jq -r '.ID')
    created_since=$(echo "$line" | jq -r '.CreatedAt')
    size=$(echo "$line" | jq -r '.Size')
    
    echo "    {
      \"repository\": \"$repository\",
      \"tag\": \"$tag\",
      \"id\": \"$image_id\",
      \"created_since\": \"$created_since\",
      \"size\": \"$size\"
    },"
  fi
done | sed '$ s/,$//')
  ],
  "volumes": [
$(docker volume ls --format='{{json .}}' 2>/dev/null | while read -r line; do
  if [[ -n "$line" ]]; then
    driver=$(echo "$line" | jq -r '.Driver')
    volume_name=$(echo "$line" | jq -r '.Name')
    
    echo "    {
      \"driver\": \"$driver\",
      \"name\": \"$volume_name\"
    },"
  fi
done | sed '$ s/,$//')
  ],
  "networks": [
$(docker network ls --format='{{json .}}' 2>/dev/null | while read -r line; do
  if [[ -n "$line" ]]; then
    network_id=$(echo "$line" | jq -r '.ID')
    name=$(echo "$line" | jq -r '.Name')
    driver=$(echo "$line" | jq -r '.Driver')
    scope=$(echo "$line" | jq -r '.Scope')
    
    echo "    {
      \"id\": \"$network_id\",
      \"name\": \"$name\",
      \"driver\": \"$driver\",
      \"scope\": \"$scope\"
    },"
  fi
done | sed '$ s/,$//')
  ]
}
EOF
)

    echo "$container_info" > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Collect the container information
collect_container_info "$REPORT_FILE"

echo "Container information report generated: $REPORT_FILE"