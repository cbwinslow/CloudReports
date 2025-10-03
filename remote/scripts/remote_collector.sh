#!/bin/bash

# Remote Collection Management Script
source /home/cbwinslow/reports/config_manager.sh

# Function to collect data from a remote server
collect_from_remote() {
    local server_config=$1
    local server_name=$(echo "$server_config" | jq -r '.name')
    local server_host=$(echo "$server_config" | jq -r '.host')
    local server_port=$(echo "$server_config" | jq -r '.port // "22"')
    local server_user=$(echo "$server_config" | jq -r '.user')
    local ssh_key=$(echo "$server_config" | jq -r '.ssh_key // ""')
    
    # Create directory for remote reports
    local remote_output_dir="/home/cbwinslow/reports/data/remote/$server_name"
    mkdir -p "$remote_output_dir"
    
    # Set SSH options
    local ssh_opts="-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    if [[ -n "$ssh_key" && -f "$ssh_key" ]]; then
        ssh_opts="$ssh_opts -i $ssh_key"
    fi
    
    echo "Collecting reports from $server_name ($server_host)..."
    
    # Run remote commands to collect reports
    # The reports will be stored in the remote-specific directory
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    # Collect system info from remote server
    if ssh $ssh_opts "$server_user@$server_host" -p "$server_port" "command -v uname > /dev/null 2>&1"; then
        ssh $ssh_opts "$server_user@$server_host" -p "$server_port" "uname -a; uptime; df -h; free -h" > "$remote_output_dir/system_$timestamp.txt" 2>/dev/null
        echo "  System info collected from $server_name"
    else
        echo "  Could not connect to $server_name"
        return 1
    fi
    
    # Copy the reporting scripts to the remote server and execute them
    local temp_dir=$(mktemp -d)
    
    # Copy all report scripts to the remote server
    for report_dir in /home/cbwinslow/reports/*/; do
        if [[ -d "$report_dir/scripts" ]]; then
            local report_type=$(basename "$report_dir")
            if is_report_enabled "$report_type"; then
                # Create remote directory
                ssh $ssh_opts "$server_user@$server_host" -p "$server_port" "mkdir -p /tmp/reports_$timestamp/$report_type" 2>/dev/null
                
                # Copy scripts to remote server
                for script in "$report_dir/scripts/"*.sh; do
                    if [[ -f "$script" ]]; then
                        scp $ssh_opts "$script" "$server_user@$server_host:/tmp/reports_$timestamp/$report_type/" 2>/dev/null
                        # Execute the script on the remote server
                        ssh $ssh_opts "$server_user@$server_host" -p "$server_port" "chmod +x /tmp/reports_$timestamp/$report_type/$(basename "$script"); /tmp/reports_$timestamp/$report_type/$(basename "$script")" 2>/dev/null
                    fi
                done
            fi
        fi
    done
    
    # Copy the collected reports back to the local system
    ssh $ssh_opts "$server_user@$server_host" -p "$server_port" "find /tmp/reports_$timestamp -name '*.json' -type f" | while read -r remote_file; do
        local filename=$(basename "$remote_file")
        local report_type=$(echo "$remote_file" | cut -d'/' -f4)
        mkdir -p "$remote_output_dir/$report_type"
        scp $ssh_opts "$server_user@$server_host:$remote_file" "$remote_output_dir/$report_type/$filename" 2>/dev/null
    done
    
    # Clean up remote temporary directory
    ssh $ssh_opts "$server_user@$server_host" -p "$server_port" "rm -rf /tmp/reports_$timestamp" 2>/dev/null
    
    echo "  Reports from $server_name collected successfully"
}

# Function to run remote reports
run_remote_reports() {
    local config_file="/home/cbwinslow/reports/config.json"
    
    # Check if remote collection is enabled
    if [[ "$(get_config "remote_servers" "enabled")" == "true" ]]; then
        # Loop through all configured servers
        local servers=$(cat "$config_file" | jq -r '."remote_servers".servers[] | @base64')
        
        for server_data in $servers; do
            server_config=$(echo "$server_data" | base64 --decode)
            collect_from_remote "$server_config"
        done
    else
        echo "Remote collection is disabled in configuration"
    fi
}

# Run remote collection if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_remote_reports
fi