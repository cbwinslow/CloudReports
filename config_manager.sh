#!/bin/bash

# Configuration management for the reporting system
CONFIG_FILE="/home/cbwinslow/reports/config.json"

# Function to get a configuration value
get_config() {
    local section=$1
    local key=$2
    
    # Using jq if available, otherwise basic parsing
    if command -v jq > /dev/null 2>&1; then
        cat "$CONFIG_FILE" | jq -r ".$section.$key" 2>/dev/null
    else
        # Basic parsing if jq is not available
        grep -o "\"$key\": *[^,}]*" "$CONFIG_FILE" | cut -d: -f2 | sed 's/^[[:space:]]*"\|"[[:space:]]*$//g'
    fi
}

# Function to check if a report type is enabled
is_report_enabled() {
    local report_type=$1
    local status=$(get_config "report_types" "$report_type.enabled")
    
    if [[ "$status" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# Function to get script list for a report type
get_scripts_for_report() {
    local report_type=$1
    local scripts=$(get_config "report_types" "$report_type.scripts")
    
    # Remove brackets and quotes if using basic parsing
    if [[ "$scripts" == "["* ]]; then
        scripts=$(echo "$scripts" | sed 's/\[//' | sed 's/\]//' | sed 's/"//g' | sed 's/,/ /g')
    fi
    
    echo "$scripts"
}

# Function to get schedule for a report type
get_schedule_for_report() {
    local report_type=$1
    get_config "report_types" "$report_type.schedule"
}

# Function to get all enabled report types
get_enabled_reports() {
    if command -v jq > /dev/null 2>&1; then
        cat "$CONFIG_FILE" | jq -r '."report_types" | to_entries[] | select(.value.enabled == true) | .key'
    else
        # Fallback method if jq is not available
        echo "system network filesystem error log container security process hardware backup monitoring"
    fi
}

# Create output directory if it doesn't exist
OUTPUT_DIR=$(get_config "general" "output_dir")
mkdir -p "$OUTPUT_DIR"