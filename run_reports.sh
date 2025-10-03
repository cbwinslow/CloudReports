#!/bin/bash

# Main Reporting System Script
source /home/cbwinslow/reports/config_manager.sh

# Main function to run all enabled reports
run_reports() {
    local report_types=()
    
    # Get all enabled report types
    while IFS= read -r report_type; do
        if is_report_enabled "$report_type"; then
            report_types+=("$report_type")
        fi
    done < <(get_enabled_reports)
    
    echo "Starting report generation for $(date -Iseconds)"
    echo "Enabled reports: ${report_types[*]}"
    
    # Execute each enabled report
    for report_type in "${report_types[@]}"; do
        echo "Running $report_type reports..."
        
        # Get the schedule for this report type
        schedule=$(get_schedule_for_report "$report_type")
        
        # Get all scripts for this report type
        scripts=$(get_scripts_for_report "$report_type")
        
        for script in $scripts; do
            script_path="/home/cbwinslow/reports/$report_type/scripts/$script"
            
            if [[ -f "$script_path" ]]; then
                echo "  Executing $script_path"
                chmod +x "$script_path"
                "$script_path"
            else
                echo "  Warning: Script $script_path not found"
            fi
        done
    done
    
    echo "Report generation completed at $(date -Iseconds)"
}

# Function to run remote reports
run_remote_reports() {
    local remote_script="/home/cbwinslow/reports/remote/scripts/remote_collector.sh"
    
    if [[ -f "$remote_script" ]]; then
        echo "Running remote collection..."
        chmod +x "$remote_script"
        "$remote_script"
    else
        echo "Remote collection script not found: $remote_script"
    fi
}

# Function to run reports for specific type
run_specific_report() {
    local report_type=$1
    
    if is_report_enabled "$report_type"; then
        echo "Running $report_type reports..."
        
        # Get all scripts for this report type
        scripts=$(get_scripts_for_report "$report_type")
        
        for script in $scripts; do
            script_path="/home/cbwinslow/reports/$report_type/scripts/$script"
            
            if [[ -f "$script_path" ]]; then
                echo "  Executing $script_path"
                chmod +x "$script_path"
                "$script_path"
            else
                echo "  Warning: Script $script_path not found"
            fi
        done
    else
        echo "Report type $report_type is not enabled in configuration"
    fi
}

# Function to clean old reports
clean_reports() {
    local retention_days=$(get_config "general" "retention_days")
    local output_dir=$(get_config "general" "output_dir")
    
    echo "Cleaning reports older than $retention_days days..."
    find "$output_dir" -type f -name "*.json" -mtime +$retention_days -delete
    echo "Clean up completed"
}

# Parse command line arguments
case "${1:-full}" in
    "full")
        run_reports
        ;;
    "system")
        run_specific_report "system"
        ;;
    "network")
        run_specific_report "network"
        ;;
    "filesystem")
        run_specific_report "filesystem"
        ;;
    "error")
        run_specific_report "error"
        ;;
    "log")
        run_specific_report "log"
        ;;
    "container")
        run_specific_report "container"
        ;;
    "security")
        run_specific_report "security"
        ;;
    "process")
        run_specific_report "process"
        ;;
    "hardware")
        run_specific_report "hardware"
        ;;
    "backup")
        run_specific_report "backup"
        ;;
    "monitoring")
        run_specific_report "monitoring"
        ;;
    "remote")
        run_remote_reports
        ;;
    "clean")
        clean_reports
        ;;
    "list")
        echo "Available report types:"
        get_enabled_reports | while read -r report_type; do
            if is_report_enabled "$report_type"; then
                echo "  - $report_type (enabled)"
            else
                echo "  - $report_type (disabled)"
            fi
        done
        ;;
    *)
        echo "Usage: $0 [full|system|network|filesystem|error|log|container|security|process|hardware|backup|monitoring|remote|clean|list]"
        echo "  full      - Run all enabled reports (default)"
        echo "  <type>    - Run specific report type"
        echo "  remote    - Run remote collection"
        echo "  clean     - Clean old reports based on retention policy"
        echo "  list      - List all available report types"
        exit 1
        ;;
esac