#!/bin/bash

# Security enhancement functions for the reporting system
source /home/cbwinslow/reports/config_manager.sh

# Function to set proper file permissions
set_secure_permissions() {
    local base_dir="/home/cbwinslow/reports"
    
    # Set directory permissions to 750 (owner: read/write/execute, group: read/execute)
    find "$base_dir" -type d -exec chmod 750 {} \;
    
    # Set configuration file permissions to 640 (owner: read/write, group: read)
    chmod 640 "$base_dir/config.json"
    chmod 640 "$base_dir/config_manager.sh"
    
    # Set script permissions to 750 (owner: read/write/execute, group: read/execute)
    find "$base_dir" -name "*.sh" -type f -exec chmod 750 {} \;
    
    # Set data output directory permissions
    local output_dir=$(get_config "general" "output_dir")
    mkdir -p "$output_dir"
    chmod 750 "$output_dir"
    
    echo "Security permissions have been set."
}

# Function to validate configuration for security issues
validate_configuration() {
    local config_file="/home/cbwinslow/reports/config.json"
    local issues=()
    
    # Check if config file contains potential password/plain text credentials
    if grep -q "password\|passwd\|pwd\|secret\|token" "$config_file"; then
        issues+=("Potential credentials found in config file")
    fi
    
    # Check for insecure SSH configurations
    if grep -q "PermitRootLogin yes\|PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        issues+=("SSH server configured with potential security issues")
    fi
    
    # Output validation results
    if [ ${#issues[@]} -gt 0 ]; then
        echo "Security Issues Found:"
        for issue in "${issues[@]}"; do
            echo "  - $issue"
        done
    else
        echo "No security issues found in configuration."
    fi
}

# Function to create credential file with proper permissions
create_secure_credential_file() {
    local credential_file="${1:-/home/cbwinslow/reports/credentials.json}"
    
    # Create credential file with secure permissions
    if [ ! -f "$credential_file" ]; then
        echo "{}" > "$credential_file"
        chmod 600 "$credential_file"  # Owner: read/write, Group/Other: none
        echo "Secure credential file created: $credential_file"
    fi
}

# Function to encrypt sensitive data
encrypt_data() {
    local data="$1"
    local key="${2:-$(hostname -f | md5sum | cut -d' ' -f1)}"
    
    # Use openssl to encrypt data if available
    if command -v openssl > /dev/null 2>&1; then
        echo -n "$data" | openssl enc -aes-256-cbc -a -salt -pass pass:"$key" 2>/dev/null
    else
        echo "Encryption not available. Install openssl for data encryption."
        echo "$data"
    fi
}

# Function to decrypt sensitive data
decrypt_data() {
    local data="$1"
    local key="${2:-$(hostname -f | md5sum | cut -d' ' -f1)}"
    
    # Use openssl to decrypt data if available
    if command -v openssl > /dev/null 2>&1; then
        echo -n "$data" | openssl enc -aes-256-cbc -a -d -pass pass:"$key" 2>/dev/null
    else
        echo "Decryption not available. Install openssl for data decryption."
        echo "$data"
    fi
}

# Run security setup if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Running security enhancements..."
    set_secure_permissions
    validate_configuration
    create_secure_credential_file
    echo "Security enhancements completed."
fi