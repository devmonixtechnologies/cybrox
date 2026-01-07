#!/bin/bash

# FILE INTEGRITY MONITOR MODULE
# Real-time file integrity monitoring and change detection

# File integrity state files
readonly INTEGRITY_DB="${TEMP_DIR}/integrity.db"
readonly INTEGRITY_STATE="${TEMP_DIR}/integrity_state.tmp"
readonly INTEGRITY_LOG="${LOGS_DIR}/file_integrity.log"
readonly CHANGES_LOG="${LOGS_DIR}/file_changes.log"

# Initialize file integrity monitoring
init_file_integrity() {
    log_message "INFO" "Initializing file integrity monitoring module"
    
    # Create state files
    touch "$INTEGRITY_STATE" "$INTEGRITY_LOG" "$CHANGES_LOG"
    
    # Create initial integrity database
    if [[ ! -f "$INTEGRITY_DB" ]]; then
        create_integrity_database
    fi
    
    # Initialize tracking variables
    declare -A file_hashes
    declare -A file_sizes
    declare -A file_permissions
    declare -A last_check
    
    # Save initial state
    declare -p file_hashes file_sizes file_permissions last_check > "$INTEGRITY_STATE"
}

# Create initial integrity database
create_integrity_database() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    log_message "INFO" "Creating initial file integrity database"
    
    # Process protected directories
    IFS=',' read -ra directories <<< "$PROTECTED_DIRECTORIES"
    
    for directory in "${directories[@]}"; do
        if [[ -d "$directory" ]]; then
            scan_directory "$directory" "$timestamp"
        fi
    done
    
    log_message "INFO" "File integrity database created: $INTEGRITY_DB"
}

# Scan directory for integrity database
scan_directory() {
    local directory="$1"
    local timestamp="$2"
    
    # Find all files in directory
    while IFS= read -r -d '' file; do
        # Skip ignored file types
        if should_ignore_file "$file"; then
            continue
        fi
        
        # Calculate file hash
        local hash=$(calculate_hash "$file")
        local size=$(stat -c%s "$file" 2>/dev/null || echo 0)
        local perms=$(stat -c%A "$file" 2>/dev/null || echo "unknown")
        
        # Add to database
        echo "$file|$hash|$size|$perms|$timestamp" >> "$INTEGRITY_DB"
        
    done < <(find "$directory" -type f -print0 2>/dev/null)
}

# Check if file should be ignored
should_ignore_file() {
    local file="$1"
    
    IFS=',' read -ra ignore_types <<< "$IGNORE_FILE_TYPES"
    
    for pattern in "${ignore_types[@]}"; do
        if [[ "$file" == $pattern ]]; then
            return 0
        fi
    done
    
    return 1
}

# Calculate file hash
calculate_hash() {
    local file="$1"
    
    if command -v sha256sum &> /dev/null; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v md5sum &> /dev/null; then
        md5sum "$file" | awk '{print $1}'
    else
        # Fallback to simple checksum
        cksum "$file" | awk '{print $1}'
    fi
}

# Monitor file integrity
monitor_file_integrity() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local temp_db="${TEMP_DIR}/integrity_check.tmp"
    
    # Create current database
    > "$temp_db"
    
    IFS=',' read -ra directories <<< "$PROTECTED_DIRECTORIES"
    
    for directory in "${directories[@]}"; do
        if [[ -d "$directory" ]]; then
            scan_directory "$directory" "$timestamp" >> "$temp_db"
        fi
    done
    
    # Compare with original database
    compare_integrity_databases "$INTEGRITY_DB" "$temp_db" "$timestamp"
    
    # Cleanup
    rm -f "$temp_db"
}

# Compare integrity databases
compare_integrity_databases() {
    local original_db="$1"
    local current_db="$2"
    local timestamp="$3"
    
    local changes_detected=0
    
    # Check for modified files
    while IFS='|' read -r file orig_hash orig_size orig_perms orig_time; do
        if [[ -f "$file" ]]; then
            local current_entry=$(grep "^$file|" "$current_db" | head -n 1)
            
            if [[ -n "$current_entry" ]]; then
                IFS='|' read -r curr_hash curr_size curr_perms curr_time <<< "$current_entry"
                
                # Check for changes
                if [[ "$orig_hash" != "$curr_hash" ]]; then
                    ((changes_detected++))
                    log_file_change "MODIFIED" "$file" "$orig_hash" "$curr_hash" "$timestamp"
                    send_alert "MEDIUM" "File modified: $file" "FILE_INTEGRITY"
                fi
                
                if [[ "$orig_perms" != "$curr_perms" ]]; then
                    ((changes_detected++))
                    log_file_change "PERMISSIONS" "$file" "$orig_perms" "$curr_perms" "$timestamp"
                    send_alert "MEDIUM" "File permissions changed: $file ($orig_perms -> $curr_perms)" "FILE_INTEGRITY"
                fi
            fi
        else
            # File deleted
            ((changes_detected++))
            log_file_change "DELETED" "$file" "$orig_hash" "N/A" "$timestamp"
            send_alert "HIGH" "File deleted: $file" "FILE_INTEGRITY"
        fi
    done < "$original_db"
    
    # Check for new files
    while IFS='|' read -r file curr_hash curr_size curr_perms curr_time; do
        if ! grep -q "^$file|" "$original_db"; then
            ((changes_detected++))
            log_file_change "CREATED" "$file" "N/A" "$curr_hash" "$timestamp"
            send_alert "LOW" "New file created: $file" "FILE_INTEGRITY"
        fi
    done < "$current_db"
    
    if [[ $changes_detected -gt 0 ]]; then
        log_message "INFO" "File integrity check completed: $changes_detected changes detected"
        
        # Update database if significant changes
        if [[ $changes_detected -lt 50 ]]; then
            cp "$current_db" "$INTEGRITY_DB"
            log_message "INFO" "Integrity database updated"
        else
            send_alert "HIGH" "Excessive file changes detected: $changes_detected" "FILE_INTEGRITY"
        fi
    fi
}

# Log file change
log_file_change() {
    local change_type="$1"
    local file="$2"
    local old_value="$3"
    local new_value="$4"
    local timestamp="$5"
    
    echo "[$timestamp] $change_type: $file ($old_value -> $new_value)" >> "$CHANGES_LOG"
}

# Monitor critical system files
monitor_critical_files() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/group"
        "/etc/sudoers"
        "/etc/hosts"
        "/etc/ssh/sshd_config"
        "/etc/crontab"
        "/boot/grub/grub.cfg"
        "/etc/fstab"
    )
    
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]]; then
            monitor_single_file "$file" "$timestamp"
        fi
    done
}

# Monitor single file
monitor_single_file() {
    local file="$1"
    local timestamp="$2"
    local state_file="${TEMP_DIR}/$(echo "$file" | tr '/' '_').state"
    
    local current_hash=$(calculate_hash "$file")
    local current_size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    local current_perms=$(stat -c%A "$file" 2>/dev/null || echo "unknown")
    
    if [[ -f "$state_file" ]]; then
        local last_state=$(cat "$state_file")
        IFS='|' read -r last_hash last_size last_perms <<< "$last_state"
        
        # Check for changes
        if [[ "$last_hash" != "$current_hash" ]]; then
            send_alert "CRITICAL" "Critical file modified: $file" "CRITICAL_FILE_MONITOR"
            log_file_change "CRITICAL_MODIFIED" "$file" "$last_hash" "$current_hash" "$timestamp"
        fi
        
        if [[ "$last_perms" != "$current_perms" ]]; then
            send_alert "HIGH" "Critical file permissions changed: $file ($last_perms -> $current_perms)" "CRITICAL_FILE_MONITOR"
        fi
    fi
    
    # Update state
    echo "$current_hash|$current_size|$current_perms" > "$state_file"
}

# Monitor executable files
monitor_executables() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local bin_dirs=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    
    for dir in "${bin_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                if [[ -x "$file" ]]; then
                    monitor_single_file "$file" "$timestamp"
                fi
            done < <(find "$dir" -maxdepth 1 -type f -executable -print0 2>/dev/null)
        fi
    done
}

# Detect suspicious file activity
detect_suspicious_activity() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Check for hidden files in unusual locations
    local hidden_files=$(find /tmp /var/tmp -name ".*" -type f 2>/dev/null)
    
    while IFS= read -r file; do
        if [[ -n "$file" ]]; then
            send_alert "MEDIUM" "Hidden file found in temp directory: $file" "SUSPICIOUS_FILE_ACTIVITY"
        fi
    done <<< "$hidden_files"
    
    # Check for files with suspicious names
    local suspicious_patterns=".*backdoor.*|.*rootkit.*|.*trojan.*|.*malware.*|.*virus.*"
    local suspicious_files=$(find / -type f -iname -regex "$suspicious_patterns" 2>/dev/null | head -n 10)
    
    while IFS= read -r file; do
        if [[ -n "$file" ]]; then
            send_alert "HIGH" "Suspicious file detected: $file" "SUSPICIOUS_FILE_ACTIVITY"
        fi
    done <<< "$suspicious_files"
    
    # Check for recently modified system files
    local recent_system_files=$(find /etc /bin /sbin -type f -mmin -60 2>/dev/null)
    
    while IFS= read -r file; do
        if [[ -n "$file" ]]; then
            send_alert "MEDIUM" "Recently modified system file: $file" "SUSPICIOUS_FILE_ACTIVITY"
        fi
    done <<< "$recent_system_files"
}

# Monitor file access patterns
monitor_access_patterns() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local access_log="${TEMP_DIR}/file_access.tmp"
    
    # Monitor file access using inotifywait if available
    if command -v inotifywait &> /dev/null; then
        timeout 10 inotifywait -r -e modify,attrib,move,create,delete --format '%w%f %e' /etc /bin /sbin 2>/dev/null > "$access_log" &
        
        wait
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local file=$(echo "$line" | awk '{print $1}')
                local event=$(echo "$line" | awk '{print $2}')
                
                send_alert "LOW" "File access detected: $file ($event)" "FILE_ACCESS_MONITOR"
            fi
        done < "$access_log"
        
        rm -f "$access_log"
    fi
}

# Main file integrity function
file_integrity_main() {
    if [[ "$FILE_INTEGRITY_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Initialize if not done
    if [[ ! -f "$INTEGRITY_STATE" ]]; then
        init_file_integrity
    fi
    
    # Run integrity checks
    monitor_file_integrity
    monitor_critical_files
    monitor_executables
    detect_suspicious_activity
    monitor_access_patterns
}

# Export functions for main script
export -f init_file_integrity create_integrity_database scan_directory should_ignore_file
export -f calculate_hash monitor_file_integrity compare_integrity_databases log_file_change
export -f monitor_critical_files monitor_single_file monitor_executables detect_suspicious_activity
export -f monitor_access_patterns file_integrity_main
