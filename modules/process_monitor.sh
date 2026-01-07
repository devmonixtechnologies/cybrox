#!/bin/bash

# PROCESS MONITOR MODULE
# Advanced process monitoring and suspicious activity detection

# Process monitoring state files
readonly PROCESS_STATE="${TEMP_DIR}/process_state.tmp"
readonly PROCESS_LOG="${LOGS_DIR}/process_monitor.log"
readonly SUSPICIOUS_LOG="${LOGS_DIR}/suspicious_processes.log"
readonly PROCESS_DB="${TEMP_DIR}/process.db"

# Initialize process monitoring
init_process_monitor() {
    log_message "INFO" "Initializing process monitoring module"
    
    # Create state files
    touch "$PROCESS_STATE" "$PROCESS_LOG" "$SUSPICIOUS_LOG" "$PROCESS_DB"
    
    # Initialize tracking variables
    declare -A process_counts
    declare -A suspicious_processes
    declare -A process_parents
    declare -A last_seen
    
    # Save initial state
    declare -p process_counts suspicious_processes process_parents last_seen > "$PROCESS_STATE"
}

# Monitor running processes
monitor_processes() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local current_processes=$(ps aux --no-headers)
    
    # Count processes by name
    local process_count_file="${TEMP_DIR}/process_counts.tmp"
    echo "$current_processes" | awk '{print $11}' | sort | uniq -c | sort -nr > "$process_count_file"
    
    # Check for unusual process counts
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local count=$(echo "$line" | awk '{print $1}')
            local process=$(echo "$line" | awk '{print $2}')
            
            # Alert on high process counts
            if [[ $count -gt 50 ]]; then
                send_alert "MEDIUM" "High process count: $count instances of $process" "PROCESS_MONITOR"
            fi
            
            # Log process count
            echo "[$timestamp] PROCESS_COUNT: $process - $count instances" >> "$PROCESS_LOG"
        fi
    done < "$process_count_file"
    
    rm -f "$process_count_file"
}

# Detect suspicious processes
detect_suspicious_processes() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local current_processes=$(ps aux --no-headers)
    
    IFS=',' read -ra suspicious_array <<< "$SUSPICIOUS_PROCESSES"
    
    for suspicious_proc in "${suspicious_array[@]}"; do
        local found_processes=$(echo "$current_processes" | grep -i "$suspicious_proc" | grep -v grep)
        
        if [[ -n "$found_processes" ]]; then
            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    local pid=$(echo "$line" | awk '{print $2}')
                    local user=$(echo "$line" | awk '{print $1}')
                    local cmd=$(echo "$line" | awk '{print $11}')
                    
                    send_alert "HIGH" "Suspicious process detected: $cmd (PID: $pid, User: $user)" "SUSPICIOUS_PROCESS"
                    echo "[$timestamp] SUSPICIOUS: $cmd (PID: $pid, User: $user)" >> "$SUSPICIOUS_LOG"
                    
                    # Kill suspicious process if configured
                    if [[ "$KILL_SUSPICIOUS_PROCESSES" == "true" ]]; then
                        kill_process "$pid" "$cmd"
                    fi
                fi
            done <<< "$found_processes"
        fi
    done
}

# Kill suspicious process
kill_process() {
    local pid="$1"
    local cmd="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Try graceful termination first
    if kill -TERM "$pid" 2>/dev/null; then
        sleep 2
        
        # Check if process still exists
        if kill -0 "$pid" 2>/dev/null; then
            # Force kill if still running
            kill -KILL "$pid" 2>/dev/null || true
        fi
        
        log_message "INFO" "Killed suspicious process: $cmd (PID: $pid)"
        send_alert "MEDIUM" "Killed suspicious process: $cmd (PID: $pid)" "PROCESS_KILLER"
    else
        log_message "WARN" "Failed to kill process: $cmd (PID: $pid)"
    fi
}

# Monitor process resource usage
monitor_resource_usage() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local resource_file="${TEMP_DIR}/process_resources.tmp"
    
    # Get process resource usage
    ps aux --no-headers | awk 'NR>1 {print $2","$3","$4","$11}' | sort -t',' -k2 -nr > "$resource_file"
    
    while IFS=',' read -r pid cpu mem cmd; do
        # Check for high CPU usage
        if (( $(echo "$cpu > 80" | bc -l) )); then
            send_alert "MEDIUM" "High CPU usage: $cmd (${cpu}%) - PID: $pid" "RESOURCE_MONITOR"
        fi
        
        # Check for high memory usage
        if (( $(echo "$mem > 80" | bc -l) )); then
            send_alert "MEDIUM" "High memory usage: $cmd (${mem}%) - PID: $pid" "RESOURCE_MONITOR"
        fi
        
        # Log resource usage
        echo "[$timestamp] RESOURCE: $cmd (PID: $pid) - CPU: ${cpu}%, MEM: ${mem}%" >> "$PROCESS_LOG"
    done < "$resource_file"
    
    rm -f "$resource_file"
}

# Monitor network connections by process
monitor_process_network() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if command -v netstat &> /dev/null; then
        local network_processes=$(netstat -tulpn 2>/dev/null | grep -E 'LISTEN|ESTABLISHED')
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local protocol=$(echo "$line" | awk '{print $1}')
                local address=$(echo "$line" | awk '{print $4}')
                local pid=$(echo "$line" | awk '{print $7}' | cut -d'/' -f1)
                local process=$(echo "$line" | awk '{print $7}' | cut -d'/' -f2)
                
                # Check for suspicious network processes
                if echo "$process" | grep -qiE "nc|netcat|ncat|socat"; then
                    send_alert "HIGH" "Suspicious network process: $process (PID: $pid) listening on $address" "NETWORK_PROCESS"
                fi
                
                # Log network process
                echo "[$timestamp] NETWORK_PROCESS: $process (PID: $pid) - $protocol $address" >> "$PROCESS_LOG"
            fi
        done <<< "$network_processes"
    fi
}

# Detect process injection attacks
detect_process_injection() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Check for processes with unusual parent-child relationships
    local process_tree=$(ps -e -o pid,ppid,comm --no-headers)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local pid=$(echo "$line" | awk '{print $1}')
            local ppid=$(echo "$line" | awk '{print $2}')
            local comm=$(echo "$line" | awk '{print $3}')
            
            # Check for suspicious parent processes
            if [[ "$ppid" != "1" ]] && [[ "$ppid" != "2" ]]; then
                local parent_comm=$(ps -p "$ppid" -o comm --no-headers 2>/dev/null || echo "unknown")
                
                # Check for unusual parent-child relationships
                case "$parent_comm" in
                    "apache2"|"httpd"|"nginx")
                        if [[ "$comm" =~ (bash|sh|zsh|python|perl) ]]; then
                            send_alert "HIGH" "Suspicious parent-child: $parent_comm -> $comm (PID: $pid)" "PROCESS_INJECTION"
                        fi
                        ;;
                    "sshd")
                        if [[ "$comm" =~ (nc|netcat|tcpdump|nmap) ]]; then
                            send_alert "HIGH" "Suspicious SSH session: $comm (PID: $pid)" "PROCESS_INJECTION"
                        fi
                        ;;
                esac
            fi
        fi
    done <<< "$process_tree"
}

# Monitor user processes
monitor_user_processes() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Get list of users with processes
    local users=$(ps aux --no-headers | awk '{print $1}' | sort | uniq)
    
    while IFS= read -r user; do
        if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
            local user_processes=$(ps -u "$user" --no-headers | wc -l)
            
            # Alert on excessive user processes
            if [[ $user_processes -gt 100 ]]; then
                send_alert "MEDIUM" "Excessive processes for user $user: $user_processes" "USER_PROCESS_MONITOR"
            fi
            
            # Check for privileged user processes
            local privileged_processes=$(ps -u "$user" --no-headers | grep -E 'sudo|su|passwd|chmod|chown')
            
            if [[ -n "$privileged_processes" ]]; then
                while IFS= read -r line; do
                    if [[ -n "$line" ]]; then
                        local cmd=$(echo "$line" | awk '{print $11}')
                        send_alert "HIGH" "Privileged command by user $user: $cmd" "USER_PROCESS_MONITOR"
                    fi
                done <<< "$privileged_processes"
            fi
        fi
    done <<< "$users"
}

# Detect rootkits and malware
detect_malware() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Check for hidden processes
    local all_processes=$(ps -e -o pid --no-headers | sort -n)
    local proc_processes=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
    
    # Find processes in /proc but not in ps output (potential rootkits)
    local hidden_processes=$(comm -23 <(echo "$proc_processes") <(echo "$all_processes"))
    
    while IFS= read -r pid; do
        if [[ -n "$pid" ]]; then
            local cmd=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
            send_alert "CRITICAL" "Hidden process detected: $cmd (PID: $pid)" "MALWARE_DETECTION"
        fi
    done <<< "$hidden_processes"
    
    # Check for suspicious process names
    local suspicious_names="backdoor|rootkit|trojan|malware|virus|bot|agent"
    local suspicious_procs=$(ps aux --no-headers | grep -iE "$suspicious_names" | grep -v grep)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local pid=$(echo "$line" | awk '{print $2}')
            local cmd=$(echo "$line" | awk '{print $11}')
            send_alert "CRITICAL" "Malware process detected: $cmd (PID: $pid)" "MALWARE_DETECTION"
            
            # Kill malware process
            kill_process "$pid" "$cmd"
        fi
    done <<< "$suspicious_procs"
}

# Monitor system calls (if strace available)
monitor_system_calls() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if command -v strace &> /dev/null; then
        # Monitor suspicious system calls from common processes
        local target_processes=$(ps aux --no-headers | grep -E "(bash|sh|python|perl)" | awk '{print $2}' | head -n 5)
        
        while IFS= read -r pid; do
            if [[ -n "$pid" ]]; then
                # Monitor for suspicious syscalls (timeout to prevent hanging)
                timeout 3 strace -p "$pid" -e trace=network,process,file 2>&1 | \
                grep -E "(connect|bind|listen|execve|fork|clone)" | \
                while IFS= read -r syscall; do
                    if [[ -n "$syscall" ]]; then
                        send_alert "LOW" "Suspicious syscall: PID $pid - $syscall" "SYSCALL_MONITOR"
                    fi
                done &
            fi
        done <<< "$target_processes"
    fi
}

# Main process monitoring function
process_monitor_main() {
    if [[ "$PROCESS_MONITOR_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Initialize if not done
    if [[ ! -f "$PROCESS_STATE" ]]; then
        init_process_monitor
    fi
    
    # Run monitoring functions
    monitor_processes
    detect_suspicious_processes
    monitor_resource_usage
    monitor_process_network
    detect_process_injection
    monitor_user_processes
    detect_malware
    monitor_system_calls
}

# Export functions for main script
export -f init_process_monitor monitor_processes detect_suspicious_processes kill_process
export -f monitor_resource_usage monitor_process_network detect_process_injection
export -f monitor_user_processes detect_malware monitor_system_calls process_monitor_main
