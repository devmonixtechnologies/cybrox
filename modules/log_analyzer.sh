#!/bin/bash

# LOG ANALYZER MODULE
# Advanced log analysis and anomaly detection system

# Log analysis state files
readonly LOG_STATE="${TEMP_DIR}/log_state.tmp"
readonly ANALYSIS_LOG="${LOGS_DIR}/log_analysis.log"
readonly PATTERN_DB="${CONFIG_DIR}/patterns.db"
readonly ANOMALY_LOG="${LOGS_DIR}/anomalies.log"

# Initialize log analyzer
init_log_analyzer() {
    log_message "INFO" "Initializing log analyzer module"
    
    # Create state files
    touch "$LOG_STATE" "$ANALYSIS_LOG" "$ANOMALY_LOG"
    
    # Create pattern database if not exists
    if [[ ! -f "$PATTERN_DB" ]]; then
        create_pattern_db
    fi
    
    # Initialize tracking variables
    declare -A failed_logins
    declare -A suspicious_ips
    declare -A pattern_counts
    declare -A last_analysis
    
    # Save initial state
    declare -p failed_logins suspicious_ips pattern_counts last_analysis > "$LOG_STATE"
}

# Create pattern database
create_pattern_db() {
    cat > "$PATTERN_DB" << 'EOF'
# Suspicious log patterns
FAILED_LOGIN|failed login|authentication failure|invalid user|login failed
PRIVILEGE_ESCALATION|sudo|su|passwd|chmod 777|chown root
SUSPICIOUS_COMMAND|nc|netcat|wget|curl|ssh|scp|rsync|ftp
SYSTEM_COMPROMISE|root|admin|administrator|privilege|escalation
NETWORK_ATTACK|port scan|ddos|flood|attack|intrusion|breach
MALWARE_ACTIVITY|virus|trojan|malware|backdoor|rootkit|botnet
FILE_ACCESS|unauthorized|forbidden|denied|permission|access denied
SERVICE_ANOMALY|service failed|daemon crashed|restart|shutdown|error
SECURITY_VIOLATION|violation|breach|intrusion|attack|compromise
SUSPICIOUS_IP|proxy|vpn|tor|anonymous|foreign|unknown
EOF
    
    log_message "INFO" "Pattern database created: $PATTERN_DB"
}

# Analyze authentication logs
analyze_auth_logs() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local auth_log="/var/log/auth.log"
    
    if [[ ! -f "$auth_log" ]]; then
        auth_log="/var/log/secure"  # RHEL/CentOS
    fi
    
    if [[ ! -f "$auth_log" ]]; then
        log_message "WARN" "Authentication log not found"
        return 0
    fi
    
    # Get recent log entries
    local recent_entries=$(tail -n 100 "$auth_log")
    
    # Analyze failed login attempts
    local failed_count=0
    local failed_ips=()
    
    while IFS= read -r line; do
        if echo "$line" | grep -qiE "failed|invalid|authentication"; then
            ((failed_count++))
            
            # Extract IP address
            local ip=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)
            if [[ -n "$ip" ]]; then
                failed_ips+=("$ip")
            fi
        fi
    done <<< "$recent_entries"
    
    # Check for brute force attacks
    if [[ $failed_count -gt $MAX_FAILED_LOGIN_ATTEMPTS ]]; then
        send_alert "HIGH" "Multiple failed login attempts detected: $failed_count" "AUTH_ANALYZER"
        
        # Count IPs and block if necessary
        printf '%s\n' "${failed_ips[@]}" | sort | uniq -c | sort -nr | while read -r count ip; do
            if [[ $count -gt $MAX_FAILED_LOGIN_ATTEMPTS ]]; then
                send_alert "CRITICAL" "Brute force attack from $ip: $count attempts" "AUTH_ANALYZER"
                block_ip "$ip"
            fi
        done
    fi
    
    echo "[$timestamp] Auth analysis: $failed_count failed attempts" >> "$ANALYSIS_LOG"
}

# Analyze system logs
analyze_system_logs() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local syslog="/var/log/syslog"
    
    if [[ ! -f "$syslog" ]]; then
        syslog="/var/log/messages"  # RHEL/CentOS
    fi
    
    if [[ ! -f "$syslog" ]]; then
        log_message "WARN" "System log not found"
        return 0
    fi
    
    # Get recent entries
    local recent_entries=$(tail -n 200 "$syslog")
    local anomaly_count=0
    
    # Check for suspicious patterns
    while IFS= read -r line; do
        if echo "$line" | grep -qiE "panic|oops|segfault|kernel panic|fatal|critical"; then
            ((anomaly_count++))
            echo "[$timestamp] SYSTEM_ANOMALY: $line" >> "$ANOMALY_LOG"
        fi
        
        # Check for unusual process activity
        if echo "$line" | grep -qiE "suspicious|unusual|unexpected|malicious"; then
            send_alert "MEDIUM" "Suspicious system activity: $line" "SYSTEM_ANALYZER"
        fi
    done <<< "$recent_entries"
    
    if [[ $anomaly_count -gt 5 ]]; then
        send_alert "HIGH" "Multiple system anomalies detected: $anomaly_count" "SYSTEM_ANALYZER"
    fi
}

# Analyze web server logs
analyze_web_logs() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local web_logs=("/var/log/apache2/access.log" "/var/log/nginx/access.log" "/var/log/httpd/access.log")
    
    for web_log in "${web_logs[@]}"; do
        if [[ -f "$web_log" ]]; then
            analyze_web_log "$web_log" "$timestamp"
        fi
    done
}

# Analyze individual web log
analyze_web_log() {
    local web_log="$1"
    local timestamp="$2"
    local recent_entries=$(tail -n 500 "$web_log")
    local suspicious_count=0
    local error_count=0
    
    while IFS= read -r line; do
        # Check for HTTP errors
        if echo "$line" | grep -E " (4[0-9]{2}|5[0-9]{2}) "; then
            ((error_count++))
            
            # Check for specific attack patterns
            if echo "$line" | grep -qiE "sql injection|xss|csrf|directory traversal|\.\./|\.\.%2f"; then
                ((suspicious_count++))
                send_alert "HIGH" "Web attack detected: $line" "WEB_ANALYZER"
            fi
        fi
        
        # Check for unusual user agents
        if echo "$line" | grep -qiE "bot|crawler|scanner|nikto|nmap|sqlmap"; then
            send_alert "MEDIUM" "Suspicious user agent detected: $line" "WEB_ANALYZER"
        fi
        
        # Check for large requests
        local request_size=$(echo "$line" | awk '{print $10}')
        if [[ $request_size -gt 10485760 ]]; then  # 10MB
            send_alert "MEDIUM" "Large web request detected: ${request_size} bytes" "WEB_ANALYZER"
        fi
    done <<< "$recent_entries"
    
    if [[ $error_count -gt 100 ]]; then
        send_alert "HIGH" "High web error rate: $error_count errors" "WEB_ANALYZER"
    fi
    
    echo "[$timestamp] Web analysis for $web_log: $error_count errors, $suspicious_count attacks" >> "$ANALYSIS_LOG"
}

# Pattern matching analysis
pattern_analysis() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local log_files_array
    
    IFS=',' read -ra log_files_array <<< "$LOG_FILES"
    
    for log_file in "${log_files_array[@]}"; do
        if [[ -f "$log_file" ]]; then
            analyze_patterns "$log_file" "$timestamp"
        fi
    done
}

# Analyze patterns in log file
analyze_patterns() {
    local log_file="$1"
    local timestamp="$2"
    local recent_entries=$(tail -n 1000 "$log_file")
    
    while IFS= read -r pattern_line; do
        if [[ "$pattern_line" =~ ^# ]] || [[ -z "$pattern_line" ]]; then
            continue
        fi
        
        local pattern_name=$(echo "$pattern_line" | cut -d'|' -f1)
        local patterns=$(echo "$pattern_line" | cut -d'|' -f2)
        
        local match_count=0
        while IFS= read -r line; do
            if echo "$line" | grep -iqE "$patterns"; then
                ((match_count++))
                echo "[$timestamp] PATTERN_MATCH: $pattern_name - $line" >> "$ANOMALY_LOG"
            fi
        done <<< "$recent_entries"
        
        if [[ $match_count -gt 0 ]]; then
            send_alert "MEDIUM" "Pattern '$pattern_name' matched $match_count times in $log_file" "PATTERN_ANALYZER"
        fi
    done < "$PATTERN_DB"
}

# Detect log anomalies
detect_log_anomalies() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local log_files_array
    
    IFS=',' read -ra log_files_array <<< "$LOG_FILES"
    
    for log_file in "${log_files_array[@]}"; do
        if [[ -f "$log_file" ]]; then
            detect_file_anomalies "$log_file" "$timestamp"
        fi
    done
}

# Detect anomalies in specific log file
detect_file_anomalies() {
    local log_file="$1"
    local timestamp="$2"
    
    # Check log size
    local file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo 0)
    
    # Check log growth rate
    local size_file="${TEMP_DIR}/${log_file##*/}_size.tmp"
    echo "$timestamp,$file_size" >> "$size_file"
    
    # Keep only last 10 entries
    tail -n 10 "$size_file" > "${size_file}.new" 2>/dev/null || true
    mv "${size_file}.new" "$size_file" 2>/dev/null || true
    
    # Calculate growth rate
    if [[ -f "$size_file" ]]; then
        local line_count=$(wc -l < "$size_file")
        if [[ $line_count -gt 1 ]]; then
            local last_line=$(tail -n 1 "$size_file")
            local prev_line=$(tail -n 2 "$size_file" | head -n 1)
            
            local last_size=$(echo "$last_line" | cut -d',' -f2)
            local prev_size=$(echo "$prev_line" | cut -d',' -f2)
            
            local growth=$((last_size - prev_size))
            
            # Alert on rapid log growth
            if [[ $growth -gt 1048576 ]]; then  # 1MB
                send_alert "MEDIUM" "Rapid log growth in $log_file: $((growth/1024))KB" "LOG_ANOMALY"
            fi
        fi
    fi
    
    # Check for log rotation issues
    if [[ $file_size -gt 104857600 ]]; then  # 100MB
        send_alert "HIGH" "Large log file detected: $log_file (${file_size} bytes)" "LOG_ANOMALY"
    fi
}

# Correlate events across logs
correlate_events() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local correlation_window=300  # 5 minutes
    local current_time=$(date +%s)
    
    # Look for related events in recent logs
    local recent_anomalies=$(find "$ANOMALY_LOG" -mmin -5 2>/dev/null || true)
    
    if [[ -n "$recent_anomalies" ]]; then
        local anomaly_count=$(echo "$recent_anomalies" | wc -l)
        
        if [[ $anomaly_count -gt 10 ]]; then
            send_alert "CRITICAL" "Multiple correlated anomalies detected: $anomaly_count events" "EVENT_CORRELATION"
        fi
    fi
}

# Main log analyzer function
log_analyzer_main() {
    if [[ "$LOG_ANALYSIS_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Initialize if not done
    if [[ ! -f "$LOG_STATE" ]]; then
        init_log_analyzer
    fi
    
    # Run analysis functions
    analyze_auth_logs
    analyze_system_logs
    analyze_web_logs
    pattern_analysis
    detect_log_anomalies
    correlate_events
}

# Export functions for main script
export -f init_log_analyzer create_pattern_db analyze_auth_logs analyze_system_logs
export -f analyze_web_logs analyze_web_log pattern_analysis analyze_patterns
export -f detect_log_anomalies detect_file_anomalies correlate_events log_analyzer_main
