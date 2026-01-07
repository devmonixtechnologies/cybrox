#!/bin/bash

# INTRUSION DETECTION MODULE
# Advanced intrusion detection and threat analysis

# Intrusion detection state files
readonly INTRUSION_STATE="${TEMP_DIR}/intrusion_state.tmp"
readonly INTRUSION_LOG="${LOGS_DIR}/intrusion_detection.log"
readonly THREAT_LOG="${LOGS_DIR}/threats.log"
readonly SIGNATURE_DB="${CONFIG_DIR}/threat_signatures.db"

# Initialize intrusion detection
init_intrusion_detection() {
    log_message "INFO" "Initializing intrusion detection module"
    
    # Create state files
    touch "$INTRUSION_STATE" "$INTRUSION_LOG" "$THREAT_LOG"
    
    # Create threat signature database if not exists
    if [[ ! -f "$SIGNATURE_DB" ]]; then
        create_signature_database
    fi
    
    # Initialize tracking variables
    declare -A attack_patterns
    declare -A threat_levels
    declare -A incident_counts
    declare -A last_incident
    
    # Save initial state
    declare -p attack_patterns threat_levels incident_counts last_incident > "$INTRUSION_STATE"
}

# Create threat signature database
create_signature_database() {
    cat > "$SIGNATURE_DB" << 'EOF'
# Network attack signatures
PORT_SCAN|multiple ports|rapid connection attempts|reconnaissance
BRUTE_FORCE|repeated login|password attempts|authentication failure
DDOS|high connection count|bandwidth flood|service disruption
SQL_INJECTION|union select|or 1=1|drop table|insert into
XSS_ATTACK|script>alert|onerror|javascript|<script>
DIRECTORY_TRAVERSAL|\.\./|\.\.%2f|\.\.%c0%af|etc/passwd
COMMAND_INJECTION|;cat|;ls|;whoami|;id|`whoami`
BUFFER_OVERFLOW|AAAAA|NOP sled|\x90\x90\x90|shellcode
MITM|arp spoof|dns poisoning|session hijack|man in middle
BACKDOOR|reverse shell|bind shell|nc -e|/bin/sh
ROOTKIT|hidden processes|unusual system calls|kernel modules
MALWARE|virus|trojan|worm|botnet|c2 communication
EOF
    
    log_message "INFO" "Threat signature database created: $SIGNATURE_DB"
}

# Detect network intrusions
detect_network_intrusions() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local network_log="${TEMP_DIR}/network_intrusions.tmp"
    
    # Analyze network traffic patterns
    if command -v tcpdump &> /dev/null; then
        timeout 10 tcpdump -i "$SYSTEM_INTERFACE" -n -c 200 2>/dev/null | \
        awk '{print $0}' > "$network_log"
        
        # Check for attack signatures
        while IFS= read -r signature_line; do
            if [[ "$signature_line" =~ ^# ]] || [[ -z "$signature_line" ]]; then
                continue
            fi
            
            local attack_type=$(echo "$signature_line" | cut -d'|' -f1)
            local patterns=$(echo "$signature_line" | cut -d'|' -f2- | tr '|' '|')
            
            local match_count=0
            IFS='|' read -ra pattern_array <<< "$patterns"
            
            for pattern in "${pattern_array[@]}"; do
                local matches=$(grep -i "$pattern" "$network_log" | wc -l)
                match_count=$((match_count + matches))
            done
            
            if [[ $match_count -gt 0 ]]; then
                local threat_level=$(determine_threat_level "$attack_type" "$match_count")
                send_alert "$threat_level" "Network intrusion detected: $attack_type ($match_count matches)" "NETWORK_INTRUSION"
                echo "[$timestamp] NETWORK_INTRUSION: $attack_type - $match_count matches" >> "$INTRUSION_LOG"
            fi
        done < "$SIGNATURE_DB"
        
        rm -f "$network_log"
    fi
}

# Detect application layer attacks
detect_application_attacks() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local web_logs=("/var/log/apache2/access.log" "/var/log/nginx/access.log" "/var/log/httpd/access.log")
    
    for web_log in "${web_logs[@]}"; do
        if [[ -f "$web_log" ]]; then
            analyze_web_attacks "$web_log" "$timestamp"
        fi
    done
}

# Analyze web attacks in log file
analyze_web_attacks() {
    local web_log="$1"
    local timestamp="$2"
    local recent_entries=$(tail -n 1000 "$web_log")
    
    # SQL Injection patterns
    local sql_patterns="union.*select|or.*1=1|drop.*table|insert.*into|delete.*from|update.*set"
    local sql_matches=$(echo "$recent_entries" | grep -iE "$sql_patterns" | wc -l)
    
    if [[ $sql_matches -gt 0 ]]; then
        send_alert "HIGH" "SQL Injection attempts detected: $sql_matches in $web_log" "WEB_ATTACK"
        echo "[$timestamp] SQL_INJECTION: $sql_matches attempts in $web_log" >> "$INTRUSION_LOG"
    fi
    
    # XSS patterns
    local xss_patterns="<script|alert\(|onerror=|javascript:|document\.cookie"
    local xss_matches=$(echo "$recent_entries" | grep -iE "$xss_patterns" | wc -l)
    
    if [[ $xss_matches -gt 0 ]]; then
        send_alert "MEDIUM" "XSS attempts detected: $xss_matches in $web_log" "WEB_ATTACK"
        echo "[$timestamp] XSS_ATTACK: $xss_matches attempts in $web_log" >> "$INTRUSION_LOG"
    fi
    
    # Directory traversal patterns
    local dir_patterns="\.\./|\.\.%2f|\.\.%c0%af|etc/passwd|windows/system32"
    local dir_matches=$(echo "$recent_entries" | grep -iE "$dir_patterns" | wc -l)
    
    if [[ $dir_matches -gt 0 ]]; then
        send_alert "HIGH" "Directory traversal attempts: $dir_matches in $web_log" "WEB_ATTACK"
        echo "[$timestamp] DIR_TRAVERSAL: $dir_matches attempts in $web_log" >> "$INTRUSION_LOG"
    fi
    
    # Command injection patterns
    local cmd_patterns=";cat|;ls|;whoami|;id|`whoami|\|whoami|&&whoami"
    local cmd_matches=$(echo "$recent_entries" | grep -iE "$cmd_patterns" | wc -l)
    
    if [[ $cmd_matches -gt 0 ]]; then
        send_alert "CRITICAL" "Command injection attempts: $cmd_matches in $web_log" "WEB_ATTACK"
        echo "[$timestamp] CMD_INJECTION: $cmd_matches attempts in $web_log" >> "$INTRUSION_LOG"
    fi
}

# Detect privilege escalation attempts
detect_privilege_escalation() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local auth_log="/var/log/auth.log"
    
    if [[ ! -f "$auth_log" ]]; then
        auth_log="/var/log/secure"
    fi
    
    if [[ ! -f "$auth_log" ]]; then
        return 0
    fi
    
    local recent_entries=$(tail -n 500 "$auth_log")
    
    # Check for sudo abuse
    local sudo_abuse=$(echo "$recent_entries" | grep -E "sudo.*COMMAND" | grep -vE "(vi|nano|cat|ls)" | wc -l)
    if [[ $sudo_abuse -gt 5 ]]; then
        send_alert "HIGH" "Potential sudo abuse: $sudo_abuse suspicious commands" "PRIVILEGE_ESCALATION"
        echo "[$timestamp] SUDO_ABUSE: $sudo_abuse suspicious commands" >> "$INTRUSION_LOG"
    fi
    
    # Check for su attempts
    local su_attempts=$(echo "$recent_entries" | grep -E "su.*to.*root" | wc -l)
    if [[ $su_attempts -gt 3 ]]; then
        send_alert "MEDIUM" "Multiple su attempts to root: $su_attempts" "PRIVILEGE_ESCALATION"
        echo "[$timestamp] SU_ATTEMPTS: $su_attempts attempts to root" >> "$INTRUSION_LOG"
    fi
    
    # Check for password changes
    local passwd_changes=$(echo "$recent_entries" | grep -E "passwd.*changed|chpasswd" | wc -l)
    if [[ $passwd_changes -gt 2 ]]; then
        send_alert "HIGH" "Multiple password changes detected: $passwd_changes" "PRIVILEGE_ESCALATION"
        echo "[$timestamp] PASSWD_CHANGES: $passwd_changes password changes" >> "$INTRUSION_LOG"
    fi
}

# Detect malware and backdoors
detect_malware_signatures() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Check for suspicious network connections
    local suspicious_connections=$(netstat -ant 2>/dev/null | grep -E "ESTABLISHED" | \
    awk '{print $5}' | cut -d':' -f1 | sort | uniq -c | sort -nr | \
    awk '$1 > 10 {print $2}')
    
    while IFS= read -r ip; do
        if [[ -n "$ip" ]]; then
            # Check if IP is known malicious
            if is_malicious_ip "$ip"; then
                send_alert "CRITICAL" "Connection to malicious IP: $ip" "MALWARE_DETECTION"
                echo "[$timestamp] MALICIOUS_IP: Connection to $ip" >> "$INTRUSION_LOG"
            fi
        fi
    done <<< "$suspicious_connections"
    
    # Check for suspicious processes
    local suspicious_procs=$(ps aux --no-headers | grep -iE "backdoor|rootkit|trojan|malware|botnet" | grep -v grep)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local pid=$(echo "$line" | awk '{print $2}')
            local cmd=$(echo "$line" | awk '{print $11}')
            send_alert "CRITICAL" "Malware process detected: $cmd (PID: $pid)" "MALWARE_DETECTION"
            echo "[$timestamp] MALWARE_PROCESS: $cmd (PID: $pid)" >> "$INTRUSION_LOG"
        fi
    done <<< "$suspicious_procs"
    
    # Check for unusual file modifications
    local modified_files=$(find /tmp /var/tmp -type f -mmin -30 2>/dev/null | head -n 10)
    
    while IFS= read -r file; do
        if [[ -n "$file" ]]; then
            send_alert "MEDIUM" "Recently modified file in temp: $file" "MALWARE_DETECTION"
            echo "[$timestamp] SUSPICIOUS_FILE: $file" >> "$INTRUSION_LOG"
        fi
    done <<< "$modified_files"
}

# Check if IP is malicious
is_malicious_ip() {
    local ip="$1"
    
    # Check against known malicious IP ranges (simplified)
    local malicious_ranges="10.0.0.0/8|172.16.0.0/12|192.168.0.0/16"  # Private networks (example)
    
    # In a real implementation, this would check against threat intelligence feeds
    # For now, just check if it's a private network connecting unusually
    if echo "$ip" | grep -qE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
        return 1  # Not considered malicious in this simplified version
    fi
    
    return 0  # Consider external IPs potentially malicious for demonstration
}

# Detect insider threats
detect_insider_threats() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S"
    
    # Check for unusual user activity
    local users=$(ps aux --no-headers | awk '{print $1}' | sort | uniq)
    
    while IFS= read -r user; do
        if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
            # Check for unusual login times
            local user_logins=$(last "$user" | head -n 10 | wc -l)
            if [[ $user_logins -gt 20 ]]; then
                send_alert "MEDIUM" "High login activity for user $user: $user_logins sessions" "INSIDER_THREAT"
                echo "[$timestamp] USER_ACTIVITY: High login count for $user" >> "$INTRUSION_LOG"
            fi
            
            # Check for unusual file access
            local user_file_access=$(find /home -user "$user" -mmin -60 2>/dev/null | wc -l)
            if [[ $user_file_access -gt 50 ]]; then
                send_alert "MEDIUM" "High file activity for user $user: $user_file_access files" "INSIDER_THREAT"
                echo "[$timestamp] FILE_ACTIVITY: High file access for $user" >> "$INTRUSION_LOG"
            fi
        fi
    done <<< "$users"
}

# Correlate intrusion events
correlate_intrusion_events() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local recent_events=$(find "$INTRUSION_LOG" -mmin -10 2>/dev/null || true)
    
    if [[ -n "$recent_events" ]]; then
        local event_count=$(echo "$recent_events" | wc -l)
        
        if [[ $event_count -gt 5 ]]; then
            send_alert "CRITICAL" "Multiple intrusion events detected: $event_count in 10 minutes" "EVENT_CORRELATION"
            echo "[$timestamp] CORRELATION: $event_count intrusion events" >> "$THREAT_LOG"
        fi
        
        # Analyze event patterns
        local attack_types=$(echo "$recent_events" | awk '{print $4}' | sort | uniq -c | sort -nr)
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local count=$(echo "$line" | awk '{print $1}')
                local attack_type=$(echo "$line" | awk '{print $2}')
                
                if [[ $count -gt 3 ]]; then
                    send_alert "HIGH" "Repeated attack pattern: $attack_type ($count times)" "ATTACK_PATTERN"
                    echo "[$timestamp] ATTACK_PATTERN: $attack_type repeated $count times" >> "$THREAT_LOG"
                fi
            fi
        done <<< "$attack_types"
    fi
}

# Determine threat level
determine_threat_level() {
    local attack_type="$1"
    local match_count="$2"
    
    case "$attack_type" in
        "SQL_INJECTION"|"COMMAND_INJECTION"|"BACKDOOR"|"ROOTKIT")
            if [[ $match_count -gt 5 ]]; then
                echo "CRITICAL"
            else
                echo "HIGH"
            fi
            ;;
        "XSS_ATTACK"|"DIRECTORY_TRAVERSAL"|"PRIVILEGE_ESCALATION")
            if [[ $match_count -gt 10 ]]; then
                echo "HIGH"
            else
                echo "MEDIUM"
            fi
            ;;
        "PORT_SCAN"|"BRUTE_FORCE")
            if [[ $match_count -gt 20 ]]; then
                echo "HIGH"
            else
                echo "MEDIUM"
            fi
            ;;
        *)
            if [[ $match_count -gt 15 ]]; then
                echo "MEDIUM"
            else
                echo "LOW"
            fi
            ;;
    esac
}

# Generate intrusion report
generate_intrusion_report() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local report_file="${LOGS_DIR}/intrusion_report_$(date +%Y%m%d).txt"
    
    cat > "$report_file" << EOF
CYBROX INTRUSION DETECTION REPORT
Generated: $timestamp
Host: $SYSTEM_HOSTNAME
IP: $SYSTEM_IP

=== SUMMARY ===
Total Intrusion Events: $(wc -l < "$INTRUSION_LOG" 2>/dev/null || echo 0)
Total Threats: $(wc -l < "$THREAT_LOG" 2>/dev/null || echo 0)

=== RECENT INTRUSION EVENTS ===
$(tail -n 20 "$INTRUSION_LOG" 2>/dev/null || echo "No recent events")

=== RECENT THREATS ===
$(tail -n 10 "$THREAT_LOG" 2>/dev/null || echo "No recent threats")

=== TOP ATTACK TYPES ===
$(awk '{print $4}' "$INTRUSION_LOG" 2>/dev/null | sort | uniq -c | sort -nr | head -n 10 || echo "No data")

=== RECOMMENDATIONS ===
1. Review recent intrusion events for patterns
2. Update firewall rules to block malicious IPs
3. Patch vulnerable services
4. Monitor affected systems closely
5. Consider enhancing security controls

EOF
    
    log_message "INFO" "Intrusion report generated: $report_file"
}

# Main intrusion detection function
intrusion_detection_main() {
    if [[ "$INTRUSION_DETECTION_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Initialize if not done
    if [[ ! -f "$INTRUSION_STATE" ]]; then
        init_intrusion_detection
    fi
    
    # Run detection functions
    detect_network_intrusions
    detect_application_attacks
    detect_privilege_escalation
    detect_malware_signatures
    detect_insider_threats
    correlate_intrusion_events
    
    # Generate report hourly
    if (( $(date +%s) % 3600 == 0 )); then
        generate_intrusion_report
    fi
}

# Export functions for main script
export -f init_intrusion_detection create_signature_database detect_network_intrusions
export -f detect_application_attacks analyze_web_attacks detect_privilege_escalation
export -f detect_malware_signatures is_malicious_ip detect_insider_threats
export -f correlate_intrusion_events determine_threat_level generate_intrusion_report
export -f intrusion_detection_main
