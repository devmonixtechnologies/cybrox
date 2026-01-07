#!/bin/bash

# AUTOMATED RESPONSE MODULE
# Automated incident response and system hardening

# Auto response state files
readonly RESPONSE_STATE="${TEMP_DIR}/auto_response_state.tmp"
readonly RESPONSE_LOG="${LOGS_DIR}/auto_response.log"
readonly ACTIONS_LOG="${LOGS_DIR}/response_actions.log"

# Initialize automated response
init_auto_response() {
    log_message "INFO" "Initializing automated response module"
    
    # Create state files
    touch "$RESPONSE_STATE" "$RESPONSE_LOG" "$ACTIONS_LOG"
    
    # Initialize tracking variables
    declare -A response_actions
    declare -A blocked_entities
    declare -A last_response
    declare -A response_counts
    
    # Save initial state
    declare -p response_actions blocked_entities last_response response_counts > "$RESPONSE_STATE"
}

# Automated IP blocking
auto_block_ip() {
    local ip="$1"
    local reason="$2"
    local severity="$3"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Check if already blocked
    if grep -q "$ip" "$BLOCKED_IPS" 2>/dev/null; then
        return 0
    fi
    
    # Block using multiple methods
    block_ip_firewall "$ip"
    block_ip_hosts "$ip"
    block_ip_fail2ban "$ip" 2>/dev/null || true
    
    # Log action
    echo "[$timestamp] BLOCKED_IP: $ip - Reason: $reason (Severity: $severity)" >> "$ACTIONS_LOG"
    log_message "INFO" "Auto-blocked IP: $ip - $reason"
    
    # Send notification
    send_alert "MEDIUM" "Auto-blocked IP: $ip - $reason" "AUTO_RESPONSE"
    
    # Add to blocked list
    echo "$timestamp,$ip" >> "$BLOCKED_IPS"
}

# Block IP using firewall
block_ip_firewall() {
    local ip="$1"
    
    # iptables blocking
    if command -v iptables &> /dev/null; then
        iptables -A INPUT -s "$ip" -j DROP 2>/dev/null || true
        iptables -A FORWARD -s "$ip" -j DROP 2>/dev/null || true
        iptables -A OUTPUT -d "$ip" -j DROP 2>/dev/null || true
    fi
    
    # ufw blocking (Ubuntu)
    if command -v ufw &> /dev/null; then
        ufw deny from "$ip" 2>/dev/null || true
    fi
    
    # firewalld blocking (RHEL/CentOS)
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' drop" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
}

# Block IP using hosts file
block_ip_hosts() {
    local ip="$1"
    local hosts_file="/etc/hosts.deny"
    
    if [[ -f "$hosts_file" ]]; then
        echo "ALL: $ip" >> "$hosts_file" 2>/dev/null || true
    fi
}

# Block IP using fail2ban
block_ip_fail2ban() {
    local ip="$1"
    
    if command -v fail2ban-client &> /dev/null; then
        # Create custom jail if not exists
        fail2ban-client status cybrox 2>/dev/null || {
            cat > "/etc/fail2ban/jail.d/cybrox.conf" << EOF
[cybrox]
enabled = true
filter = cybrox
action = iptables-allports[name=cybrox]
logpath = ${LOGS_DIR}/cybrox.log
maxretry = 3
bantime = 3600
EOF
            
            cat > "/etc/fail2ban/filter.d/cybrox.conf" << EOF
[Definition]
failregex = .*ALERT.*<HOST>.*
ignoreregex =
EOF
            
            fail2ban-client reload 2>/dev/null || true
        }
        
        fail2ban-client set cybrox banip "$ip" 2>/dev/null || true
    fi
}

# Automated process termination
auto_kill_process() {
    local pid="$1"
    local process_name="$2"
    local reason="$3"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Verify process exists
    if ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    
    # Get process details
    local process_info=$(ps -p "$pid" -o pid,user,comm,cmd --no-headers 2>/dev/null || echo "")
    local user=$(echo "$process_info" | awk '{print $2}')
    local cmd=$(echo "$process_info" | awk '{print $4}')
    
    # Try graceful termination first
    if kill -TERM "$pid" 2>/dev/null; then
        sleep 2
        
        # Check if still running
        if kill -0 "$pid" 2>/dev/null; then
            # Force kill
            kill -KILL "$pid" 2>/dev/null || true
        fi
        
        # Log action
        echo "[$timestamp] KILLED_PROCESS: PID $pid ($process_name) - User: $user - Reason: $reason" >> "$ACTIONS_LOG"
        log_message "INFO" "Auto-killed process: $process_name (PID: $pid, User: $user) - $reason"
        
        # Send notification
        send_alert "MEDIUM" "Auto-killed suspicious process: $process_name (PID: $pid)" "AUTO_RESPONSE"
        
        # Kill child processes
        local child_pids=$(pgrep -P "$pid" 2>/dev/null || true)
        for child_pid in $child_pids; do
            kill -TERM "$child_pid" 2>/dev/null || true
            sleep 1
            kill -KILL "$child_pid" 2>/dev/null || true
        done
    fi
}

# Automated user account actions
auto_handle_user() {
    local username="$1"
    local action="$2"
    local reason="$3"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$action" in
        "lock")
            # Lock user account
            usermod -L "$username" 2>/dev/null || true
            echo "[$timestamp] LOCKED_USER: $username - Reason: $reason" >> "$ACTIONS_LOG"
            log_message "INFO" "Auto-locked user account: $username - $reason"
            send_alert "HIGH" "Auto-locked user account: $username - $reason" "AUTO_RESPONSE"
            ;;
        "disable")
            # Disable user account
            usermod -s /usr/sbin/nologin "$username" 2>/dev/null || true
            echo "[$timestamp] DISABLED_USER: $username - Reason: $reason" >> "$ACTIONS_LOG"
            log_message "INFO" "Auto-disabled user account: $username - $reason"
            send_alert "MEDIUM" "Auto-disabled user account: $username - $reason" "AUTO_RESPONSE"
            ;;
        "kill_sessions")
            # Kill all user sessions
            pkill -u "$username" 2>/dev/null || true
            echo "[$timestamp] KILLED_SESSIONS: $username - Reason: $reason" >> "$ACTIONS_LOG"
            log_message "INFO" "Auto-killed sessions for user: $username - $reason"
            send_alert "MEDIUM" "Auto-killed sessions for user: $username - $reason" "AUTO_RESPONSE"
            ;;
    esac
}

# Automated service actions
auto_handle_service() {
    local service="$1"
    local action="$2"
    local reason="$3"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S"
    
    case "$action" in
        "stop")
            systemctl stop "$service" 2>/dev/null || service "$service" stop 2>/dev/null || true
            echo "[$timestamp] STOPPED_SERVICE: $service - Reason: $reason" >> "$ACTIONS_LOG"
            log_message "INFO" "Auto-stopped service: $service - $reason"
            send_alert "HIGH" "Auto-stopped service: $service - $reason" "AUTO_RESPONSE"
            ;;
        "restart")
            systemctl restart "$service" 2>/dev/null || service "$service" restart 2>/dev/null || true
            echo "[$timestamp] RESTARTED_SERVICE: $service - Reason: $reason" >> "$ACTIONS_LOG"
            log_message "INFO" "Auto-restarted service: $service - $reason"
            send_alert "MEDIUM" "Auto-restarted service: $service - $reason" "AUTO_RESPONSE"
            ;;
        "disable")
            systemctl disable "$service" 2>/dev/null || chkconfig "$service" off 2>/dev/null || true
            echo "[$timestamp] DISABLED_SERVICE: $service - Reason: $reason" >> "$ACTIONS_LOG"
            log_message "INFO" "Auto-disabled service: $service - $reason"
            send_alert "HIGH" "Auto-disabled service: $service - $reason" "AUTO_RESPONSE"
            ;;
    esac
}

# Automated file quarantine
auto_quarantine_file() {
    local file="$1"
    local reason="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local quarantine_dir="${TEMP_DIR}/quarantine"
    
    # Create quarantine directory
    mkdir -p "$quarantine_dir"
    
    # Generate quarantine filename
    local quarantine_file="${quarantine_dir}/$(basename "$file")_$(date +%s)"
    
    # Move file to quarantine
    if mv "$file" "$quarantine_file" 2>/dev/null; then
        echo "[$timestamp] QUARANTINED_FILE: $file -> $quarantine_file - Reason: $reason" >> "$ACTIONS_LOG"
        log_message "INFO" "Auto-quarantined file: $file - $reason"
        send_alert "MEDIUM" "Auto-quarantined file: $file - $reason" "AUTO_RESPONSE"
        
        # Set restrictive permissions
        chmod 000 "$quarantine_file" 2>/dev/null || true
    fi
}

# Automated system hardening
auto_harden_system() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Harden SSH configuration
    harden_ssh_config
    
    # Harden network configuration
    harden_network_config
    
    # Harden file permissions
    harden_file_permissions
    
    # Enable security services
    enable_security_services
    
    echo "[$timestamp] SYSTEM_HARDENED: Automated hardening completed" >> "$ACTIONS_LOG"
    log_message "INFO" "Automated system hardening completed"
}

# Harden SSH configuration
harden_ssh_config() {
    local ssh_config="/etc/ssh/sshd_config"
    
    if [[ -f "$ssh_config" ]]; then
        # Backup original config
        cp "$ssh_config" "${ssh_config}.cybrox.backup" 2>/dev/null || true
        
        # Apply hardening settings
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$ssh_config" 2>/dev/null || true
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$ssh_config" 2>/dev/null || true
        sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$ssh_config" 2>/dev/null || true
        sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$ssh_config" 2>/dev/null || true
        sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' "$ssh_config" 2>/dev/null || true
        sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' "$ssh_config" 2>/dev/null || true
        
        # Restart SSH service
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        
        log_message "INFO" "SSH configuration hardened"
    fi
}

# Harden network configuration
harden_network_config() {
    # Disable IP forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    
    # Enable SYN cookies
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || true
    
    # Disable source routing
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route 2>/dev/null || true
    
    # Disable redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/default/accept_redirects 2>/dev/null || true
    
    log_message "INFO" "Network configuration hardened"
}

# Harden file permissions
harden_file_permissions() {
    # Secure critical files
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    chmod 600 /etc/sudoers 2>/dev/null || true
    
    # Remove world-writable permissions
    find / -type f -perm /002 -exec chmod o-w {} \; 2>/dev/null || true
    find / -type d -perm /002 -exec chmod o-w {} \; 2>/dev/null || true
    
    log_message "INFO" "File permissions hardened"
}

# Enable security services
enable_security_services() {
    # Enable and start firewall
    if command -v ufw &> /dev/null; then
        ufw --force enable 2>/dev/null || true
    fi
    
    # Enable fail2ban
    if command -v fail2ban-client &> /dev/null; then
        systemctl enable fail2ban 2>/dev/null || true
        systemctl start fail2ban 2>/dev/null || true
    fi
    
    # Enable auditd
    if command -v auditd &> /dev/null; then
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
    fi
    
    log_message "INFO" "Security services enabled"
}

# Automated incident response
auto_respond_incident() {
    local incident_type="$1"
    local incident_data="$2"
    local severity="$3"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case "$incident_type" in
        "BRUTE_FORCE")
            local ip=$(echo "$incident_data" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)
            if [[ -n "$ip" ]]; then
                auto_block_ip "$ip" "Brute force attack" "$severity"
            fi
            ;;
        "SUSPICIOUS_PROCESS")
            local pid=$(echo "$incident_data" | grep -oE 'PID: [0-9]+' | cut -d' ' -f2)
            local process=$(echo "$incident_data" | grep -oE '[a-zA-Z0-9_-]+' | head -n 1)
            if [[ -n "$pid" ]] && [[ -n "$process" ]]; then
                auto_kill_process "$pid" "$process" "Suspicious activity" "$severity"
            fi
            ;;
        "MALWARE_DETECTED")
            local file=$(echo "$incident_data" | grep -oE '/[a-zA-Z0-9_/\.]+' | head -n 1)
            if [[ -n "$file" ]]; then
                auto_quarantine_file "$file" "Malware detected" "$severity"
            fi
            auto_harden_system
            ;;
        "PRIVILEGE_ESCALATION")
            local user=$(echo "$incident_data" | grep -oE 'user: [a-zA-Z0-9_-]+' | cut -d' ' -f2)
            if [[ -n "$user" ]]; then
                auto_handle_user "$user" "lock" "Privilege escalation attempt" "$severity"
            fi
            ;;
        "WEB_ATTACK")
            # Block attacking IP
            local ip=$(echo "$incident_data" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)
            if [[ -n "$ip" ]]; then
                auto_block_ip "$ip" "Web attack" "$severity"
            fi
            
            # Restart web services if needed
            auto_handle_service "apache2" "restart" "Web attack detected" "$severity" 2>/dev/null || true
            auto_handle_service "nginx" "restart" "Web attack detected" "$severity" 2>/dev/null || true
            ;;
        "SYSTEM_COMPROMISE")
            # Full system lockdown
            auto_harden_system
            auto_handle_service "ssh" "stop" "System compromise" "$severity" 2>/dev/null || true
            auto_handle_service "sshd" "stop" "System compromise" "$severity" 2>/dev/null || true
            ;;
    esac
    
    echo "[$timestamp] INCIDENT_RESPONSE: $incident_type - $severity" >> "$ACTIONS_LOG"
    log_message "INFO" "Automated response completed for: $incident_type"
}

# Main automated response function
auto_response_main() {
    if [[ "$AUTO_RESPONSE_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Initialize if not done
    if [[ ! -f "$RESPONSE_STATE" ]]; then
        init_auto_response
    fi
    
    # Monitor alerts and respond automatically
    local recent_alerts=$(tail -n 10 "$ALERT_LOG" 2>/dev/null || true)
    
    while IFS= read -r alert; do
        if [[ -n "$alert" ]]; then
            # Parse alert
            local severity=$(echo "$alert" | grep -oE '\[CRITICAL\]|\[HIGH\]|\[MEDIUM\]' | head -n 1 | tr -d '[]')
            local message=$(echo "$alert" | sed 's/.*\[ALERT\] .* \[.*\] \[.*\] //')
            local source=$(echo "$alert" | grep -oE '\[.*\]' | head -n 2 | tail -n 1 | tr -d '[]')
            
            # Determine response based on severity and content
            if [[ "$severity" == "CRITICAL" ]]; then
                # Immediate response for critical alerts
                if echo "$message" | grep -qi "brute force"; then
                    auto_respond_incident "BRUTE_FORCE" "$alert" "$severity"
                elif echo "$message" | grep -qi "malware\|backdoor\|rootkit"; then
                    auto_respond_incident "MALWARE_DETECTED" "$alert" "$severity"
                elif echo "$message" | grep -qi "privilege escalation"; then
                    auto_respond_incident "PRIVILEGE_ESCALATION" "$alert" "$severity"
                elif echo "$message" | grep -qi "system compromise"; then
                    auto_respond_incident "SYSTEM_COMPROMISE" "$alert" "$severity"
                fi
            elif [[ "$severity" == "HIGH" ]]; then
                # Moderate response for high alerts
                if echo "$message" | grep -qi "suspicious process"; then
                    auto_respond_incident "SUSPICIOUS_PROCESS" "$alert" "$severity"
                elif echo "$message" | grep -qi "web attack\|sql injection\|xss"; then
                    auto_respond_incident "WEB_ATTACK" "$alert" "$severity"
                fi
            fi
        fi
    done <<< "$recent_alerts"
    
    # Cleanup old blocked IPs
    cleanup_blocked_ips
}

# Export functions for main script
export -f init_auto_response auto_block_ip block_ip_firewall block_ip_hosts block_ip_fail2ban
export -f auto_kill_process auto_handle_user auto_handle_service auto_quarantine_file
export -f auto_harden_system harden_ssh_config harden_network_config harden_file_permissions
export -f enable_security_services auto_respond_incident auto_response_main
