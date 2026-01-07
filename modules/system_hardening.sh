#!/bin/bash

# SYSTEM HARDENING MODULE
# Comprehensive system security hardening and configuration management

# System hardening state files
readonly HARDENING_STATE="${TEMP_DIR}/hardening_state.tmp"
readonly HARDENING_LOG="${LOGS_DIR}/system_hardening.log"
readonly CONFIG_BACKUP="${TEMP_DIR}/config_backup"

# Initialize system hardening
init_system_hardening() {
    log_message "INFO" "Initializing system hardening module"
    
    # Create state files
    touch "$HARDENING_STATE" "$HARDENING_LOG"
    mkdir -p "$CONFIG_BACKUP"
    
    # Initialize tracking variables
    declare -A hardened_configs
    declare -A backup_timestamps
    declare -A security_settings
    
    # Save initial state
    declare -p hardened_configs backup_timestamps security_settings > "$HARDENING_STATE"
}

# Backup configuration before hardening
backup_config() {
    local config_file="$1"
    local timestamp=$(date +"Y%m%d_%H%M%S")
    local backup_file="${CONFIG_BACKUP}/$(basename "$config_file")_${timestamp}"
    
    if [[ -f "$config_file" ]]; then
        cp "$config_file" "$backup_file" 2>/dev/null || true
        echo "$timestamp" > "${backup_file}.timestamp"
        log_message "INFO" "Backed up configuration: $config_file -> $backup_file"
    fi
}

# SSH hardening
harden_ssh() {
    local ssh_config="/etc/ssh/sshd_config"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if [[ -f "$ssh_config" ]]; then
        backup_config "$ssh_config"
        
        # Create hardened SSH configuration
        cat > "${ssh_config}.hardened" << 'EOF'
# CYBROX HARDENED SSH CONFIGURATION
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Authentication settings
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Security settings
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60

# Key-based authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Access control
AllowUsers sshusers
DenyUsers root guest nobody
AllowGroups sshgroup
DenyGroups nogroup

# Network settings
ListenAddress 0.0.0.0
TCPKeepAlive yes
UsePrivilegeSeparation yes

# Subsystem configuration
Subsystem sftp /usr/lib/openssh/sftp-server

# Additional security
X11Forwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
Compression no
EOF
        
        # Apply hardened configuration
        mv "${ssh_config}.hardened" "$ssh_config"
        
        # Restart SSH service
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        
        echo "[$timestamp] SSH_HARDENED: Configuration applied and service restarted" >> "$HARDENING_LOG"
        log_message "INFO" "SSH hardening completed"
    fi
}

# Firewall configuration
configure_firewall() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Configure iptables
    if command -v iptables &> /dev/null; then
        # Backup existing rules
        iptables-save > "${CONFIG_BACKUP}/iptables_rules_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
        
        # Create hardened firewall rules
        cat > "${CONFIG_BACKUP}/firewall_rules.sh" << 'EOF'
#!/bin/bash
# CYBROX HARDENED FIREWALL RULES

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (rate limited)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name ssh
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name ssh -j DROP
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Rate limiting
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 20/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 20/minute --limit-burst 100 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Prevent IP spoofing
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -s 255.255.255.255/32 -j DROP

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4

# Save rules
iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null || true
EOF
        
        # Apply firewall rules
        chmod +x "${CONFIG_BACKUP}/firewall_rules.sh"
        "${CONFIG_BACKUP}/firewall_rules.sh" 2>/dev/null || true
        
        echo "[$timestamp] FIREWALL_CONFIGURED: Hardened iptables rules applied" >> "$HARDENING_LOG"
        log_message "INFO" "Firewall hardening completed"
    fi
    
    # Configure UFW if available
    if command -v ufw &> /dev/null; then
        ufw --force reset 2>/dev/null || true
        ufw default deny incoming 2>/dev/null || true
        ufw default allow outgoing 2>/dev/null || true
        ufw allow ssh 2>/dev/null || true
        ufw allow http 2>/dev/null || true
        ufw allow https 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
        
        echo "[$timestamp] UFW_CONFIGURED: UFW firewall enabled" >> "$HARDENING_LOG"
        log_message "INFO" "UFW firewall configured"
    fi
}

# System kernel hardening
harden_kernel() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local sysctl_config="/etc/sysctl.d/99-cybrox.conf"
    
    backup_config "$sysctl_config"
    
    # Create hardened sysctl configuration
    cat > "$sysctl_config" << 'EOF'
# CYBROX KERNEL HARDENING

# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Memory protection
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1

# File system security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Core dumps
kernel.core_pattern = |/bin/false

# Randomize memory space
kernel.randomize_va_space = 2

# Network stack protection
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_challenge_ack_limit = 1000000
EOF
    
    # Apply sysctl settings
    sysctl -p "$sysctl_config" 2>/dev/null || true
    
    echo "[$timestamp] KERNEL_HARDENED: Sysctl configuration applied" >> "$HARDENING_LOG"
    log_message "INFO" "Kernel hardening completed"
}

# User and group hardening
harden_users() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S"
    
    # Create security groups
    groupadd -f sshusers 2>/dev/null || true
    groupadd -f sshgroup 2>/dev/null || true
    groupadd -f webusers 2>/dev/null || true
    
    # Secure user accounts
    while IFS= read -r username; do
        if [[ -n "$username" ]] && [[ "$username" != "root" ]]; then
            # Lock accounts without passwords
            if [[ -z "$(grep "^$username:" /etc/shadow | cut -d':' -f2)" ]] || [[ "$(grep "^$username:" /etc/shadow | cut -d':' -f2)" == "!" ]] || [[ "$(grep "^$username:" /etc/shadow | cut -d':' -f2)" == "*" ]]; then
                usermod -L "$username" 2>/dev/null || true
                echo "[$timestamp] USER_LOCKED: $username (no password set)" >> "$HARDENING_LOG"
            fi
            
            # Remove users from unnecessary groups
            usermod -G "$username" "$username" 2>/dev/null || true
        fi
    done < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd)
    
    # Secure root account
    usermod -s /usr/sbin/nologin root 2>/dev/null || true
    
    echo "[$timestamp] USERS_HARDENED: User accounts secured" >> "$HARDENING_LOG"
    log_message "INFO" "User hardening completed"
}

# File permissions hardening
harden_permissions() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Secure critical files
    chmod 600 /etc/shadow 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 600 /etc/gshadow 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
    chmod 600 /etc/sudoers 2>/dev/null || true
    chmod 644 /etc/hosts 2>/dev/null || true
    chmod 644 /etc/fstab 2>/dev/null || true
    
    # Remove world-writable files
    find / -type f -perm /002 -exec chmod o-w {} \; 2>/dev/null || true
    find / -type d -perm /002 -exec chmod o-w {} \; 2>/dev/null || true
    
    # Secure home directories
    find /home -type d -exec chmod 750 {} \; 2>/dev/null || true
    
    # Secure temporary directories
    chmod 1777 /tmp 2>/dev/null || true
    chmod 1777 /var/tmp 2>/dev/null || true
    
    echo "[$timestamp] PERMISSIONS_HARDENED: File permissions secured" >> "$HARDENING_LOG"
    log_message "INFO" "File permissions hardening completed"
}

# Service hardening
harden_services() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Disable unnecessary services
    local services_to_disable=(
        "telnet"
        "rsh"
        "rlogin"
        "finger"
        "talk"
        "ntalk"
        "ftp"
        "tftp"
        "sendmail"
        "cups"
        "bluetooth"
        "avahi-daemon"
    )
    
    for service in "${services_to_disable[@]}"; do
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        echo "[$timestamp] SERVICE_DISABLED: $service" >> "$HARDENING_LOG"
    done
    
    # Enable security services
    local services_to_enable=(
        "fail2ban"
        "auditd"
        "rsyslog"
        "apparmor"
        "ufw"
    )
    
    for service in "${services_to_enable[@]}"; do
        systemctl enable "$service" 2>/dev/null || true
        systemctl start "$service" 2>/dev/null || true
        echo "[$timestamp] SERVICE_ENABLED: $service" >> "$HARDENING_LOG"
    done
    
    echo "[$timestamp] SERVICES_HARDENED: Services configured" >> "$HARDENING_LOG"
    log_message "INFO" "Service hardening completed"
}

# Log configuration hardening
harden_logging() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local rsyslog_config="/etc/rsyslog.d/99-cybrox.conf"
    
    backup_config "$rsyslog_config"
    
    # Create enhanced logging configuration
    cat > "$rsyslog_config" << 'EOF'
# CYBROX ENHANCED LOGGING CONFIGURATION

# Log all auth messages to auth.log
auth,authpriv.*          /var/log/auth.log

# Log all kernel messages to kern.log
kern.*                  /var/log/kern.log

# Log all mail messages
mail.*                  /var/log/maillog

# Log all cron messages
cron.*                  /var/log/cron

# Log all daemon messages
daemon.*                /var/log/daemon.log

# Log all user messages
user.*                  /var/log/user.log

# Log all security messages
security.*              /var/log/secure

# Log everything to syslog
*.*                     /var/log/syslog

# Log important messages to console
*.emerg                 :omusrmsg:*

# Create log rotation
$RepeatedMsgReduction on
$ActionQueueSize 1000000
$ActionQueueTimeoutDiscard 1000
$ActionQueueSaveOnShutdown on
EOF
    
    # Restart rsyslog
    systemctl restart rsyslog 2>/dev/null || true
    
    # Configure log rotation
    cat > "/etc/logrotate.d/cybrox" << 'EOF'
/var/log/cybrox/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOF
    
    echo "[$timestamp] LOGGING_HARDENED: Enhanced logging configured" >> "$HARDENING_LOG"
    log_message "INFO" "Logging hardening completed"
}

# Application hardening
harden_applications() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S"
    
    # Harden Apache if installed
    if command -v apache2 &> /dev/null; then
        backup_config "/etc/apache2/apache2.conf"
        
        # Add security headers
        cat >> "/etc/apache2/conf-available/security.conf" << 'EOF'
# CYBROX APACHE SECURITY CONFIGURATION
ServerTokens Prod
ServerSignature Off

# Security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Disable HTTP methods
<LimitExcept GET POST HEAD>
    Deny from all
</LimitExcept>

# Hide server information
ServerTokens Minimal
ServerSignature Off
EOF
        
        a2enconf security 2>/dev/null || true
        systemctl reload apache2 2>/dev/null || true
        
        echo "[$timestamp] APACHE_HARDENED: Security configuration applied" >> "$HARDENING_LOG"
    fi
    
    # Harden Nginx if installed
    if command -v nginx &> /dev/null; then
        backup_config "/etc/nginx/nginx.conf"
        
        # Add security configuration
        cat >> "/etc/nginx/conf.d/security.conf" << 'EOF'
# CYBROX NGINX SECURITY CONFIGURATION

# Security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Hide server version
server_tokens off;

# Disable server tokens
more_clear_headers Server;
more_clear_headers X-Powered-By;

# Limit request size
client_max_body_size 10M;

# Disable unwanted HTTP methods
if ($request_method !~ ^(GET|POST|HEAD)$ ) {
    return 405;
}
EOF
        
        systemctl reload nginx 2>/dev/null || true
        
        echo "[$timestamp] NGINX_HARDENED: Security configuration applied" >> "$HARDENING_LOG"
    fi
    
    log_message "INFO" "Application hardening completed"
}

# Security audit
security_audit() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local audit_report="${LOGS_DIR}/security_audit_$(date +%Y%m%d).txt"
    
    cat > "$audit_report" << EOF
CYBROX SECURITY AUDIT REPORT
Generated: $timestamp
Host: $SYSTEM_HOSTNAME
IP: $SYSTEM_IP

=== SYSTEM INFORMATION ===
OS: $(uname -a)
Kernel: $(uname -r)
Uptime: $(uptime -p)
Memory: $(free -h | grep Mem)
Disk: $(df -h /)

=== USER ACCOUNTS ===
$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1":"$3":"$6}' /etc/passwd)

=== OPEN PORTS ===
$(ss -tuln | grep LISTEN)

=== RUNNING SERVICES ===
$(systemctl list-units --type=service --state=running | head -20)

=== FIREWALL STATUS ===
$(iptables -L -n 2>/dev/null || ufw status verbose 2>/dev/null || echo "Firewall not configured")

=== RECENT LOGINS ===
$(last -n 10)

=== FAILED LOGINS ===
$(grep "Failed" /var/log/auth.log 2>/dev/null | tail -10 || echo "No failed logins found")

=== SECURITY RECOMMENDATIONS ===
1. Regularly update system packages
2. Monitor logs for suspicious activity
3. Use strong passwords and multi-factor authentication
4. Implement principle of least privilege
5. Regular security audits and penetration testing
6. Backup critical data regularly
7. Monitor network traffic for anomalies
8. Keep software up to date

EOF
    
    echo "[$timestamp] SECURITY_AUDIT: Audit report generated" >> "$HARDENING_LOG"
    log_message "INFO" "Security audit completed: $audit_report"
}

# Main system hardening function
system_hardening_main() {
    # Initialize if not done
    if [[ ! -f "$HARDENING_STATE" ]]; then
        init_system_hardening
    fi
    
    # Run hardening functions
    harden_ssh
    configure_firewall
    harden_kernel
    harden_users
    harden_permissions
    harden_services
    harden_logging
    harden_applications
    
    # Generate security audit
    security_audit
    
    log_message "INFO" "System hardening completed successfully"
}

# Export functions for main script
export -f init_system_hardening backup_config harden_ssh configure_firewall
export -f harden_kernel harden_users harden_permissions harden_services
export -f harden_logging harden_applications security_audit system_hardening_main
