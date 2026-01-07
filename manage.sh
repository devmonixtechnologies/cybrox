#!/bin/bash

# CYBROX INSTALLATION AND MANAGEMENT SCRIPT

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Script directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CYBROX_SCRIPT="${SCRIPT_DIR}/cybrox.sh"

# Print colored output
print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "INFO")  echo -e "${BLUE}[INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        "WARNING") echo -e "${YELLOW}[WARNING]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
    esac
}

# Check system requirements
check_system_requirements() {
    print_status "INFO" "Checking system requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "CYBROX must be installed and run as root"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("bash" "ps" "netstat" "ss" "awk" "grep" "sed" "find" "sort" "uniq" "head" "tail")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        print_status "ERROR" "Missing required commands: ${missing_commands[*]}"
        exit 1
    fi
    
    # Check OS compatibility
    if [[ ! -f /etc/os-release ]]; then
        print_status "WARNING" "Cannot determine OS version"
    else
        source /etc/os-release
        print_status "INFO" "Detected OS: $PRETTY_NAME"
    fi
    
    print_status "SUCCESS" "System requirements check passed"
}

# Install CYBROX
install_cybrox() {
    print_status "INFO" "Installing CYBROX Anti-Hacking System..."
    
    # Check if already installed
    if [[ -f "/usr/local/bin/cybrox" ]]; then
        print_status "WARNING" "CYBROX is already installed"
        read -p "Do you want to reinstall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    # Make main script executable
    chmod +x "$CYBROX_SCRIPT"
    
    # Create symlink for system-wide access
    ln -sf "$CYBROX_SCRIPT" "/usr/local/bin/cybrox"
    
    # Create systemd service
    create_systemd_service
    
    # Set up log rotation
    setup_log_rotation
    
    # Create configuration files
    setup_configuration
    
    print_status "SUCCESS" "CYBROX installation completed"
    print_status "INFO" "Start CYBROX with: systemctl start cybrox"
    print_status "INFO" "Enable auto-start with: systemctl enable cybrox"
}

# Create systemd service
create_systemd_service() {
    local service_file="/etc/systemd/system/cybrox.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=CYBROX Anti-Hacking System
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$CYBROX_SCRIPT
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
User=root
Group=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybrox

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$SCRIPT_DIR/logs $SCRIPT_DIR/temp $SCRIPT_DIR/config
ProtectHome=true
RemoveIPC=true

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_status "INFO" "Systemd service created"
}

# Setup log rotation
setup_log_rotation() {
    local logrotate_file="/etc/logrotate.d/cybrox"
    
    cat > "$logrotate_file" << EOF
${SCRIPT_DIR}/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload cybrox >/dev/null 2>&1 || true
    endscript
}
EOF
    
    print_status "INFO" "Log rotation configured"
}

# Setup configuration
setup_configuration() {
    # Create email configuration template
    local email_config="${SCRIPT_DIR}/config/email.conf"
    
    if [[ ! -f "$email_config" ]]; then
        cat > "$email_config" << EOF
# CYBROX Email Configuration
# Uncomment and configure to enable email alerts

#EMAIL_RECIPIENT="admin@example.com"
#EMAIL_SUBJECT_PREFIX="[CYBROX ALERT]"
#SMTP_SERVER="smtp.example.com"
#SMTP_PORT="587"
#SMTP_USER="your-email@example.com"
#SMTP_PASSWORD="your-password"
#SMTP_TLS="true"
EOF
        print_status "INFO" "Email configuration template created"
    fi
    
    # Set proper permissions
    chmod 755 "$SCRIPT_DIR"
    chmod 644 "${SCRIPT_DIR}/config/"*
    chmod 755 "${SCRIPT_DIR}/modules/"*
    
    print_status "INFO" "Configuration setup completed"
}

# Uninstall CYBROX
uninstall_cybrox() {
    print_status "INFO" "Uninstalling CYBROX Anti-Hacking System..."
    
    # Stop service if running
    if systemctl is-active --quiet cybrox 2>/dev/null; then
        systemctl stop cybrox
        print_status "INFO" "CYBROX service stopped"
    fi
    
    # Disable service
    if systemctl is-enabled --quiet cybrox 2>/dev/null; then
        systemctl disable cybrox
        print_status "INFO" "CYBROX service disabled"
    fi
    
    # Remove systemd service
    rm -f "/etc/systemd/system/cybrox.service"
    systemctl daemon-reload
    
    # Remove symlink
    rm -f "/usr/local/bin/cybrox"
    
    # Remove log rotation
    rm -f "/etc/logrotate.d/cybrox"
    
    print_status "SUCCESS" "CYBROX uninstalled successfully"
    print_status "INFO" "Configuration and logs preserved in $SCRIPT_DIR"
}

# Start CYBROX
start_cybrox() {
    print_status "INFO" "Starting CYBROX Anti-Hacking System..."
    
    if systemctl is-active --quiet cybrox 2>/dev/null; then
        print_status "WARNING" "CYBROX is already running"
        return 0
    fi
    
    systemctl start cybrox
    
    if systemctl is-active --quiet cybrox; then
        print_status "SUCCESS" "CYBROX started successfully"
        print_status "INFO" "View dashboard: ${SCRIPT_DIR}/dashboard.html"
        print_status "INFO" "View logs: journalctl -u cybrox -f"
    else
        print_status "ERROR" "Failed to start CYBROX"
        print_status "INFO" "Check logs: journalctl -u cybrox"
    fi
}

# Stop CYBROX
stop_cybrox() {
    print_status "INFO" "Stopping CYBROX Anti-Hacking System..."
    
    if ! systemctl is-active --quiet cybrox 2>/dev/null; then
        print_status "WARNING" "CYBROX is not running"
        return 0
    fi
    
    systemctl stop cybrox
    
    if ! systemctl is-active --quiet cybrox; then
        print_status "SUCCESS" "CYBROX stopped successfully"
    else
        print_status "ERROR" "Failed to stop CYBROX"
    fi
}

# Restart CYBROX
restart_cybrox() {
    print_status "INFO" "Restarting CYBROX Anti-Hacking System..."
    
    systemctl restart cybrox
    
    if systemctl is-active --quiet cybrox; then
        print_status "SUCCESS" "CYBROX restarted successfully"
    else
        print_status "ERROR" "Failed to restart CYBROX"
    fi
}

# Show CYBROX status
show_status() {
    print_status "INFO" "CYBROX Anti-Hacking System Status"
    echo
    
    # Service status
    if systemctl is-active --quiet cybrox 2>/dev/null; then
        print_status "SUCCESS" "Service Status: RUNNING"
    else
        print_status "ERROR" "Service Status: STOPPED"
    fi
    
    # Service enabled status
    if systemctl is-enabled --quiet cybrox 2>/dev/null; then
        print_status "INFO" "Auto-start: ENABLED"
    else
        print_status "WARNING" "Auto-start: DISABLED"
    fi
    
    echo
    
    # Recent alerts
    if [[ -f "${SCRIPT_DIR}/logs/alerts.log" ]]; then
        local alert_count=$(wc -l < "${SCRIPT_DIR}/logs/alerts.log")
        print_status "INFO" "Total Alerts: $alert_count"
        
        local critical_count=$(grep -c "CRITICAL" "${SCRIPT_DIR}/logs/alerts.log" 2>/dev/null || echo "0")
        if [[ $critical_count -gt 0 ]]; then
            print_status "ERROR" "Critical Alerts: $critical_count"
        fi
    fi
    
    # Dashboard availability
    if [[ -f "${SCRIPT_DIR}/dashboard.html" ]]; then
        print_status "SUCCESS" "Dashboard: Available at ${SCRIPT_DIR}/dashboard.html"
    else
        print_status "WARNING" "Dashboard: Not generated yet"
    fi
    
    echo
    
    # System resources
    print_status "INFO" "System Resources:"
    echo "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')"
    echo "  Memory Usage: $(free | awk 'NR==2{printf "%.1f%%", $3*100/$2}')"
    echo "  Disk Usage: $(df "${SCRIPT_DIR}" | awk 'NR==2 {print $5}')"
    echo "  Load Average: $(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')"
}

# Show logs
show_logs() {
    local log_type="${1:-all}"
    
    case "$log_type" in
        "all")
            journalctl -u cybrox -f
            ;;
        "alerts")
            if [[ -f "${SCRIPT_DIR}/logs/alerts.log" ]]; then
                tail -f "${SCRIPT_DIR}/logs/alerts.log"
            else
                print_status "ERROR" "Alerts log not found"
            fi
            ;;
        "security")
            if [[ -f "${SCRIPT_DIR}/logs/cybrox.log" ]]; then
                tail -f "${SCRIPT_DIR}/logs/cybrox.log"
            else
                print_status "ERROR" "Security log not found"
            fi
            ;;
        "network")
            if [[ -f "${SCRIPT_DIR}/logs/network_connections.log" ]]; then
                tail -f "${SCRIPT_DIR}/logs/network_connections.log"
            else
                print_status "ERROR" "Network log not found"
            fi
            ;;
        *)
            print_status "ERROR" "Unknown log type: $log_type"
            echo "Available log types: all, alerts, security, network"
            ;;
    esac
}

# Show help
show_help() {
    cat << EOF
CYBROX Anti-Hacking System - Management Script

Usage: $0 {install|uninstall|start|stop|restart|status|logs|help}

Commands:
    install     Install CYBROX system-wide
    uninstall   Remove CYBROX installation
    start       Start CYBROX service
    stop        Stop CYBROX service
    restart     Restart CYBROX service
    status      Show CYBROX status and statistics
    logs [type] Show logs (all, alerts, security, network)
    help        Show this help message

Examples:
    $0 install              # Install CYBROX
    $0 start                # Start the service
    $0 status               # Check status
    $0 logs alerts          # Follow alert logs
    $0 logs                 # Follow all logs

Dashboard: ${SCRIPT_DIR}/dashboard.html
Configuration: ${SCRIPT_DIR}/config/cybrox.conf

For more information, see the documentation.
EOF
}

# Main script logic
main() {
    case "${1:-help}" in
        "install")
            check_system_requirements
            install_cybrox
            ;;
        "uninstall")
            uninstall_cybrox
            ;;
        "start")
            start_cybrox
            ;;
        "stop")
            stop_cybrox
            ;;
        "restart")
            restart_cybrox
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs "${2:-all}"
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function
main "$@"
