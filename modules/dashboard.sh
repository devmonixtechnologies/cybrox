#!/bin/bash

# DASHBOARD AND REPORTING MODULE
# Real-time security dashboard and comprehensive reporting system

# Dashboard state files
readonly DASHBOARD_STATE="${TEMP_DIR}/dashboard_state.tmp"
readonly DASHBOARD_LOG="${LOGS_DIR}/dashboard.log"
readonly REPORTS_DIR="${SCRIPT_DIR}/reports"
readonly HTML_DASHBOARD="${SCRIPT_DIR}/dashboard.html"

# Initialize dashboard system
init_dashboard() {
    log_message "INFO" "Initializing dashboard and reporting module"
    
    # Create directories
    mkdir -p "$REPORTS_DIR"
    
    # Create state files
    touch "$DASHBOARD_STATE" "$DASHBOARD_LOG"
    
    # Initialize tracking variables
    declare -A dashboard_metrics
    declare -A report_data
    declare -A last_update
    declare -A alert_counts
    
    # Save initial state
    declare -p dashboard_metrics report_data last_update alert_counts > "$DASHBOARD_STATE"
}

# Generate security metrics
generate_metrics() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local metrics_file="${TEMP_DIR}/security_metrics.tmp"
    
    # System metrics
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local mem_usage=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    # Security metrics
    local total_alerts=$(wc -l < "$ALERT_LOG" 2>/dev/null || echo 0)
    local critical_alerts=$(grep -c "CRITICAL" "$ALERT_LOG" 2>/dev/null || echo 0)
    local high_alerts=$(grep -c "HIGH" "$ALERT_LOG" 2>/dev/null || echo 0)
    local blocked_ips=$(wc -l < "$BLOCKED_IPS" 2>/dev/null || echo 0)
    local running_processes=$(ps aux | wc -l)
    local network_connections=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || echo 0)
    
    # Log metrics
    cat > "$metrics_file" << EOF
{
    "timestamp": "$timestamp",
    "system": {
        "cpu_usage": "$cpu_usage",
        "memory_usage": "$mem_usage",
        "disk_usage": "$disk_usage",
        "load_average": "$load_avg"
    },
    "security": {
        "total_alerts": "$total_alerts",
        "critical_alerts": "$critical_alerts",
        "high_alerts": "$high_alerts",
        "blocked_ips": "$blocked_ips",
        "running_processes": "$running_processes",
        "network_connections": "$network_connections"
    }
}
EOF
    
    echo "$timestamp,$cpu_usage,$mem_usage,$disk_usage,$load_avg,$total_alerts,$critical_alerts,$high_alerts,$blocked_ips,$running_processes,$network_connections" >> "$DASHBOARD_LOG"
    
    echo "$metrics_file"
}

# Generate HTML dashboard
generate_html_dashboard() {
    local metrics_file="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Read metrics
    local cpu_usage=$(grep -o '"cpu_usage": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local mem_usage=$(grep -o '"memory_usage": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local disk_usage=$(grep -o '"disk_usage": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local load_avg=$(grep -o '"load_average": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local total_alerts=$(grep -o '"total_alerts": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local critical_alerts=$(grep -o '"critical_alerts": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local high_alerts=$(grep -o '"high_alerts": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local blocked_ips=$(grep -o '"blocked_ips": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local running_processes=$(grep -o '"running_processes": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    local network_connections=$(grep -o '"network_connections": "[^"]*"' "$metrics_file" | cut -d'"' -f4)
    
    # Generate recent alerts
    local recent_alerts=$(tail -n 10 "$ALERT_LOG" 2>/dev/null | sed 's/"/\&quot;/g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g' | awk '{print "<tr><td>" $1 "</td><td>" $2 "</td><td>" $3 "</td><td>" $4 "</td><td>" substr($0, index($0,$5)) "</td></tr>"}')
    
    # Generate recent log entries
    local recent_logs=$(tail -n 10 "$LOG_FILE" 2>/dev/null | sed 's/"/\&quot;/g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g' | awk '{print "<tr><td>" $1 "</td><td>" $2 "</td><td>" substr($0, index($0,$3)) "</td></tr>"}')
    
    # Create HTML dashboard
    cat > "$HTML_DASHBOARD" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CYBROX Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #fff; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .container { max-width: 1400px; margin: 20px auto; padding: 0 20px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: #2a2a2a; border-radius: 10px; padding: 20px; border-left: 4px solid #667eea; }
        .metric-card h3 { color: #667eea; margin-bottom: 10px; }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { opacity: 0.7; }
        .critical { border-left-color: #e74c3c; }
        .critical h3 { color: #e74c3c; }
        .warning { border-left-color: #f39c12; }
        .warning h3 { color: #f39c12; }
        .success { border-left-color: #27ae60; }
        .success h3 { color: #27ae60; }
        .info { border-left-color: #3498db; }
        .info h3 { color: #3498db; }
        .tables-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .table-card { background: #2a2a2a; border-radius: 10px; padding: 20px; }
        .table-card h3 { margin-bottom: 15px; color: #667eea; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #444; }
        th { background: #333; font-weight: 600; }
        tr:hover { background: #333; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 10px; }
        .status-ok { background: #27ae60; }
        .status-warning { background: #f39c12; }
        .status-critical { background: #e74c3c; }
        .refresh-info { text-align: center; opacity: 0.7; margin-top: 20px; }
        .progress-bar { width: 100%; height: 20px; background: #333; border-radius: 10px; overflow: hidden; margin-top: 10px; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); transition: width 0.3s ease; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CYBROX Security Dashboard</h1>
        <p>Real-time Security Monitoring and Threat Detection</p>
        <p><strong>Host:</strong> $SYSTEM_HOSTNAME | <strong>IP:</strong> $SYSTEM_IP | <strong>Last Updated:</strong> $timestamp</p>
    </div>
    
    <div class="container">
        <div class="metrics-grid">
            <div class="metric-card info">
                <h3>🖥️ System Status</h3>
                <div class="metric-value" id="system-status">ONLINE</div>
                <div class="metric-label">System Operational</div>
            </div>
            
            <div class="metric-card $([ "$critical_alerts" -gt 0 ] && echo "critical" || ([ "$high_alerts" -gt 0 ] && echo "warning" || echo "success"))">
                <h3>🚨 Security Alerts</h3>
                <div class="metric-value">$total_alerts</div>
                <div class="metric-label">Total Alerts (Critical: $critical_alerts, High: $high_alerts)</div>
            </div>
            
            <div class="metric-card $([ "$cpu_usage" -gt 80 ] && echo "warning" || "success")">
                <h3>💻 CPU Usage</h3>
                <div class="metric-value">${cpu_usage}%</div>
                <div class="metric-label">Processor Load</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${cpu_usage}%"></div>
                </div>
            </div>
            
            <div class="metric-card $([ "$mem_usage" -gt 80 ] && echo "warning" || "success")">
                <h3>🧠 Memory Usage</h3>
                <div class="metric-value">${mem_usage}%</div>
                <div class="metric-label">RAM Utilization</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${mem_usage}%"></div>
                </div>
            </div>
            
            <div class="metric-card $([ "$disk_usage" -gt 90 ] && echo "critical" || ([ "$disk_usage" -gt 80 ] && echo "warning" || "success"))">
                <h3>💾 Disk Usage</h3>
                <div class="metric-value">${disk_usage}%</div>
                <div class="metric-label">Storage Utilization</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${disk_usage}%"></div>
                </div>
            </div>
            
            <div class="metric-card info">
                <h3>⚡ Load Average</h3>
                <div class="metric-value">$load_avg</div>
                <div class="metric-label">System Load</div>
            </div>
            
            <div class="metric-card warning">
                <h3>🚫 Blocked IPs</h3>
                <div class="metric-value">$blocked_ips</div>
                <div class="metric-label">Malicious Addresses</div>
            </div>
            
            <div class="metric-card info">
                <h3>🔄 Network Connections</h3>
                <div class="metric-value">$network_connections</div>
                <div class="metric-label">Active Connections</div>
            </div>
        </div>
        
        <div class="tables-grid">
            <div class="table-card">
                <h3>📊 Recent Security Alerts</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Level</th>
                            <th>Source</th>
                            <th>Alert</th>
                        </tr>
                    </thead>
                    <tbody>
                        $recent_alerts
                    </tbody>
                </table>
            </div>
            
            <div class="table-card">
                <h3>📝 System Log</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Level</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        $recent_logs
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="refresh-info">
            <p>🔄 Dashboard auto-refreshes every 30 seconds | CYBROX Anti-Hacking System v1.0</p>
        </div>
    </div>
    
    <script>
        // Auto-refresh dashboard every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
        
        // Add real-time updates simulation
        setInterval(function() {
            const statusElement = document.getElementById('system-status');
            statusElement.style.opacity = '0.5';
            setTimeout(function() {
                statusElement.style.opacity = '1';
            }, 500);
        }, 5000);
    </script>
</body>
</html>
EOF
    
    log_message "INFO" "HTML dashboard generated: $HTML_DASHBOARD"
}

# Generate comprehensive security report
generate_security_report() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local report_file="${REPORTS_DIR}/security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
=================================================================
                    CYBROX SECURITY REPORT
=================================================================

Report Generated: $timestamp
System Hostname: $SYSTEM_HOSTNAME
System IP: $SYSTEM_IP
Report Type: Comprehensive Security Analysis

=================================================================
EXECUTIVE SUMMARY
=================================================================

This report provides a comprehensive analysis of the current security
status of the system monitored by CYBROX Anti-Hacking System.

System Status: OPERATIONAL
Security Level: $CURRENT_SECURITY_LEVEL
Monitoring Duration: $(ps -o etime= -p $(cat "$PID_FILE" 2>/dev/null || echo "0") 2>/dev/null || echo "Unknown")

=================================================================
SYSTEM METRICS
=================================================================

CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
Memory Usage: $(free | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
Disk Usage: $(df / | awk 'NR==2 {print $5}')
Load Average: $(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
Running Processes: $(ps aux | wc -l)
Network Connections: $(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || echo "0")

=================================================================
SECURITY METRICS
=================================================================

Total Security Alerts: $(wc -l < "$ALERT_LOG" 2>/dev/null || echo "0")
Critical Alerts: $(grep -c "CRITICAL" "$ALERT_LOG" 2>/dev/null || echo "0")
High Priority Alerts: $(grep -c "HIGH" "$ALERT_LOG" 2>/dev/null || echo "0")
Medium Priority Alerts: $(grep -c "MEDIUM" "$ALERT_LOG" 2>/dev/null || echo "0")
Low Priority Alerts: $(grep -c "LOW" "$ALERT_LOG" 2>/dev/null || echo "0")

Blocked IP Addresses: $(wc -l < "$BLOCKED_IPS" 2>/dev/null || echo "0")
File Integrity Violations: $(wc -l < "$CHANGES_LOG" 2>/dev/null || echo "0")
Suspicious Processes Detected: $(wc -l < "$SUSPICIOUS_LOG" 2>/dev/null || echo "0")
Network Intrusions Detected: $(wc -l < "$INTRUSION_LOG" 2>/dev/null || echo "0")

=================================================================
RECENT SECURITY EVENTS
=================================================================

$(tail -n 20 "$ALERT_LOG" 2>/dev/null || echo "No recent alerts")

=================================================================
SYSTEM HEALTH ANALYSIS
=================================================================

Disk Space Analysis:
$(df -h | head -10)

Memory Analysis:
$(free -h)

Process Analysis:
$(ps aux --no-headers | awk '{print $11}' | sort | uniq -c | sort -nr | head -10)

Network Analysis:
$(netstat -tuln 2>/dev/null | head -10 || ss -tuln | head -10)

=================================================================
SECURITY RECOMMENDATIONS
=================================================================

1. IMMEDIATE ACTIONS REQUIRED:
$(if [[ $(grep -c "CRITICAL" "$ALERT_LOG" 2>/dev/null || echo "0") -gt 0 ]]; then
    echo "   - Address $(grep -c "CRITICAL" "$ALERT_LOG" 2>/dev/null || echo "0") critical security alerts immediately"
    echo "   - Review blocked IP addresses and update firewall rules"
    echo "   - Investigate suspicious processes and file changes"
else
    echo "   - No immediate critical actions required"
fi)

2. SYSTEM HARDENING:
   - Review and update system passwords
   - Implement multi-factor authentication where possible
   - Regularly update system packages and security patches
   - Review user accounts and remove unnecessary access

3. MONITORING ENHANCEMENT:
   - Consider increasing log retention periods
   - Implement additional monitoring for critical services
   - Set up automated backup and recovery procedures

4. COMPLIANCE AND AUDITING:
   - Regular security audits and penetration testing
   - Document security policies and procedures
   - Train staff on security best practices

=================================================================
THREAT INTELLIGENCE
=================================================================

Top Attack Sources:
$(awk '{print $8}' "$ALERT_LOG" 2>/dev/null | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -nr | head -5 || echo "No attack sources identified")

Most Common Attack Types:
$(awk '{print $5}' "$ALERT_LOG" 2>/dev/null | sort | uniq -c | sort -nr | head -5 || echo "No attack patterns identified")

=================================================================
APPENDICES
=================================================================

A. SYSTEM CONFIGURATION
$(uname -a)

B. INSTALLED SECURITY TOOLS
$(which iptables ufw fail2ban auditd 2>/dev/null || echo "Security tools not found")

C. LOG ANALYSIS SUMMARY
Total Log Entries: $(wc -l < "$LOG_FILE" 2>/dev/null || echo "0")
Log File Size: $(du -h "$LOG_FILE" 2>/dev/null | cut -f1 || echo "Unknown")

D. NETWORK CONFIGURATION
$(ip addr show 2>/dev/null | head -20 || ifconfig 2>/dev/null | head -20 || echo "Network configuration not available")

=================================================================
REPORT CONCLUSION
=================================================================

The CYBROX Anti-Hacking System has been actively monitoring the system
and has detected $(wc -l < "$ALERT_LOG" 2>/dev/null || echo "0") security events during this reporting period.

Overall Security Status: $([[ $(grep -c "CRITICAL" "$ALERT_LOG" 2>/dev/null || echo "0") -gt 0 ]] && echo "ATTENTION REQUIRED" || echo "SECURE")

Next Report: $(date -d "+1 hour" +"%Y-%m-%d %H:%M:%S")

For questions or concerns, contact your security administrator.

=================================================================
End of Report - CYBROX Anti-Hacking System
=================================================================
EOF
    
    log_message "INFO" "Security report generated: $report_file"
    echo "$report_file"
}

# Generate threat intelligence report
generate_threat_report() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local threat_file="${REPORTS_DIR}/threat_intelligence_$(date +%Y%m%d).txt"
    
    cat > "$threat_file" << EOF
=================================================================
                CYBROX THREAT INTELLIGENCE REPORT
=================================================================

Generated: $timestamp
Analysis Period: Last 24 hours

=================================================================
THREAT OVERVIEW
=================================================================

Total Threat Events: $(wc -l < "$THREAT_LOG" 2>/dev/null || echo "0")
Critical Threats: $(grep -c "CRITICAL" "$THREAT_LOG" 2>/dev/null || echo "0")
High Priority Threats: $(grep -c "HIGH" "$THREAT_LOG" 2>/dev/null || echo "0")

=================================================================
ATTACK PATTERNS
=================================================================

$(awk '{print $4}' "$THREAT_LOG" 2>/dev/null | sort | uniq -c | sort -nr | head -10 || echo "No attack patterns detected")

=================================================================
MALICIOUS INDICATORS
=================================================================

Suspicious IP Addresses:
$(awk '{print $0}' "$ALERT_LOG" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -nr | head -10 || echo "No suspicious IPs detected")

Suspicious Processes:
$(awk '{print $0}' "$SUSPICIOUS_LOG" 2>/dev/null | grep -oE '[a-zA-Z0-9_-]+' | sort | uniq -c | sort -nr | head -10 || echo "No suspicious processes detected")

=================================================================
RECOMMENDATIONS
=================================================================

1. Block identified malicious IP addresses
2. Update intrusion detection signatures
3. Review and patch vulnerable services
4. Enhance monitoring for identified attack patterns

=================================================================
End of Threat Intelligence Report
=================================================================
EOF
    
    log_message "INFO" "Threat intelligence report generated: $threat_file"
}

# Main dashboard function
dashboard_main() {
    # Initialize if not done
    if [[ ! -f "$DASHBOARD_STATE" ]]; then
        init_dashboard
    fi
    
    # Generate metrics
    local metrics_file=$(generate_metrics)
    
    # Generate HTML dashboard
    generate_html_dashboard "$metrics_file"
    
    # Generate reports hourly
    if (( $(date +%s) % 3600 == 0 )); then
        generate_security_report
        generate_threat_report
    fi
    
    # Cleanup old metrics
    rm -f "$metrics_file"
    
    log_message "INFO" "Dashboard updated successfully"
}

# Export functions for main script
export -f init_dashboard generate_metrics generate_html_dashboard
export -f generate_security_report generate_threat_report dashboard_main
