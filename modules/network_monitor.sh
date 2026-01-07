#!/bin/bash

# NETWORK MONITOR MODULE
# Real-time network traffic monitoring and intrusion detection

# Network monitoring state file
readonly NETWORK_STATE="${TEMP_DIR}/network_state.tmp"
readonly CONNECTION_LOG="${LOGS_DIR}/network_connections.log"
readonly BLOCKED_IPS="${TEMP_DIR}/blocked_ips.tmp"

# Initialize network monitoring
init_network_monitor() {
    log_message "INFO" "Initializing network monitoring module"
    
    # Create state files
    touch "$NETWORK_STATE" "$CONNECTION_LOG" "$BLOCKED_IPS"
    
    # Initialize connection tracking
    declare -A connection_counts
    declare -A port_scan_counts
    declare -A last_seen
    
    # Save initial state
    declare -p connection_counts port_scan_counts last_seen > "$NETWORK_STATE"
}

# Monitor network connections
monitor_connections() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Get current connections
    local current_connections=$(ss -tuln | awk 'NR>1 {print $4":"$6}' | sort | uniq -c | sort -nr)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local count=$(echo "$line" | awk '{print $1}')
            local address=$(echo "$line" | awk '{print $2}')
            local ip=$(echo "$address" | cut -d':' -f1)
            local port=$(echo "$address" | cut -d':' -f2)
            
            # Log connection
            echo "[$timestamp] CONN: $count connections to $address" >> "$CONNECTION_LOG"
            
            # Check for suspicious activity
            if [[ $count -gt $MAX_CONNECTIONS_PER_IP ]]; then
                send_alert "HIGH" "Excessive connections: $count from $ip to port $port" "NETWORK_MONITOR"
                
                if [[ "$BLOCK_SUSPICIOUS_IPS" == "true" ]]; then
                    block_ip "$ip"
                fi
            fi
        fi
    done <<< "$current_connections"
}

# Detect port scans
detect_port_scan() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local scan_log="${TEMP_DIR}/port_scan.tmp"
    
    # Monitor for port scan patterns using tcpdump
    if command -v tcpdump &> /dev/null; then
        timeout 5 tcpdump -i "$SYSTEM_INTERFACE" -n -c 100 2>/dev/null | \
        awk '{print $3}' | cut -d'.' -f1-4 | sort | uniq -c | sort -nr > "$scan_log"
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local count=$(echo "$line" | awk '{print $1}')
                local ip=$(echo "$line" | awk '{print $2}')
                
                if [[ $count -gt $SUSPICIOUS_PORT_SCAN_THRESHOLD ]]; then
                    send_alert "CRITICAL" "Port scan detected: $count packets from $ip" "PORT_SCAN_DETECTION"
                    
                    if [[ "$BLOCK_SUSPICIOUS_IPS" == "true" ]]; then
                        block_ip "$ip"
                    fi
                fi
            fi
        done < "$scan_log"
        
        rm -f "$scan_log"
    fi
}

# Monitor bandwidth usage
monitor_bandwidth() {
    local interface="$SYSTEM_INTERFACE"
    local rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes")
    local tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes")
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Store current usage
    local usage_file="${TEMP_DIR}/bandwidth.tmp"
    echo "$timestamp,$rx_bytes,$tx_bytes" >> "$usage_file"
    
    # Keep only last 100 entries
    tail -n 100 "$usage_file" > "${usage_file}.new" && mv "${usage_file}.new" "$usage_file"
    
    # Calculate bandwidth rate
    if [[ -f "$usage_file" ]]; then
        local line_count=$(wc -l < "$usage_file")
        if [[ $line_count -gt 1 ]]; then
            local last_line=$(tail -n 1 "$usage_file")
            local prev_line=$(tail -n 2 "$usage_file" | head -n 1)
            
            local last_rx=$(echo "$last_line" | cut -d',' -f2)
            local prev_rx=$(echo "$prev_line" | cut -d',' -f2)
            local last_tx=$(echo "$last_line" | cut -d',' -f3)
            local prev_tx=$(echo "$prev_line" | cut -d',' -f3)
            
            local rx_rate=$(( (last_rx - prev_rx) / MONITORING_INTERVAL ))
            local tx_rate=$(( (last_tx - prev_tx) / MONITORING_INTERVAL ))
            
            # Alert on unusual bandwidth usage
            if [[ $rx_rate -gt 1048576 ]] || [[ $tx_rate -gt 1048576 ]]; then  # 1MB/s
                send_alert "MEDIUM" "High bandwidth usage detected: RX=$((rx_rate/1024))KB/s, TX=$((tx_rate/1024))KB/s" "BANDWIDTH_MONITOR"
            fi
        fi
    fi
}

# Block IP address
block_ip() {
    local ip="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Check if already blocked
    if grep -q "$ip" "$BLOCKED_IPS" 2>/dev/null; then
        return 0
    fi
    
    # Block using iptables
    if command -v iptables &> /dev/null; then
        iptables -A INPUT -s "$ip" -j DROP 2>/dev/null || true
        iptables -A FORWARD -s "$ip" -j DROP 2>/dev/null || true
    fi
    
    # Add to blocked list
    echo "$timestamp,$ip" >> "$BLOCKED_IPS"
    
    log_message "INFO" "Blocked IP: $ip"
    send_alert "MEDIUM" "IP $ip has been blocked" "IP_BLOCKING"
}

# Unblock IP address
unblock_ip() {
    local ip="$1"
    
    # Remove from iptables
    if command -v iptables &> /dev/null; then
        iptables -D INPUT -s "$ip" -j DROP 2>/dev/null || true
        iptables -D FORWARD -s "$ip" -j DROP 2>/dev/null || true
    fi
    
    # Remove from blocked list
    grep -v "$ip" "$BLOCKED_IPS" > "${BLOCKED_IPS}.tmp" 2>/dev/null || true
    mv "${BLOCKED_IPS}.tmp" "$BLOCKED_IPS" 2>/dev/null || true
    
    log_message "INFO" "Unblocked IP: $ip"
}

# Clean up old blocked IPs
cleanup_blocked_ips() {
    local current_time=$(date +%s)
    local temp_file="${BLOCKED_IPS}.tmp"
    
    while IFS=',' read -r timestamp ip; do
        local block_time=$(date -d "$timestamp" +%s 2>/dev/null || echo 0)
        local age=$((current_time - block_time))
        
        if [[ $age -gt $BLOCK_IP_DURATION ]]; then
            unblock_ip "$ip"
        fi
    done < "$BLOCKED_IPS"
}

# Monitor specific ports
monitor_ports() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local ports_log="${TEMP_DIR}/ports.tmp"
    
    # Check monitored ports
    IFS=',' read -ra PORTS <<< "$MONITOR_PORTS"
    for port in "${PORTS[@]}"; do
        local connections=$(ss -tn | grep ":$port " | wc -l)
        
        if [[ $connections -gt 0 ]]; then
            echo "[$timestamp] Port $port: $connections active connections" >> "$ports_log"
            
            # Check for unusual activity on sensitive ports
            case "$port" in
                22|2222)  # SSH
                    if [[ $connections -gt 10 ]]; then
                        send_alert "MEDIUM" "High SSH activity: $connections connections" "PORT_MONITOR"
                    fi
                    ;;
                23)      # Telnet
                    send_alert "HIGH" "Telnet activity detected: $connections connections" "PORT_MONITOR"
                    ;;
                3389)    # RDP
                    if [[ $connections -gt 5 ]]; then
                        send_alert "MEDIUM" "High RDP activity: $connections connections" "PORT_MONITOR"
                    fi
                    ;;
            esac
        fi
    done
}

# Detect DDoS attacks
detect_ddos() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local connection_file="${TEMP_DIR}/ddos.tmp"
    
    # Get connection statistics
    ss -tn | awk '{print $4}' | cut -d':' -f1 | sort | uniq -c | sort -nr > "$connection_file"
    
    local total_connections=$(wc -l < "$connection_file")
    local unique_ips=$(wc -l < "$connection_file")
    
    # DDoS detection logic
    if [[ $total_connections -gt 1000 ]] && [[ $unique_ips -lt 100 ]]; then
        local avg_connections=$((total_connections / unique_ips))
        
        if [[ $avg_connections -gt 50 ]]; then
            send_alert "CRITICAL" "Potential DDoS attack detected: $total_connections total connections from $unique_ips unique IPs" "DDOS_DETECTION"
            
            # Block top offending IPs
            head -n 10 "$connection_file" | while IFS= read -r line; do
                local ip=$(echo "$line" | awk '{print $2}')
                block_ip "$ip"
            done
        fi
    fi
    
    rm -f "$connection_file"
}

# Main network monitoring function
network_monitor_main() {
    if [[ "$NETWORK_MONITOR_ENABLED" != "true" ]]; then
        return 0
    fi
    
    # Initialize if not done
    if [[ ! -f "$NETWORK_STATE" ]]; then
        init_network_monitor
    fi
    
    # Run monitoring functions
    monitor_connections
    detect_port_scan
    monitor_bandwidth
    monitor_ports
    detect_ddos
    cleanup_blocked_ips
}

# Export functions for main script
export -f init_network_monitor monitor_connections detect_port_scan monitor_bandwidth
export -f block_ip unblock_ip cleanup_blocked_ips monitor_ports detect_ddos network_monitor_main
