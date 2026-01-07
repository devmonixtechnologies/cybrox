#!/bin/bash

# SPYWARE DETECTION AND PRIVACY PROTECTION MODULE
# Advanced spyware detection, privacy protection, and data leak prevention

# Spyware detection state files
readonly SPYWARE_STATE="${TEMP_DIR}/spyware_state.tmp"
readonly SPYWARE_LOG="${LOGS_DIR}/spyware_detection.log"
readonly PRIVACY_LOG="${LOGS_DIR}/privacy_protection.log"
readonly SPYWARE_SIGNATURES="${CONFIG_DIR}/spyware_signatures.db"
readonly PRIVACY_RULES="${CONFIG_DIR}/privacy_rules.db"

# Initialize spyware detection
init_spyware_detection() {
    log_message "INFO" "Initializing spyware detection and privacy protection module"
    
    # Create state files
    touch "$SPYWARE_STATE" "$SPYWARE_LOG" "$PRIVACY_LOG"
    
    # Create signature databases if not exists
    if [[ ! -f "$SPYWARE_SIGNATURES" ]]; then
        create_spyware_signatures
    fi
    
    if [[ ! -f "$PRIVACY_RULES" ]]; then
        create_privacy_rules
    fi
    
    # Initialize tracking variables
    declare -A detected_spyware
    declare -A privacy_violations
    declare -A data_leak_events
    declare -A monitoring_timestamps
    
    # Save initial state
    declare -p detected_spyware privacy_violations data_leak_events monitoring_timestamps > "$SPYWARE_STATE"
}

# Create comprehensive spyware signature database
create_spyware_signatures() {
    cat > "$SPYWARE_SIGNATURES" << 'EOF'
# SPYWARE SIGNATURE DATABASE
# Format: signature_name|spyware_type|signature_pattern|severity|description

# Commercial Spyware
FINSPIRE_SPYWARE|commercial|finfire|critical|FinFisher surveillance spyware
HACKINGTEAM_SPYWARE|commercial|hackingteam|critical|HackingTeam RCS spyware
NSO_PEGASUS_SPYWARE|commercial|pegasus|critical|NSO Group Pegasus spyware
CITIZENLAB_SPYWARE|commercial|citizenlab|high|Citizen Lab identified spyware
FINSPY_SPYWARE|commercial|finspy|critical|FinSpy commercial spyware
REMEXI_SPYWARE|commercial|remexi|high|Remexi surveillance spyware
MOKSEC_SPYWARE|commercial|moksec|high|MokSec surveillance tools
WEBWEAVER_SPYWARE|commercial|webweaver|high|WebWeaver surveillance platform

# Government Spyware
CANDIRU_SPYWARE|government|candiru|critical|Candiru government spyware
MORPHISec_SPYWARE|government|morphisec|high|Morphisec government tools
ZERODIUM_SPYWARE|government|zerodium|high|Zerodium exploit tools
EXETER_SPYWARE|government|exeter|critical|Exeter government spyware
MERCURY_SPYWARE|government|mercury|critical|Mercury government spyware
STRONTIUM_SPYWARE|government|strontium|critical|Strontium APT spyware
PHOSPHORUS_SPYWARE|government|phosphorus|high|Phosphorus APT spyware
TURBINE_SPYWARE|government|turbine|high|Turbine surveillance tools

# Mobile Spyware
ANDROID_SPYWARE|mobile|android|medium|Android spyware signatures
IOS_SPYWARE|mobile|ios|medium|iOS spyware signatures
FLUXXY_SPYWARE|mobile|fluxxy|high|Fluxxy mobile spyware
MUMU_SPYWARE|mobile|mumu|high|Mumu mobile spyware
BANDOOK_SPYWARE|mobile|bandook|high|Bandook mobile spyware

# Keyloggers
ARDA_KEYLOGGER|keylogger|arda|high|Arda keylogger family
REFOG_KEYLOGGER|keylogger|refog|medium|Refog keylogger
ACTUAL_SPYWARE|keylogger|actualspy|medium|ActualSpy keylogger
BLAZINGTOOLS_KEYLOGGER|keylogger|blazingtools|medium|BlazingTools keylogger
REVEALER_KEYLOGGER|keylogger|revealer|medium|Revealer keylogger
SPYAGENT_KEYLOGGER|keylogger|spyagent|medium|SpyAgent keylogger

# Webcam Spyware
WEBCAM_SPYWARE|webcam|webcam|high|Webcam surveillance spyware
CAMCAPTURE_SPYWARE|webcam|camcapture|high|Camera capture spyware
VIDEOREG_SPYWARE|webcam|videoreg|high|VideoReg webcam spyware
WEBCAMHACK_SPYWARE|webcam|webcamhack|critical|Webcam hacking tools

# Microphone Spyware
MICROPHONE_SPYWARE|microphone|microphone|high|Microphone surveillance
AUDIOCAPTURE_SPYWARE|microphone|audiocapture|high|Audio capture spyware
VOICEREC_SPYWARE|microphone|voicerec|high|Voice recording spyware

# Screen Capture Spyware
SCREEN_SPYWARE|screen|screen|high|Screen capture spyware
DESKTOP_SPYWARE|screen|desktop|high|Desktop monitoring spyware
REMOTE_SPYWARE|screen|remote|high|Remote desktop spyware
VNC_SPYWARE|screen|vnc|medium|VNC-based spyware

# Data Stealing Spyware
INFOSTEALER_SPYWARE|infostealer|infostealer|high|Information stealing spyware
PASSWORD_SPYWARE|infostealer|password|high|Password stealing spyware
BROWSER_SPYWARE|infostealer|browser|high|Browser data stealing spyware
EMAIL_SPYWARE|infostealer|email|high|Email stealing spyware
CRYPTO_SPYWARE|infostealer|crypto|high|Cryptocurrency stealing spyware

# Network Spyware
NETWORK_SPYWARE|network|network|high|Network traffic monitoring
PACKET_SPYWARE|network|packet|high|Packet capture spyware
DNS_SPYWARE|network|dns|medium|DNS monitoring spyware
PROXY_SPYWARE|network|proxy|medium|Proxy-based spyware

# File System Spyware
FILE_SPYWARE|filesystem|file|medium|File system monitoring
CLIPBOARD_SPYWARE|filesystem|clipboard|medium|Clipboard monitoring spyware
PRINT_SPYWARE|filesystem|print|medium|Print job monitoring spyware

# Browser Spyware
BROWSER_PLUGIN_SPYWARE|browser|plugin|medium|Browser plugin spyware
BROWSER_EXTENSION_SPYWARE|browser|extension|medium|Browser extension spyware
BROWSER_HELPER_SPYWARE|browser|helper|medium|Browser helper object spyware
COOKIE_SPYWARE|browser|cookie|low|Cookie tracking spyware

# Advanced Spyware Techniques
ROOTKIT_SPYWARE|advanced|rootkit|critical|Rootkit-based spyware
BOOTKIT_SPYWARE|advanced|bootkit|critical|Bootkit-based spyware
FIRMWARE_SPYWARE|advanced|firmware|critical|Firmware-based spyware
HARDWARE_SPYWARE|advanced|hardware|critical|Hardware-based spyware
EOF
    
    log_message "INFO" "Spyware signature database created: $SPYWARE_SIGNATURES"
}

# Create privacy protection rules
create_privacy_rules() {
    cat > "$PRIVACY_RULES" << 'EOF'
# PRIVACY PROTECTION RULES DATABASE
# Format: rule_name|rule_type|condition|action|severity|description

# Data Protection Rules
PERSONAL_DATA_PROTECTION|data|personal_data_access|block|high|Block access to personal data files
FINANCIAL_DATA_PROTECTION|data|financial_data_access|block|critical|Block access to financial data
MEDICAL_DATA_PROTECTION|data|medical_data_access|block|critical|Block access to medical data
IDENTITY_DATA_PROTECTION|data|identity_data_access|block|critical|Block access to identity documents

# Network Privacy Rules
DATA_EXFILTRATION_BLOCK|network|data_exfiltration|block|critical|Block data exfiltration attempts
PRIVACY_VIOLATION_BLOCK|network|privacy_violation|block|high|Block privacy violation attempts
TRACKING_BLOCK|network|tracking_activity|block|medium|Block tracking activity
TELEMETRY_BLOCK|network|telemetry_data|block|medium|Block telemetry data transmission

# Application Privacy Rules
CAMERA_PROTECTION|application|camera_access|block|high|Block unauthorized camera access
MICROPHONE_PROTECTION|application|microphone_access|block|high|Block unauthorized microphone access
LOCATION_PROTECTION|application|location_access|block|medium|Block unauthorized location access
CONTACTS_PROTECTION|application|contacts_access|block|medium|Block unauthorized contacts access

# File System Privacy Rules
TEMP_FILE_MONITORING|filesystem|temp_file_access|log|low|Monitor temporary file access
SYSTEM_FILE_PROTECTION|filesystem|system_file_access|block|high|Block unauthorized system file access
USER_FILE_PROTECTION|filesystem|user_file_access|log|medium|Log user file access attempts
CONFIG_FILE_PROTECTION|filesystem|config_file_access|block|medium|Block config file access

# Process Privacy Rules
KEYLOGGER_DETECTION|process|keylogger_activity|block|critical|Block keylogger processes
SCREEN_CAPTURE_DETECTION|process|screen_capture|block|high|Block screen capture processes
NETWORK_MONITORING_DETECTION|process|network_monitor|log|medium|Log network monitoring processes
FILE_MONITORING_DETECTION|process|file_monitor|log|medium|Log file monitoring processes

# Device Privacy Rules
USB_DEVICE_PROTECTION|device|usb_access|block|medium|Block unauthorized USB device access
BLUETOOTH_PROTECTION|device|bluetooth_access|block|medium|Block unauthorized Bluetooth access
WEBCAM_PROTECTION|device|webcam_access|block|high|Block unauthorized webcam access
MICROPHONE_DEVICE_PROTECTION|device|microphone_access|block|high|Block unauthorized microphone access

# Browser Privacy Rules
COOKIE_PROTECTION|browser|cookie_access|log|low|Log cookie access
HISTORY_PROTECTION|browser|history_access|log|low|Log browser history access
PASSWORD_PROTECTION|browser|password_access|block|high|Block password manager access
BOOKMARK_PROTECTION|browser|bookmark_access|log|low|Log bookmark access

# Communication Privacy Rules
EMAIL_PROTECTION|communication|email_access|block|high|Block unauthorized email access
CHAT_PROTECTION|communication|chat_access|block|medium|Block unauthorized chat access
CALL_PROTECTION|communication|call_access|block|high|Block unauthorized call access
SMS_PROTECTION|communication|sms_access|block|medium|Block unauthorized SMS access

# Cloud Privacy Rules
CLOUD_SYNC_PROTECTION|cloud|cloud_sync|block|medium|Block unauthorized cloud sync
CLOUD_BACKUP_PROTECTION|cloud|cloud_backup|block|high|Block unauthorized cloud backup
CLOUD_STORAGE_PROTECTION|cloud|cloud_storage|log|medium|Log cloud storage access
CLOUD_SHARING_PROTECTION|cloud|cloud_sharing|block|high|Block unauthorized cloud sharing

# Advanced Privacy Rules
BEHAVIORAL_ANALYSIS|advanced|behavioral_tracking|log|medium|Log behavioral tracking
BIOMETRIC_PROTECTION|advanced|biometric_access|block|critical|Block biometric data access
VOICE_PATTERN_PROTECTION|advanced|voice_pattern|block|high|Block voice pattern analysis
FACIAL_RECOGNITION_PROTECTION|advanced|facial_recognition|block|high|Block facial recognition access
EOF
    
    log_message "INFO" "Privacy protection rules database created: $PRIVACY_RULES"
}

# Detect spyware processes
detect_spyware_processes() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local suspicious_processes=$(ps aux --no-headers)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local pid=$(echo "$line" | awk '{print $2}')
            local user=$(echo "$line" | awk '{print $1}')
            local cmd=$(echo "$line" | awk '{print $11}')
            local full_cmd=$(echo "$line" | cut -d' ' -f11-)
            
            # Check for spyware signatures in process name
            while IFS='|' read -r signature_name spyware_type signature_pattern severity description; do
                if [[ "$signature_name" =~ ^# ]] || [[ -z "$signature_name" ]]; then
                    continue
                fi
                
                if echo "$cmd" | grep -iq "$signature_pattern" || echo "$full_cmd" | grep -iq "$signature_pattern"; then
                    log_spyware_detection "$signature_name" "$spyware_type" "PROCESS" "$pid" "$cmd" "$timestamp"
                    
                    # Kill spyware process
                    kill_spyware_process "$pid" "$cmd" "$signature_name" "$timestamp"
                fi
            done < "$SPYWARE_SIGNATURES"
            
            # Check for suspicious process behavior
            detect_suspicious_process_behavior "$pid" "$cmd" "$full_cmd" "$timestamp"
        fi
    done <<< "$suspicious_processes"
}

# Detect suspicious process behavior
detect_suspicious_process_behavior() {
    local pid="$1"
    local cmd="$2"
    local full_cmd="$3"
    local timestamp="$4"
    
    # Check for keylogger behavior
    if echo "$full_cmd" | grep -qiE "keyboard|keylog|keystroke|keyhook"; then
        log_spyware_detection "KEYLOGGER_BEHAVIOR" "keylogger" "PROCESS" "$pid" "$cmd" "$timestamp"
        kill_spyware_process "$pid" "$cmd" "Keylogger behavior" "$timestamp"
    fi
    
    # Check for screen capture behavior
    if echo "$full_cmd" | grep -qiE "screen|desktop|capture|screenshot|record"; then
        log_spyware_detection "SCREEN_CAPTURE" "screen" "PROCESS" "$pid" "$cmd" "$timestamp"
        kill_spyware_process "$pid" "$cmd" "Screen capture behavior" "$timestamp"
    fi
    
    # Check for webcam access
    if echo "$full_cmd" | grep -qiE "webcam|camera|video|capture|avd"; then
        log_spyware_detection "WEBCAM_ACCESS" "webcam" "PROCESS" "$pid" "$cmd" "$timestamp"
        kill_spyware_process "$pid" "$cmd" "Webcam access" "$timestamp"
    fi
    
    # Check for microphone access
    if echo "$full_cmd" | grep -qiE "microphone|audio|record|sound|voice"; then
        log_spyware_detection "MICROPHONE_ACCESS" "microphone" "PROCESS" "$pid" "$cmd" "$timestamp"
        kill_spyware_process "$pid" "$cmd" "Microphone access" "$timestamp"
    fi
    
    # Check for network monitoring
    if echo "$full_cmd" | grep -qiE "tcpdump|wireshark|nmap|netstat|network|packet"; then
        log_spyware_detection "NETWORK_MONITORING" "network" "PROCESS" "$pid" "$cmd" "$timestamp"
    fi
    
    # Check for file monitoring
    if echo "$full_cmd" | grep -qiE "inotify|watch|monitor|file|directory"; then
        log_spyware_detection "FILE_MONITORING" "filesystem" "PROCESS" "$pid" "$cmd" "$timestamp"
    fi
}

# Detect spyware files
detect_spyware_files() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local scan_dirs=("/tmp" "/var/tmp" "/home" "/usr/bin" "/usr/local/bin" "/opt")
    
    for dir in "${scan_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                if [[ -f "$file" ]]; then
                    # Check for spyware signatures in file content
                    while IFS='|' read -r signature_name spyware_type signature_pattern severity description; do
                        if [[ "$signature_name" =~ ^# ]] || [[ -z "$signature_name" ]]; then
                            continue
                        fi
                        
                        if grep -q "$signature_pattern" "$file" 2>/dev/null; then
                            log_spyware_detection "$signature_name" "$spyware_type" "FILE" "N/A" "$file" "$timestamp"
                            quarantine_spyware_file "$file" "$signature_name" "$timestamp"
                        fi
                    done < "$SPYWARE_SIGNATURES"
                    
                    # Check for suspicious file names
                    detect_suspicious_file_names "$file" "$timestamp"
                fi
            done < <(find "$dir" -type f -print0 2>/dev/null | head -z -500)
        fi
    done
}

# Detect suspicious file names
detect_suspicious_file_names() {
    local file="$1"
    local timestamp="$2"
    local filename=$(basename "$file")
    
    # Check for suspicious file name patterns
    if echo "$filename" | grep -iqE "spy|keylog|webcam|capture|record|monitor|track|steal|hack|backdoor|trojan|rootkit"; then
        log_spyware_detection "SUSPICIOUS_FILENAME" "unknown" "FILE" "N/A" "$file" "$timestamp"
        quarantine_spyware_file "$file" "Suspicious filename" "$timestamp"
    fi
    
    # Check for hidden files in suspicious locations
    if [[ "$filename" == .* ]] && [[ "$file" =~ /tmp|/var/tmp ]]; then
        log_spyware_detection "HIDDEN_FILE" "unknown" "FILE" "N/A" "$file" "$timestamp"
        quarantine_spyware_file "$file" "Hidden file in temp directory" "$timestamp"
    fi
    
    # Check for executable files with suspicious extensions
    local extension="${file##*.}"
    if [[ "$extension" =~ (exe|bat|cmd|scr|pif|vbs|js|jar) ]] && [[ "$file" =~ /tmp|/var/tmp ]]; then
        log_spyware_detection "SUSPICIOUS_EXECUTABLE" "unknown" "FILE" "N/A" "$file" "$timestamp"
        quarantine_spyware_file "$file" "Suspicious executable in temp directory" "$timestamp"
    fi
}

# Monitor network connections for spyware activity
monitor_spyware_network() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S"
    
    if command -v netstat &> /dev/null; then
        local network_connections=$(netstat -antp 2>/dev/null | grep ESTABLISHED)
        
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local protocol=$(echo "$line" | awk '{print $1}')
                local local_address=$(echo "$line" | awk '{print $4}')
                local remote_address=$(echo "$line" | awk '{print $5}')
                local pid=$(echo "$line" | awk '{print $7}' | cut -d'/' -f1)
                local process=$(echo "$line" | awk '{print $7}' | cut -d'/' -f2)
                
                # Check for connections to suspicious IPs
                if is_suspicious_ip "$remote_address"; then
                    log_spyware_detection "SUSPICIOUS_CONNECTION" "network" "NETWORK" "$pid" "$process" "$timestamp"
                    block_spyware_connection "$remote_address" "$process" "$timestamp"
                fi
                
                # Check for data exfiltration patterns
                if is_data_exfiltration "$local_address" "$remote_address" "$process"; then
                    log_spyware_detection "DATA_EXFILTRATION" "network" "NETWORK" "$pid" "$process" "$timestamp"
                    block_spyware_connection "$remote_address" "$process" "$timestamp"
                fi
            fi
        done <<< "$network_connections"
    fi
}

# Check if IP is suspicious
is_suspicious_ip() {
    local ip="$1"
    
    # Check against known malicious IP ranges (simplified)
    local suspicious_ranges="10.0.0.0/8|172.16.0.0/12|192.168.0.0/16"
    
    # Check for unusual ports
    local port=$(echo "$ip" | cut -d':' -f2)
    if [[ "$port" =~ (4444|5555|6666|7777|8888|9999|1337|31337|12345) ]]; then
        return 0
    fi
    
    return 1
}

# Check for data exfiltration patterns
is_data_exfiltration() {
    local local_address="$1"
    local remote_address="$2"
    local process="$3"
    
    # Check for large outbound connections
    if echo "$process" | grep -qiE "curl|wget|nc|netcat|ftp|scp|rsync"; then
        return 0
    fi
    
    # Check for connections to unusual ports
    local port=$(echo "$remote_address" | cut -d':' -f2)
    if [[ "$port" =~ (4444|5555|6666|7777|8888|9999|1337|31337|12345) ]]; then
        return 0
    fi
    
    return 1
}

# Monitor privacy violations
monitor_privacy_violations() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Monitor file access patterns
    monitor_file_access_privacy "$timestamp"
    
    # Monitor device access
    monitor_device_access_privacy "$timestamp"
    
    # Monitor application permissions
    monitor_application_privacy "$timestamp"
}

# Monitor file access privacy
monitor_file_access_privacy() {
    local timestamp="$1"
    local sensitive_dirs=("/home" "/etc" "/var/log" "/root" "/tmp")
    
    for dir in "${sensitive_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # Monitor recent file access
            local recent_access=$(find "$dir" -type f -amin -5 2>/dev/null | head -20)
            
            while IFS= read -r file; do
                if [[ -n "$file" ]]; then
                    # Check for access to sensitive files
                    if is_sensitive_file "$file"; then
                        log_privacy_violation "SENSITIVE_FILE_ACCESS" "$file" "$timestamp"
                    fi
                    
                    # Check for access to personal data
                    if is_personal_data_file "$file"; then
                        log_privacy_violation "PERSONAL_DATA_ACCESS" "$file" "$timestamp"
                    fi
                fi
            done <<< "$recent_access"
        fi
    done
}

# Check if file is sensitive
is_sensitive_file() {
    local file="$1"
    local filename=$(basename "$file")
    
    # Check for sensitive file patterns
    if echo "$filename" | grep -qiE "password|secret|key|private|credential|config|shadow|passwd|group"; then
        return 0
    fi
    
    # Check for sensitive directories
    if [[ "$file" =~ /etc/ssh|/etc/ssl|/etc/certs|/root/.ssh ]]; then
        return 0
    fi
    
    return 1
}

# Check if file contains personal data
is_personal_data_file() {
    local file="$1"
    local filename=$(basename "$file")
    
    # Check for personal data patterns
    if echo "$filename" | grep -qiE "resume|cv|passport|license|identity|ssn|social|tax|bank|credit|card|financial|medical|health"; then
        return 0
    fi
    
    # Check for document types
    if echo "$filename" | grep -qiE "\.doc$|\.pdf$|\.xls$|\.ppt$|\.txt$|\.rtf$"; then
        return 0
    fi
    
    return 1
}

# Monitor device access privacy
monitor_device_access_privacy() {
    local timestamp="$1"
    
    # Check for webcam access
    if [[ -c /dev/video0 ]]; then
        local webcam_access=$(lsof /dev/video0 2>/dev/null || true)
        if [[ -n "$webcam_access" ]]; then
            local process=$(echo "$webcam_access" | awk 'NR==2 {print $1}')
            log_privacy_violation "WEBCAM_ACCESS" "/dev/video0 by $process" "$timestamp"
        fi
    fi
    
    # Check for microphone access
    if [[ -c /dev/dsp ]] || [[ -c /dev/snd ]]; then
        local mic_access=$(lsof /dev/dsp 2>/dev/null || lsof /dev/snd/* 2>/dev/null || true)
        if [[ -n "$mic_access" ]]; then
            local process=$(echo "$mic_access" | awk 'NR==2 {print $1}')
            log_privacy_violation "MICROPHONE_ACCESS" "Audio device by $process" "$timestamp"
        fi
    fi
}

# Monitor application privacy
monitor_application_privacy() {
    local timestamp="$1"
    
    # Monitor browser extensions and plugins
    monitor_browser_privacy "$timestamp"
    
    # Monitor application permissions
    monitor_application_permissions "$timestamp"
}

# Monitor browser privacy
monitor_browser_privacy() {
    local timestamp="$1"
    local browser_dirs=("/home/*/.mozilla" "/home/*/.chrome" "/home/*/.config/google-chrome" "/home/*/.opera")
    
    for dir_pattern in "${browser_dirs[@]}"; do
        for dir in $dir_pattern; do
            if [[ -d "$dir" ]]; then
                # Check for suspicious browser extensions
                local extensions=$(find "$dir" -name "*.json" -path "*/extensions/*" 2>/dev/null)
                
                while IFS= read -r extension; do
                    if [[ -n "$extension" ]]; then
                        # Check extension content for spyware
                        if grep -qiE "spy|track|monitor|keylog|webcam|microphone" "$extension" 2>/dev/null; then
                            log_privacy_violation "SUSPICIOUS_BROWSER_EXTENSION" "$extension" "$timestamp"
                        fi
                    fi
                done <<< "$extensions"
            fi
        done
    done
}

# Monitor application permissions
monitor_application_permissions() {
    local timestamp="$1"
    
    # Check for applications with unusual permissions
    local suspicious_apps=$(ps aux --no-headers | grep -E "(record|capture|monitor|track|spy)" | grep -v grep)
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local pid=$(echo "$line" | awk '{print $2}')
            local cmd=$(echo "$line" | awk '{print $11}')
            log_privacy_violation "SUSPICIOUS_APPLICATION" "$cmd (PID: $pid)" "$timestamp"
        fi
    done <<< "$suspicious_apps"
}

# Log spyware detection
log_spyware_detection() {
    local signature_name="$1"
    local spyware_type="$2"
    local detection_type="$3"
    local pid="$4"
    local target="$5"
    local timestamp="$6"
    
    echo "[$timestamp] SPYWARE_DETECTED: $signature_name ($spyware_type) - Type: $detection_type - PID: $pid - Target: $target" >> "$SPYWARE_LOG"
    log_message "WARN" "Spyware detected: $signature_name - $target"
    send_alert "HIGH" "Spyware detected: $signature_name ($spyware_type) - $target" "SPYWARE_DETECTION"
}

# Log privacy violation
log_privacy_violation() {
    local violation_type="$1"
    local target="$2"
    local timestamp="$3"
    
    echo "[$timestamp] PRIVACY_VIOLATION: $violation_type - Target: $target" >> "$PRIVACY_LOG"
    log_message "WARN" "Privacy violation: $violation_type - $target"
    send_alert "MEDIUM" "Privacy violation detected: $violation_type - $target" "PRIVACY_PROTECTION"
}

# Kill spyware process
kill_spyware_process() {
    local pid="$1"
    local cmd="$2"
    local reason="$3"
    local timestamp="$4"
    
    if kill -TERM "$pid" 2>/dev/null; then
        sleep 2
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        
        log_message "INFO" "Killed spyware process: $cmd (PID: $pid) - $reason"
        send_alert "MEDIUM" "Spyware process killed: $cmd (PID: $pid) - $reason" "SPYWARE_REMOVAL"
    fi
}

# Quarantine spyware file
quarantine_spyware_file() {
    local file="$1"
    local reason="$2"
    local timestamp="$3"
    
    local quarantine_file="${QUARANTINE_DIR}/spyware_$(basename "$file")_$(date +%s)_${RANDOM}"
    
    if mv "$file" "$quarantine_file" 2>/dev/null; then
        chmod 000 "$quarantine_file" 2>/dev/null
        
        echo "[$timestamp] SPYWARE_QUARANTINED: $file -> $quarantine_file - Reason: $reason" >> "$SPYWARE_LOG"
        log_message "INFO" "Spyware file quarantined: $file -> $quarantine_file"
        send_alert "HIGH" "Spyware file quarantined: $file - $reason" "SPYWARE_QUARANTINE"
    fi
}

# Block spyware connection
block_spyware_connection() {
    local remote_address="$1"
    local process="$2"
    local timestamp="$3"
    
    local ip=$(echo "$remote_address" | cut -d':' -f1)
    
    # Block IP using iptables
    if command -v iptables &> /dev/null; then
        iptables -A OUTPUT -d "$ip" -j DROP 2>/dev/null || true
        iptables -A INPUT -s "$ip" -j DROP 2>/dev/null || true
    fi
    
    log_message "INFO" "Blocked spyware connection: $process to $ip"
    send_alert "MEDIUM" "Spyware connection blocked: $process to $ip" "SPYWARE_BLOCKING"
}

# Main spyware detection function
spyware_detection_main() {
    # Initialize if not done
    if [[ ! -f "$SPYWARE_STATE" ]]; then
        init_spyware_detection
    fi
    
    # Run detection functions
    detect_spyware_processes
    detect_spyware_files
    monitor_spyware_network
    monitor_privacy_violations
}

# Export functions for main script
export -f init_spyware_detection create_spyware_signatures create_privacy_rules
export -f detect_spyware_processes detect_suspicious_process_behavior detect_spyware_files
export -f detect_suspicious_file_names monitor_spyware_network is_suspicious_ip
export -f is_data_exfiltration monitor_privacy_violations monitor_file_access_privacy
export -f is_sensitive_file is_personal_data_file monitor_device_access_privacy
export -f monitor_application_privacy monitor_browser_privacy monitor_application_permissions
export -f log_spyware_detection log_privacy_violation kill_spyware_process
export -f quarantine_spyware_file block_spyware_connection spyware_detection_main
