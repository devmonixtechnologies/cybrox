#!/bin/bash

# MEMORY FORENSICS AND PROCESS INJECTION DETECTION MODULE
# Advanced memory analysis and process injection detection system

# Memory forensics state files
readonly MEMORY_STATE="${TEMP_DIR}/memory_state.tmp"
readonly MEMORY_LOG="${LOGS_DIR}/memory_forensics.log"
readonly INJECTION_LOG="${LOGS_DIR}/process_injection.log"
readonly MEMORY_DUMPS="${TEMP_DIR}/memory_dumps"
readonly PROCESS_ANALYSIS="${TEMP_DIR}/process_analysis"

# Initialize memory forensics
init_memory_forensics() {
    log_message "INFO" "Initializing memory forensics and process injection detection"
    
    # Create directories
    mkdir -p "$MEMORY_DUMPS" "$PROCESS_ANALYSIS"
    
    # Create state files
    touch "$MEMORY_STATE" "$MEMORY_LOG" "$INJECTION_LOG"
    
    # Initialize tracking variables
    declare -A process_memory_maps
    declare -A injection_signatures
    declare -A memory_anomalies
    declare -A forensic_snapshots
    
    # Save initial state
    declare -p process_memory_maps injection_signatures memory_anomalies forensic_snapshots > "$MEMORY_STATE"
}

# Detect process injection techniques
detect_process_injection() {
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Monitor for common injection techniques
    detect_dll_injection "$timestamp"
    detect_shellcode_injection "$timestamp"
    detect_process_hollowing "$timestamp"
    detect_thread_hijacking "$timestamp"
    detect_apt_injection_techniques "$timestamp"
}

# Detect DLL injection
detect_dll_injection() {
    local timestamp="$1"
    
    # Monitor process memory for suspicious DLL loading
    local processes=$(ps aux --no-headers | awk '{print $2}')
    
    while IFS= read -r pid; do
        if [[ -n "$pid" && -d "/proc/$pid" ]]; then
            # Check memory maps for suspicious DLLs
            local memory_maps=$(cat "/proc/$pid/maps" 2>/dev/null || true)
            
            while IFS= read -r map_line; do
                if [[ -n "$map_line" ]]; then
                    local address=$(echo "$map_line" | awk '{print $1}')
                    local permissions=$(echo "$map_line" | awk '{print $2}')
                    local path=$(echo "$map_line" | awk '{print $6}')
                    
                    # Check for suspicious DLL characteristics
                    if is_suspicious_dll "$path" "$permissions" "$address"; then
                        log_injection_detection "DLL_INJECTION" "$pid" "$path" "$timestamp"
                        analyze_injected_dll "$pid" "$path" "$timestamp"
                    fi
                fi
            done <<< "$memory_maps"
        fi
    done <<< "$processes"
}

# Detect shellcode injection
detect_shellcode_injection() {
    local timestamp="$1"
    
    # Monitor process memory for shellcode patterns
    local processes=$(ps aux --no-headers | awk '{print $2}')
    
    while IFS= read -r pid; do
        if [[ -n "$pid" && -d "/proc/$pid" ]]; then
            # Check for executable memory regions
            local executable_regions=$(grep -E "rwx|rw-x" "/proc/$pid/maps" 2>/dev/null || true)
            
            while IFS= read -r region; do
                if [[ -n "$region" ]]; then
                    local address=$(echo "$region" | awk '{print $1}')
                    local size=$(echo "$region" | awk '{print $2}')
                    local permissions=$(echo "$region" | awk '{print $3}')
                    
                    # Check for shellcode patterns
                    if contains_shellcode "$pid" "$address" "$size"; then
                        log_injection_detection "SHELLCODE_INJECTION" "$pid" "$address" "$timestamp"
                        dump_shellcode "$pid" "$address" "$size" "$timestamp"
                    fi
                fi
            done <<< "$executable_regions"
        fi
    done <<< "$processes"
}

# Detect process hollowing
detect_process_hollowing() {
    local timestamp="$1"
    
    # Monitor for process hollowing techniques
    local suspicious_processes=$(ps aux --no-headers | grep -E "(svchost|lsass|winlogon|csrss|smss)" | grep -v grep)
    
    while IFS= read -r process; do
        if [[ -n "$process" ]]; then
            local pid=$(echo "$process" | awk '{print $2}')
            local cmd=$(echo "$process" | awk '{print $11}')
            
            # Check if process is hollowed
            if is_process_hollowed "$pid" "$cmd"; then
                log_injection_detection "PROCESS_HOLLOWING" "$pid" "$cmd" "$timestamp"
                analyze_hollowed_process "$pid" "$timestamp"
            fi
        fi
    done <<< "$suspicious_processes"
}

# Detect thread hijacking
detect_thread_hijacking() {
    local timestamp="$1"
    
    # Monitor for suspicious thread creation
    local thread_activity=$(ps -eLo pid,lwp,comm,cmd 2>/dev/null | grep -v grep)
    
    while IFS= read -r thread_line; do
        if [[ -n "$thread_line" ]]; then
            local pid=$(echo "$thread_line" | awk '{print $1}')
            local tid=$(echo "$thread_line" | awk '{print $2}')
            local comm=$(echo "$thread_line" | awk '{print $3}')
            local cmd=$(echo "$thread_line" | cut -d' ' -f4-)
            
            # Check for thread hijacking indicators
            if is_thread_hijacked "$pid" "$tid" "$comm" "$cmd"; then
                log_injection_detection "THREAD_HIJACKING" "$pid" "$tid" "$timestamp"
                analyze_hijacked_thread "$pid" "$tid" "$timestamp"
            fi
        fi
    done <<< "$thread_activity"
}

# Detect APT injection techniques
detect_apt_injection_techniques() {
    local timestamp="$1"
    
    # Monitor for advanced persistent threat techniques
    detect_apt_dll_hijacking "$timestamp"
    detect_apt_service_injection "$timestamp"
    detect_apt_wmi_injection "$timestamp"
    detect_apt_registry_injection "$timestamp"
}

# Detect APT DLL hijacking
detect_apt_dll_hijacking() {
    local timestamp="$1"
    
    # Monitor for DLL search order hijacking
    local system_dirs=("/usr/bin" "/usr/sbin" "/bin" "/sbin" "/usr/local/bin" "/usr/local/sbin")
    
    for dir in "${system_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # Check for suspicious DLL files in system directories
            local suspicious_dlls=$(find "$dir" -name "*.so" -o -name "*.dll" 2>/dev/null | head -20)
            
            while IFS= read -r dll; do
                if [[ -n "$dll" ]]; then
                    if is_apt_dll_hijack "$dll"; then
                        log_injection_detection "APT_DLL_HIJACKING" "N/A" "$dll" "$timestamp"
                        quarantine_suspicious_dll "$dll" "$timestamp"
                    fi
                fi
            done <<< "$suspicious_dlls"
        fi
    done
}

# Detect APT service injection
detect_apt_service_injection() {
    local timestamp="$1"
    
    # Monitor system services for injection
    local services=$(systemctl list-units --type=service --state=running 2>/dev/null | awk '{print $1}' | sed 's/.service//')
    
    while IFS= read -r service; do
        if [[ -n "$service" ]]; then
            # Check service for injection indicators
            if is_service_injected "$service"; then
                log_injection_detection "APT_SERVICE_INJECTION" "$service" "systemd" "$timestamp"
                analyze_injected_service "$service" "$timestamp"
            fi
        fi
    done <<< "$services"
}

# Detect APT WMI injection
detect_apt_wmi_injection() {
    local timestamp="$1"
    
    # Monitor WMI for suspicious activity (Linux equivalent)
    if command -v wmic &> /dev/null; then
        local wmi_processes=$(wmic process list brief 2>/dev/null | grep -v "CommandLine" || true)
        
        while IFS= read -r wmi_line; do
            if [[ -n "$wmi_line" ]]; then
                # Check for WMI-based injection
                if is_wmi_injected "$wmi_line"; then
                    log_injection_detection "APT_WMI_INJECTION" "WMI" "$wmi_line" "$timestamp"
                fi
            fi
        done <<< "$wmi_processes"
    fi
}

# Detect APT registry injection
detect_apt_registry_injection() {
    local timestamp="$1"
    
    # Monitor for registry-like injection (Linux equivalent)
    local config_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/sudoers" "/etc/ssh/sshd_config")
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            # Check for suspicious modifications
            if is_config_injected "$config_file"; then
                log_injection_detection "APT_CONFIG_INJECTION" "CONFIG" "$config_file" "$timestamp"
                analyze_injected_config "$config_file" "$timestamp"
            fi
        fi
    done
}

# Check if DLL is suspicious
is_suspicious_dll() {
    local path="$1"
    local permissions="$2"
    local address="$3"
    
    # Check for suspicious characteristics
    if [[ "$permissions" =~ rwx ]]; then
        return 0  # Executable and writable is suspicious
    fi
    
    if [[ "$path" =~ /tmp|/var/tmp|/dev/shm ]]; then
        return 0  # DLL in temp directory is suspicious
    fi
    
    if [[ ! -f "$path" ]]; then
        return 0  # Non-existent DLL path is suspicious
    fi
    
    # Check for suspicious DLL names
    local filename=$(basename "$path")
    if echo "$filename" | grep -qiE "hook|inject|patch|crack|hack|bypass|exploit"; then
        return 0
    fi
    
    return 1
}

# Check if memory contains shellcode
contains_shellcode() {
    local pid="$1"
    local address="$2"
    local size="$3"
    
    # Extract memory content (simplified)
    if [[ -r "/proc/$pid/mem" ]]; then
        # This is a simplified check - in reality would need proper memory dumping
        local mem_content=$(dd if="/proc/$pid/mem" bs=1 skip=$((0x${address%%-*})) count="$size" 2>/dev/null | xxd | head -10)
        
        # Check for shellcode patterns
        if echo "$mem_content" | grep -qiE "eb fe|90 90 90|cc cc cc|e8.*5e|8b.*ec"; then
            return 0
        fi
    fi
    
    return 1
}

# Check if process is hollowed
is_process_hollowed() {
    local pid="$1"
    local cmd="$2"
    
    # Check for process hollowing indicators
    if [[ ! -f "/proc/$pid/exe" ]]; then
        return 0  # No executable file is suspicious
    fi
    
    local actual_exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "")
    if [[ "$actual_exe" != "$cmd" ]]; then
        return 0  # Mismatched executable is suspicious
    fi
    
    # Check for suspicious memory layout
    local memory_maps=$(cat "/proc/$pid/maps" 2>/dev/null || true)
    if echo "$memory_maps" | grep -qE "rwx.*00000000"; then
        return 0  # Executable memory at null page is suspicious
    fi
    
    return 1
}

# Check if thread is hijacked
is_thread_hijacked() {
    local pid="$1"
    local tid="$2"
    local comm="$3"
    local cmd="$4"
    
    # Check for thread hijacking indicators
    if [[ "$comm" != "$cmd" ]]; then
        return 0  # Mismatched thread command is suspicious
    fi
    
    # Check for suspicious thread names
    if echo "$comm" | grep -qiE "inject|hook|patch|exploit"; then
        return 0
    fi
    
    return 1
}

# Check for APT DLL hijack
is_apt_dll_hijack() {
    local dll="$1"
    
    # Check for DLL hijacking indicators
    if [[ ! -s "$dll" ]]; then
        return 0  # Empty DLL is suspicious
    fi
    
    # Check for suspicious DLL content
    if strings "$dll" 2>/dev/null | grep -qiE "mimikatz|powershell|cobalt|beacon|empire"; then
        return 0
    fi
    
    return 1
}

# Check if service is injected
is_service_injected() {
    local service="$1"
    
    # Check service configuration
    local service_file=$(systemctl cat "$service" 2>/dev/null | grep -E "ExecStart|ExecReload" || true)
    
    if echo "$service_file" | grep -qiE "powershell|cmd.exe|wscript|cscript|mshta"; then
        return 0  # Suspicious service command
    fi
    
    return 1
}

# Check if WMI is injected
is_wmi_injected() {
    local wmi_line="$1"
    
    # Check for suspicious WMI activity
    if echo "$wmi_line" | grep -qiE "powershell|wscript|cscript|mshta|cmd.exe"; then
        return 0
    fi
    
    return 1
}

# Check if config is injected
is_config_injected() {
    local config_file="$1"
    
    # Check for suspicious modifications
    if [[ "$config_file" == "/etc/passwd" ]]; then
        # Check for unauthorized user accounts
        local suspicious_users=$(grep -E "^[^:]*:[0-9]*:0:" "$config_file" || true)
        if [[ -n "$suspicious_users" ]]; then
            return 0
        fi
    fi
    
    if [[ "$config_file" == "/etc/sudoers" ]]; then
        # Check for suspicious sudo rules
        if grep -qE "NOPASSWD.*ALL|!root.*ALL" "$config_file" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# Analyze injected DLL
analyze_injected_dll() {
    local pid="$1"
    local dll_path="$2"
    local timestamp="$3"
    
    # Create analysis report
    local analysis_file="${PROCESS_ANALYSIS}/dll_analysis_${pid}_${timestamp}.txt"
    
    cat > "$analysis_file" << EOF
DLL Injection Analysis
====================
PID: $pid
DLL Path: $dll_path
Timestamp: $timestamp

DLL Information:
- File Size: $(stat -c%s "$dll_path" 2>/dev/null || echo "Unknown")
- File Hash: $(sha256sum "$dll_path" 2>/dev/null | awk '{print $1}' || echo "Unknown")
- Permissions: $(stat -c%A "$dll_path" 2>/dev/null || echo "Unknown")

Process Information:
- Process Name: $(ps -p "$pid" -o comm= 2>/dev/null || echo "Unknown")
- Process Command: $(ps -p "$pid" -o cmd= 2>/dev/null || echo "Unknown")
- Process User: $(ps -p "$pid" -o user= 2>/dev/null || echo "Unknown")

Memory Analysis:
- Memory Maps: $(cat "/proc/$pid/maps" 2>/dev/null | grep "$dll_path" | wc -l)
- Memory Regions: $(cat "/proc/$pid/maps" 2>/dev/null | grep "$dll_path")

Suspicious Indicators:
- DLL in Temp Directory: $([[ "$dll_path" =~ /tmp|/var/tmp ]] && echo "YES" || echo "NO")
- Executable Permissions: $([[ -x "$dll_path" ]] && echo "YES" || echo "NO")
- Suspicious Name: $([[ "$(basename "$dll_path")" =~ hook|inject|patch ]] && echo "YES" || echo "NO")

Recommendation:
- Quarantine the injected DLL
- Monitor the affected process
- Investigate the source of injection
EOF
    
    log_message "INFO" "DLL analysis completed: $analysis_file"
}

# Dump shellcode
dump_shellcode() {
    local pid="$1"
    local address="$2"
    local size="$3"
    local timestamp="$4"
    
    local dump_file="${MEMORY_DUMPS}/shellcode_${pid}_${address}_${timestamp}.bin"
    
    # Dump shellcode from memory
    if [[ -r "/proc/$pid/mem" ]]; then
        dd if="/proc/$pid/mem" of="$dump_file" bs=1 skip=$((0x${address%%-*})) count="$size" 2>/dev/null || true
        
        if [[ -f "$dump_file" && -s "$dump_file" ]]; then
            chmod 600 "$dump_file"
            
            # Create analysis report
            local analysis_file="${MEMORY_DUMPS}/shellcode_analysis_${pid}_${timestamp}.txt"
            
            cat > "$analysis_file" << EOF
Shellcode Analysis
================
PID: $pid
Address: $address
Size: $size
Timestamp: $timestamp
Dump File: $dump_file

Shellcode Content:
$(xxd "$dump_file" | head -20)

Hexdump Analysis:
$(hexdump -C "$dump_file" | head -20)

Strings Found:
$(strings "$dump_file" | head -10)

Entropy Analysis:
$(calculate_entropy "$dump_file")

Suspicious Patterns:
$(check_shellcode_patterns "$dump_file")

Recommendation:
- Analyze shellcode behavior
- Monitor affected process
- Consider terminating suspicious process
EOF
            
            log_message "INFO" "Shellcode dumped and analyzed: $dump_file"
        fi
    fi
}

# Analyze hollowed process
analyze_hollowed_process() {
    local pid="$1"
    local timestamp="$2"
    
    local analysis_file="${PROCESS_ANALYSIS}/hollowed_process_${pid}_${timestamp}.txt"
    
    cat > "$analysis_file" << EOF
Process Hollowing Analysis
=========================
PID: $pid
Timestamp: $timestamp

Process Information:
- Process Name: $(ps -p "$pid" -o comm= 2>/dev/null || echo "Unknown")
- Process Command: $(ps -p "$pid" -o cmd= 2>/dev/null || echo "Unknown")
- Process User: $(ps -p "$pid" -o user= 2>/dev/null || echo "Unknown")
- Executable Path: $(readlink "/proc/$pid/exe" 2>/dev/null || echo "Unknown")

Memory Analysis:
- Total Memory Regions: $(cat "/proc/$pid/maps" 2>/dev/null | wc -l)
- Executable Regions: $(cat "/proc/$pid/maps" 2>/dev/null | grep -E "rwx|rw-x" | wc -l)
- Suspicious Regions: $(cat "/proc/$pid/maps" 2>/dev/null | grep -E "00000000|7f[0-9a-f]{12}" | wc -l)

Hollowing Indicators:
- Missing Executable: $([[ ! -f "/proc/$pid/exe" ]] && echo "YES" || echo "NO")
- Mismatched Path: $([[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" != "$(ps -p "$pid" -o cmd= 2>/dev/null)" ]] && echo "YES" || echo "NO")
- Null Page Mapping: $([[ -f "/proc/$pid/maps" ]] && grep -qE "00000000.*rwx" "/proc/$pid/maps" 2>/dev/null && echo "YES" || echo "NO")

Recommendation:
- Investigate the hollowed process
- Monitor for suspicious activity
- Consider terminating if malicious
EOF
    
    log_message "INFO" "Hollowed process analysis completed: $analysis_file"
}

# Analyze hijacked thread
analyze_hijacked_thread() {
    local pid="$1"
    local tid="$2"
    local timestamp="$3"
    
    local analysis_file="${PROCESS_ANALYSIS}/hijacked_thread_${pid}_${tid}_${timestamp}.txt"
    
    cat > "$analysis_file" << EOF
Thread Hijacking Analysis
========================
PID: $pid
TID: $tid
Timestamp: $timestamp

Thread Information:
- Thread Command: $(ps -T -p "$pid" -o comm= 2>/dev/null | grep "$tid" | awk '{print $2}' || echo "Unknown")
- Thread Status: $(cat "/proc/$pid/task/$tid/status" 2>/dev/null | grep "State" | awk '{print $2}' || echo "Unknown")

Hijacking Indicators:
- Suspicious Thread Name: $([[ "$(ps -T -p "$pid" -o comm= 2>/dev/null | grep "$tid" | awk '{print $2}')" =~ inject|hook|patch ]] && echo "YES" || echo "NO")
- Unusual Thread Activity: $([[ -f "/proc/$pid/task/$tid/stat" ]] && grep -q "Z" "/proc/$pid/task/$tid/stat" 2>/dev/null && echo "YES" || echo "NO")

Recommendation:
- Monitor thread activity
- Investigate thread purpose
- Check for malicious code execution
EOF
    
    log_message "INFO" "Hijacked thread analysis completed: $analysis_file"
}

# Analyze injected service
analyze_injected_service() {
    local service="$1"
    local timestamp="$2"
    
    local analysis_file="${PROCESS_ANALYSIS}/injected_service_${service}_${timestamp}.txt"
    
    cat > "$analysis_file" << EOF
Service Injection Analysis
=========================
Service: $service
Timestamp: $timestamp

Service Information:
- Service Status: $(systemctl is-active "$service" 2>/dev/null || echo "Unknown")
- Service Description: $(systemctl show "$service" -p Description --value 2>/dev/null || echo "Unknown")

Injection Indicators:
- Suspicious Command: $([[ "$(systemctl cat "$service" 2>/dev/null | grep -E "ExecStart|ExecReload")" =~ powershell|cmd.exe ]] && echo "YES" || echo "NO")
- Unusual Executable: $([[ "$(systemctl cat "$service" 2>/dev/null | grep -E "ExecStart|ExecReload")" =~ /tmp|/var/tmp ]] && echo "YES" || echo "NO")

Recommendation:
- Review service configuration
- Check service logs
- Monitor service behavior
EOF
    
    log_message "INFO" "Injected service analysis completed: $analysis_file"
}

# Analyze injected config
analyze_injected_config() {
    local config_file="$1"
    local timestamp="$2"
    
    local analysis_file="${PROCESS_ANALYSIS}/injected_config_${timestamp}.txt"
    
    cat > "$analysis_file" << EOF
Configuration Injection Analysis
===============================
Config File: $config_file
Timestamp: $timestamp

File Information:
- File Size: $(stat -c%s "$config_file" 2>/dev/null || echo "Unknown")
- File Hash: $(sha256sum "$config_file" 2>/dev/null | awk '{print $1}' || echo "Unknown")
- Last Modified: $(stat -c%y "$config_file" 2>/dev/null || echo "Unknown")

Injection Indicators:
- Suspicious Entries: $([[ "$config_file" == "/etc/passwd" ]] && grep -qE "^[^:]*:[0-9]*:0:" "$config_file" && echo "YES" || echo "NO")
- Suspicious Sudo Rules: $([[ "$config_file" == "/etc/sudoers" ]] && grep -qE "NOPASSWD.*ALL" "$config_file" && echo "YES" || echo "NO")

Recommendation:
- Review configuration changes
- Check for unauthorized access
- Restore from backup if needed
EOF
    
    log_message "INFO" "Injected config analysis completed: $analysis_file"
}

# Calculate file entropy
calculate_entropy() {
    local file="$1"
    
    if command -v ent &> /dev/null; then
        ent "$file" 2>/dev/null | grep "Entropy" | awk '{print $3}' || echo "Unknown"
    else
        echo "Entropy calculation not available"
    fi
}

# Check shellcode patterns
check_shellcode_patterns() {
    local file="$1"
    
    # Check for common shellcode patterns
    local patterns="eb fe|90 90 90|cc cc cc|e8.*5e|8b.*ec|55 8b ec"
    
    while IFS='|' read -r pattern; do
        if xxd "$file" 2>/dev/null | grep -q "$pattern"; then
            echo "Pattern found: $pattern"
        fi
    done <<< "$patterns"
}

# Quarantine suspicious DLL
quarantine_suspicious_dll() {
    local dll="$1"
    local timestamp="$2"
    
    local quarantine_file="${QUARANTINE_DIR}/dll_$(basename "$dll")_${timestamp}"
    
    if mv "$dll" "$quarantine_file" 2>/dev/null; then
        chmod 000 "$quarantine_file"
        log_message "INFO" "Suspicious DLL quarantined: $dll -> $quarantine_file"
        send_alert "HIGH" "Suspicious DLL quarantined: $dll" "DLL_QUARANTINE"
    fi
}

# Log injection detection
log_injection_detection() {
    local injection_type="$1"
    local target="$2"
    local details="$3"
    local timestamp="$4"
    
    echo "[$timestamp] INJECTION_DETECTED: $injection_type - Target: $target - Details: $details" >> "$INJECTION_LOG"
    echo "[$timestamp] INJECTION_DETECTED: $injection_type - Target: $target - Details: $details" >> "$MEMORY_LOG"
    log_message "WARN" "Process injection detected: $injection_type - $target - $details"
    send_alert "HIGH" "Process injection detected: $injection_type - $target" "INJECTION_DETECTION"
}

# Main memory forensics function
memory_forensics_main() {
    # Initialize if not done
    if [[ ! -f "$MEMORY_STATE" ]]; then
        init_memory_forensics
    fi
    
    # Run injection detection
    detect_process_injection
    
    # Clean old memory dumps
    if (( $(date +%s) % 86400 == 0 )); then
        find "$MEMORY_DUMPS" -name "*.bin" -mtime +7 -delete 2>/dev/null || true
        find "$PROCESS_ANALYSIS" -name "*.txt" -mtime +7 -delete 2>/dev/null || true
    fi
}

# Export functions for main script
export -f init_memory_forensics detect_process_injection detect_dll_injection
export -f detect_shellcode_injection detect_process_hollowing detect_thread_hijacking
export -f detect_apt_injection_techniques detect_apt_dll_hijacking detect_apt_service_injection
export -f detect_apt_wmi_injection detect_apt_registry_injection is_suspicious_dll
export -f contains_shellcode is_process_hollowed is_thread_hijacked is_apt_dll_hijack
export -f is_service_injected is_wmi_injected is_config_injected analyze_injected_dll
export -f dump_shellcode analyze_hollowed_process analyze_hijacked_thread
export -f analyze_injected_service analyze_injected_config calculate_entropy
export -f check_shellcode_patterns quarantine_suspicious_dll log_injection_detection
export -f memory_forensics_main
