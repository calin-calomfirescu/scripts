#!/bin/bash

# IP Protection System for Apache with AbuseIPDB Integration
# This script monitors Apache access logs, checks IP reputation, and manages iptables rules

# Configuration
CONFIG_FILE="/etc/ip-protection/config.conf"
LOG_FILE="/var/log/ip-protection.log"
BLOCKED_IPS_FILE="/var/lib/ip-protection/blocked_ips.txt"
APACHE_ACCESS_LOG="/var/log/virtualmin/euagenda.eu_access_log"
IPTABLES_CHAIN="IP_PROTECTION"
SCRIPT_DIR="/opt/ip-protection"

# Default configuration (override in config file)
REQUEST_THRESHOLD=50          # Number of requests in time window
MAX_REQUEST_THRESHOLD=100     # Requests threshold for immediate block

TIME_WINDOW=300              # Time window in seconds (5 minutes)
ABUSEIPDB_THRESHOLD=75       # AbuseIPDB confidence threshold (%)
BLOCK_DURATION=86400         # Block duration in seconds (24 hours)
ABUSEIPDB_API_KEY=""         # Set this in config file
CHECK_INTERVAL=60            # How often to run checks (seconds)
DEBUG_MODE=false                    # Set to true for testing
DEBUG_EMAIL="colin@server-administrator.net"  # Email for debug notifications
SEND_NOTIFICATIONS=false            # Send emails in production mode too
NOTIFICATION_EMAIL="colin@server-administrator.net"  # Production notification email

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        echo "Warning: Config file not found. Using defaults."
    fi
}

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}


# Check if IP is in whitelist subnets
is_ip_whitelisted() {
    local ip=$1
    
    if [[ -z "$IP_WHITELIST_SUBNETS" ]]; then
        return 1  # Not whitelisted if no subnets defined
    fi
    
    # Convert comma-separated subnets to array
    IFS=',' read -ra subnets <<< "$IP_WHITELIST_SUBNETS"
    
    for subnet in "${subnets[@]}"; do
        subnet=$(echo "$subnet" | tr -d ' ')  # Remove spaces
        
        if [[ -n "$subnet" ]]; then
            # Use enhanced bash subnet check
            if check_ip_in_subnet "$ip" "$subnet"; then
                return 0
            fi
        fi
    done
    
    return 1  # Not whitelisted
}


check_ip_in_subnet() {
    local ip=$1
    local subnet=$2
    
    # Extract network and prefix
    local network=$(echo "$subnet" | cut -d'/' -f1)
    local prefix=$(echo "$subnet" | cut -d'/' -f2)
    
    # Convert IP addresses to integers
    local ip_int=0
    local net_int=0
    
    # Convert IP to integer
    IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
    ip_int=$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))
    
    # Convert network to integer  
    IFS='.' read -r n1 n2 n3 n4 <<< "$network"
    net_int=$(( (n1 << 24) + (n2 << 16) + (n3 << 8) + n4 ))
    
    # Calculate subnet mask
    local mask=$(( 0xFFFFFFFF << (32 - prefix) ))
    
    # Apply mask and compare
    if [[ $(( ip_int & mask )) -eq $(( net_int & mask )) ]]; then
        return 0  # IP is in subnet
    else
        return 1  # IP is not in subnet
    fi
}


# Check if user agent contains whitelisted bot
is_bot_whitelisted() {
    local user_agent=$1
    
    if [[ -z "$BOT_WHITELIST" || -z "$user_agent" ]]; then
        return 1  # Not whitelisted if no bots defined or no user agent
    fi
    
    # Convert to lowercase for case-insensitive matching
    local ua_lower=$(echo "$user_agent" | tr '[:upper:]' '[:lower:]')
    
    # Convert comma-separated bots to array
    IFS=',' read -ra bots <<< "$BOT_WHITELIST"
    
    for bot in "${bots[@]}"; do
        bot=$(echo "$bot" | tr -d ' ' | tr '[:upper:]' '[:lower:]')  # Remove spaces and convert to lowercase
        
        if [[ -n "$bot" && "$ua_lower" == *"$bot"* ]]; then
            return 0  # Bot is whitelisted
        fi
    done
    
    return 1  # Not whitelisted
}



# Initialize directories and files
initialize() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$BLOCKED_IPS_FILE")"
    mkdir -p "$SCRIPT_DIR"
    
    touch "$BLOCKED_IPS_FILE"
    
    # Create iptables chain if it doesn't exist
    if ! iptables -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
        iptables -N "$IPTABLES_CHAIN"
        iptables -I INPUT -j "$IPTABLES_CHAIN"
        log_message "Created iptables chain: $IPTABLES_CHAIN"
    fi
}

# Check if IP is already blocked
is_ip_blocked() {
    local ip=$1
    grep -q "^$ip " "$BLOCKED_IPS_FILE" 2>/dev/null
}


# Get IP request count in time window (excluding specified exceptions)
get_ip_request_count() {
    local ip=$1
    local since_time=$(date -d "$TIME_WINDOW seconds ago" '+%d/%b/%Y:%H:%M:%S')

    local additional_files="${ADDITIONAL_FILE_EXCEPTIONS:-}"
    local additional_endpoints="${ADDITIONAL_ENDPOINT_EXCEPTIONS:-}"
    
    awk -v ip="$ip" -v since="$since_time" \
        -v additional_files="$additional_files" \
        -v additional_endpoints="$additional_endpoints" '    
    BEGIN { 
        count = 0
        
        # File extension exceptions (case insensitive)
        file_exceptions["jpg"] = 1
        file_exceptions["jpeg"] = 1
        file_exceptions["png"] = 1
        file_exceptions["gif"] = 1
        file_exceptions["bmp"] = 1
        file_exceptions["webp"] = 1
        file_exceptions["ico"] = 1
        file_exceptions["svg"] = 1
        file_exceptions["css"] = 1
        file_exceptions["js"] = 1
        file_exceptions["woff"] = 1
        file_exceptions["woff2"] = 1
        file_exceptions["ttf"] = 1
        file_exceptions["eot"] = 1
        file_exceptions["pdf"] = 1
        file_exceptions["doc"] = 1
        file_exceptions["docx"] = 1
        file_exceptions["xls"] = 1
        file_exceptions["xlsx"] = 1
        file_exceptions["ppt"] = 1
        file_exceptions["pptx"] = 1
        file_exceptions["zip"] = 1
        file_exceptions["rar"] = 1
        file_exceptions["7z"] = 1
        file_exceptions["tar"] = 1
        file_exceptions["gz"] = 1
        file_exceptions["mp4"] = 1
        file_exceptions["avi"] = 1
        file_exceptions["mov"] = 1
        file_exceptions["wmv"] = 1
        file_exceptions["mp3"] = 1
        file_exceptions["wav"] = 1
        file_exceptions["ogg"] = 1
        
        # Endpoint exceptions (exact matches and patterns)
        endpoint_exceptions["/login"] = 1
        endpoint_exceptions["/logout"] = 1
        endpoint_exceptions["/auth"] = 1
        endpoint_exceptions["/captcha"] = 1
        endpoint_exceptions["/robots.txt"] = 1
        endpoint_exceptions["/sitemap.xml"] = 1
        endpoint_exceptions["/favicon.ico"] = 1
        endpoint_exceptions["/.well-known/"] = 1  # Pattern match
        endpoint_exceptions["/health"] = 1
        endpoint_exceptions["/status"] = 1
        endpoint_exceptions["/ping"] = 1
        endpoint_exceptions["/api/health"] = 1

	if (additional_files != "") {
            split(additional_files, extra_files, ",")
            for (i in extra_files) {
                file_exceptions[tolower(extra_files[i])] = 1
            }
        }
        
        # Add additional endpoints from config  
        if (additional_endpoints != "") {
            split(additional_endpoints, extra_endpoints, ",")
            for (i in extra_endpoints) {
                endpoint_exceptions[extra_endpoints[i]] = 1
            }
        }
    }
    {
        # Extract components from Apache access log
        # Standard format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
        log_ip = $1
        timestamp = substr($4, 2)  # Remove leading [
        
        # Extract the request line (between quotes)
        request_start = index($0, "\"")
        if (request_start > 0) {
            request_line = substr($0, request_start + 1)
            request_end = index(request_line, "\"")
            if (request_end > 0) {
                request_line = substr(request_line, 1, request_end - 1)
                
                # Parse method and path from request line
                split(request_line, request_parts, " ")
                method = request_parts[1]
                path = request_parts[2]
                
                # Check if this request should be counted
                if (log_ip == ip && timestamp >= since && should_count_request(path, method)) {
                    count++
                }
            }
        }
    }
    
    function should_count_request(path, method) {
        # Skip non-GET/POST requests for most checks (optional)
        # if (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE") {
        #     return 0
        # }
        
        # Check endpoint exceptions (exact matches)
        if (path in endpoint_exceptions) {
            return 0
        }
        
        # Check endpoint patterns
        if (index(path, "/.well-known/") == 1) return 0
        if (index(path, "/assets/") == 1) return 0
        if (index(path, "/static/") == 1) return 0
        if (index(path, "/public/") == 1) return 0
        if (index(path, "/images/") == 1) return 0
        if (index(path, "/img/") == 1) return 0
        if (index(path, "/css/") == 1) return 0
        if (index(path, "/js/") == 1) return 0
        if (index(path, "/fonts/") == 1) return 0
        if (index(path, "/uploads/") == 1) return 0
        if (index(path, "/media/") == 1) return 0
        if (index(path, "/downloads/") == 1) return 0
        

        # Extract file extension from path
        # Find the last dot after the last slash
        last_slash = 0
        for (i = 1; i <= length(path); i++) {
            if (substr(path, i, 1) == "/") {
                last_slash = i
            }
        }
        
        filename_part = substr(path, last_slash + 1)
        last_dot = 0
        for (i = 1; i <= length(filename_part); i++) {
            if (substr(filename_part, i, 1) == ".") {
                last_dot = i
            }
        }
        
        if (last_dot > 0) {
            ext = substr(filename_part, last_dot + 1)
            
            # Convert to lowercase manually
            ext_lower = ""
            for (j = 1; j <= length(ext); j++) {
                char = substr(ext, j, 1)
                if (char >= "A" && char <= "Z") {
                    ext_lower = ext_lower tolower(char)
                } else {
                    ext_lower = ext_lower char
                }
            }
            
            # Remove query parameters
            q_pos = index(ext_lower, "?")
            if (q_pos > 0) {
                ext_lower = substr(ext_lower, 1, q_pos - 1)
            }
            
            # Remove fragment
            h_pos = index(ext_lower, "#")
            if (h_pos > 0) {
                ext_lower = substr(ext_lower, 1, h_pos - 1)
            }
            
            # Check if extension is in exceptions
            if (ext_lower in file_exceptions) {
                return 0
            }
        }
        
        # Count this request
        return 1
    }
    
    {
        # Extract components from Apache access log
        log_ip = $1
        timestamp = substr($4, 2)  # Remove leading [
        
        # Extract the request line (between quotes)
        request_start = index($0, "\"")
        if (request_start > 0) {
            request_line = substr($0, request_start + 1)
            request_end = index(request_line, "\"")
            if (request_end > 0) {
                request_line = substr(request_line, 1, request_end - 1)
                
                # Parse method and path from request line
                split(request_line, request_parts, " ")
                method = request_parts[1]
                path = request_parts[2]
                
                # Check if this request should be counted
                if (log_ip == ip && timestamp >= since && should_count_request(path, method)) {
                    count++
                }
            }
        }
    }
    

    END { print count }
    ' "$APACHE_ACCESS_LOG"
}


# Query AbuseIPDB for IP reputation
check_abuseipdb() {
    local ip=$1
    
    if [[ -z "$ABUSEIPDB_API_KEY" ]]; then
        log_message "Error: AbuseIPDB API key not configured" >&2
        return 1
    fi
    
    local response=$(curl -s -G https://api.abuseipdb.com/api/v2/check \
        --data-urlencode "ipAddress=$ip" \
        -d maxAgeInDays=90 \
        -d verbose \
        -H "Key: $ABUSEIPDB_API_KEY" \
        -H "Accept: application/json")
    
    if [[ $? -ne 0 ]]; then
        log_message "Error: Failed to query AbuseIPDB for $ip" >&2
        return 1
    fi
    
    # Check for rate limit error (HTTP 429)
    if echo "$response" | grep -q '"status":429'; then
        log_message "Warning: AbuseIPDB rate limit exceeded. Skipping reputation check for $ip" >&2
        return 2  # Return 2 to indicate rate limit (different from other errors)
    fi
    
    # Check for other API errors
    if echo "$response" | grep -q '"errors":\['; then
        local error_detail=$(echo "$response" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4)
        log_message "Error: AbuseIPDB API error for $ip: ${error_detail:-"Unknown error"}"
        return 1
    fi
    
    # Extract confidence percentage from JSON response
    local confidence=$(echo "$response" | grep -o '"abuseConfidenceScore":[0-9]*' | cut -d':' -f2)
    
    if [[ -n "$confidence" ]]; then
        echo "$confidence"
        return 0
    else
        log_message "Error: Could not parse AbuseIPDB response for $ip" >&2
        return 1
    fi
}


# Block IP with iptables (with debug mode support)
block_ip() {
    local ip=$1
    local timestamp=$(date +%s)
    local confidence=$2  # Optional confidence parameter for email
    
    if [[ "$DEBUG_MODE" == "true" ]]; then
        # Debug mode: Send email instead of blocking
        local subject="[DEBUG] IP Protection System - Would Block IP: $ip"
        local body="IP Protection System Debug Alert

IP Address: $ip
Request Count: Exceeded threshold
AbuseIPDB Confidence: ${confidence:-"N/A"}%
Action: Would be blocked for $((BLOCK_DURATION / 3600)) hours
Timestamp: $(date)
Server: euagenda.eu

This is a DEBUG mode alert. No actual blocking has occurred.
To enable blocking, set DEBUG_MODE=false in the configuration.

Log details:
$(tail -n 10 "$LOG_FILE" | grep "$ip" || echo "No recent log entries found")"

        # Send email using mail command (requires mailutils)
        if command -v mail >/dev/null 2>&1; then
            echo "$body" | mail -s "$subject" "$DEBUG_EMAIL" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                log_message "DEBUG: Email sent for IP $ip (would be blocked with confidence ${confidence:-N/A}%)"
            else
                log_message "DEBUG: Failed to send email for IP $ip"
            fi
        else
            log_message "DEBUG: Would block IP $ip (confidence: ${confidence:-N/A}%) - mail command not available"
        fi
        
        # Log to file what would have been done
        log_message "DEBUG: Would block $ip for $((BLOCK_DURATION / 3600)) hours (confidence: ${confidence:-N/A}%)"
        
        return 0
    else
        # Production mode: Actually block the IP
        iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP
        
        if [[ $? -eq 0 ]]; then
            # Record blocked IP with timestamp
            echo "$ip $timestamp" >> "$BLOCKED_IPS_FILE"
            log_message "BLOCKED: $ip (will be unblocked at $(date -d "@$((timestamp + BLOCK_DURATION))"))"
            
            # Optionally send notification email in production too
            if [[ "$SEND_NOTIFICATIONS" == "true" ]] && command -v mail >/dev/null 2>&1; then
                local subject="IP Protection System - Blocked IP: $ip"
                local body="IP Protection System Alert

IP Address: $ip has been BLOCKED
AbuseIPDB Confidence: ${confidence:-"N/A"}%
Block Duration: $((BLOCK_DURATION / 3600)) hours
Will be unblocked at: $(date -d "@$((timestamp + BLOCK_DURATION))")
Server: euagenda.eu

This IP has been added to iptables DROP rules."

                echo "$body" | mail -s "$subject" "$NOTIFICATION_EMAIL" 2>/dev/null
            fi
            
            return 0
        else
            log_message "Error: Failed to block $ip with iptables"
            return 1
        fi
    fi
}

# Remove expired iptables rules
cleanup_expired_blocks() {
    local current_time=$(date +%s)
    local temp_file=$(mktemp)
    
    while read -r line; do
        if [[ -n "$line" ]]; then
            local ip=$(echo "$line" | awk '{print $1}')
            local block_time=$(echo "$line" | awk '{print $2}')
            local expire_time=$((block_time + BLOCK_DURATION))
            
            if [[ $current_time -ge $expire_time ]]; then
                # Remove iptables rule
                iptables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null
                log_message "UNBLOCKED: $ip (block expired)"
            else
                # Keep the entry
                echo "$line" >> "$temp_file"
            fi
        fi
    done < "$BLOCKED_IPS_FILE"
    
    mv "$temp_file" "$BLOCKED_IPS_FILE"
}


get_recent_ips() {
    local since_time=$(date -d "$TIME_WINDOW seconds ago" '+%d/%b/%Y:%H:%M:%S')
    
    awk -v since="$since_time" -v bot_whitelist="$BOT_WHITELIST" '
    BEGIN {
        # Convert bot whitelist to lowercase array
        if (bot_whitelist != "") {
            split(tolower(bot_whitelist), bots_array, ",")
            for (i in bots_array) {
                # Remove spaces
                gsub(/[ \t]/, "", bots_array[i])
                if (bots_array[i] != "") {
                    whitelisted_bots[bots_array[i]] = 1
                }
            }
        }
    }
    {
        timestamp = substr($4, 2)  # Remove leading [
        if (timestamp >= since) {
            ip = $1
            
            # Extract user agent (last quoted field)
            user_agent = ""
            quote_count = 0
            for (i = 1; i <= NF; i++) {
                if (index($i, "\"") > 0) {
                    quote_count++
                    if (quote_count == 6) {  # User agent is typically the 3rd quoted field (6th quote)
                        # Extract user agent from this field and remaining fields
                        user_agent = $i
                        for (j = i + 1; j <= NF; j++) {
                            user_agent = user_agent " " $j
                            if (index($j, "\"") > 0) break
                        }
                        # Remove quotes
                        gsub(/\"/, "", user_agent)
                        break
                    }
                }
            }
            
            # Check if user agent contains whitelisted bot
            is_bot_whitelisted = 0
            if (user_agent != "") {
                ua_lower = tolower(user_agent)
                for (bot in whitelisted_bots) {
                    if (index(ua_lower, bot) > 0) {
                        is_bot_whitelisted = 1
                        break
                    }
                }
            }
            
            # Only include IP if bot is not whitelisted
            if (!is_bot_whitelisted) {
                recent_ips[ip] = 1
            }
        }
    }
    END {
        for (ip in recent_ips) {
            print ip
        }
    }
    ' "$APACHE_ACCESS_LOG"
}


report_to_abuseipdb() {
    local ip=$1
    local request_count=$2
    
    if [[ -z "$ABUSEIPDB_API_KEY" ]]; then
        log_message "Warning: Cannot report $ip to AbuseIPDB - API key not configured"
        return 1
    fi
    
    log_message "Reporting $ip to AbuseIPDB for excessive requests ($request_count requests)"
    
    # Categories: 21 = Bad Web Bot, 16 = DDoS Attack
    local categories="21"
    local comment="Automated blocking: $request_count requests in ${TIME_WINDOW}s detected by server monitoring"
    
    local response=$(curl -s -X POST https://api.abuseipdb.com/api/v2/report \
        --data-urlencode "ip=$ip" \
        --data-urlencode "categories=$categories" \
        --data-urlencode "comment=$comment" \
        -H "Key: $ABUSEIPDB_API_KEY" \
        -H "Accept: application/json")
    
    if [[ $? -eq 0 ]]; then
        # Check if report was successful
        if echo "$response" | grep -q '"abuseConfidenceScore"'; then
            log_message "Successfully reported $ip to AbuseIPDB"
        elif echo "$response" | grep -q '"status":429'; then
            log_message "Warning: AbuseIPDB rate limit exceeded - could not report $ip"
        elif echo "$response" | grep -q '"errors":\['; then
            local error_detail=$(echo "$response" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4)
            log_message "Warning: Failed to report $ip to AbuseIPDB: ${error_detail:-"Unknown error"}"
        else
            log_message "Warning: Unexpected response when reporting $ip to AbuseIPDB"
        fi
    else
        log_message "Warning: Failed to connect to AbuseIPDB for reporting $ip"
    fi
}


# Main monitoring function
monitor_and_protect() {
    log_message "Starting IP protection monitoring"
    
    # Clean up expired blocks first
    cleanup_expired_blocks
    
    # Get list of recent IPs
    local recent_ips=$(get_recent_ips)
    
    for ip in $recent_ips; do
        # Skip if already blocked
        if is_ip_blocked "$ip"; then
            continue
        fi
        
        # Skip private/local IPs
        if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|localhost) ]]; then
            continue
        fi
        
        # Skip if IP is in whitelist subnets
        if is_ip_whitelisted "$ip"; then
            log_message "Skipping whitelisted IP: $ip"
            continue
        fi

        # Get request count for this IP
        local request_count=$(get_ip_request_count "$ip")
        
        if [[ $request_count -gt $REQUEST_THRESHOLD ]]; then
            log_message "High activity detected: $ip ($request_count requests in ${TIME_WINDOW}s)"
            
            # Block directly if activity is extremely high
            if [[ $request_count -gt $MAX_REQUEST_THRESHOLD ]]; then
                log_message "Extremely high activity detected: $ip ($request_count requests) - blocking immediately"
                block_ip "$ip" "high_activity"

                # Report to AbuseIPDB for bot behavior
                report_to_abuseipdb "$ip" "$request_count"
            else
                # Check AbuseIPDB reputation
                local confidence
                local api_result
                confidence=$(check_abuseipdb "$ip")
                api_result=$?

                if [[ $api_result -eq 2 ]]; then
                    log_message "Rate limit reached - skipping $ip for now"
                elif [[ $api_result -eq 0 && -n "$confidence" && "$confidence" =~ ^[0-9]+$ ]]; then
                    if [[ $confidence -ge $ABUSEIPDB_THRESHOLD ]]; then
                        log_message "Bad reputation confirmed: $ip (confidence: ${confidence}%)"
                        block_ip "$ip" "$confidence"
                    else
                        log_message "IP $ip has acceptable reputation (confidence: ${confidence}%)"
                        add_ip_to_checked_cache "$ip"
                    fi
                else
                    log_message "Could not check reputation for $ip - API error or invalid response"
                fi
            fi

        fi
    done
}

# Create configuration file template
create_config() {
    cat > "$CONFIG_FILE" << EOF
# IP Protection System Configuration

# AbuseIPDB API Key (required)
ABUSEIPDB_API_KEY="your_api_key_here"

# Request monitoring settings
REQUEST_THRESHOLD=50          # Requests in time window to trigger check
TIME_WINDOW=300              # Time window in seconds (5 minutes)

# AbuseIPDB settings
ABUSEIPDB_THRESHOLD=75       # Confidence threshold for blocking (%)

# Blocking settings
BLOCK_DURATION=86400         # Block duration in seconds (24 hours)

# System settings
CHECK_INTERVAL=60            # Check interval in seconds
APACHE_ACCESS_LOG="/var/log/apache2/access.log"
EOF
    
    echo "Configuration file created at: $CONFIG_FILE"
    echo "Please edit it and set your AbuseIPDB API key."
}

# Install as systemd service
install_service() {
    cat > /etc/systemd/system/ip-protection.service << EOF
[Unit]
Description=IP Protection System
After=network.target

[Service]
Type=simple
ExecStart=$SCRIPT_DIR/ip-protection.sh daemon
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ip-protection.service
    
    echo "Service installed. Start with: systemctl start ip-protection"
}

# Daemon mode
daemon_mode() {
    log_message "IP Protection daemon started"
    
    while true; do
        monitor_and_protect
        sleep "$CHECK_INTERVAL"
    done
}

# Show status
show_status() {
    echo "=== IP Protection System Status ==="
    echo "Configuration file: $CONFIG_FILE"
    echo "Log file: $LOG_FILE"
    echo "Blocked IPs file: $BLOCKED_IPS_FILE"
    echo
    echo "Currently blocked IPs:"
    if [[ -s "$BLOCKED_IPS_FILE" ]]; then
        while read -r line; do
            local ip=$(echo "$line" | awk '{print $1}')
            local block_time=$(echo "$line" | awk '{print $2}')
            local expire_time=$((block_time + BLOCK_DURATION))
            echo "  $ip (expires: $(date -d "@$expire_time"))"
        done < "$BLOCKED_IPS_FILE"
    else
        echo "  None"
    fi
    echo
    echo "IP Whitelist Subnets:"
    if [[ -n "$IP_WHITELIST_SUBNETS" ]]; then
        echo "  $IP_WHITELIST_SUBNETS" | tr ',' '\n' | sed 's/^/  /'
    else
        echo "  None configured"
    fi
    echo
    echo "Bot Whitelist:"
    if [[ -n "$BOT_WHITELIST" ]]; then
        echo "$BOT_WHITELIST" | tr ',' '\n' | sed 's/^/  /'
    else
        echo "  None configured"
    fi
    echo
    echo "Active iptables rules in $IPTABLES_CHAIN:"
    iptables -L "$IPTABLES_CHAIN" -n --line-numbers
}

# Unblock IP manually
unblock_ip() {
    local ip=$1
    
    if [[ -z "$ip" ]]; then
        echo "Usage: $0 unblock <ip_address>"
        return 1
    fi
    
    # Remove from iptables
    iptables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null
    
    # Remove from blocked IPs file
    grep -v "^$ip " "$BLOCKED_IPS_FILE" > "${BLOCKED_IPS_FILE}.tmp"
    mv "${BLOCKED_IPS_FILE}.tmp" "$BLOCKED_IPS_FILE"
    
    log_message "MANUALLY UNBLOCKED: $ip"
    echo "IP $ip has been unblocked"
}

# Main script logic
case "${1:-}" in
    "init")
        load_config
        initialize
        echo "IP Protection System initialized"
        ;;
    "config")
        create_config
        ;;
    "install")
        cp "$0" "$SCRIPT_DIR/ip-protection.sh"
        chmod +x "$SCRIPT_DIR/ip-protection.sh"
        install_service
        ;;
    "daemon")
        load_config
        initialize
        daemon_mode
        ;;
    "check")
        load_config
        initialize
        monitor_and_protect
        ;;
    "status")
        load_config
        show_status
        ;;
    "unblock")
        load_config
        unblock_ip "$2"
        ;;
    "cleanup")
        load_config
        cleanup_expired_blocks
        echo "Cleanup completed"
        ;;
    *)
        echo "Usage: $0 {init|config|install|daemon|check|status|unblock <ip>|cleanup}"
        echo
        echo "Commands:"
        echo "  init     - Initialize directories and iptables chain"
        echo "  config   - Create configuration file template"
        echo "  install  - Install as systemd service"
        echo "  daemon   - Run in daemon mode"
        echo "  check    - Run one-time check"
        echo "  status   - Show current status"
        echo "  unblock  - Manually unblock an IP"
        echo "  cleanup  - Remove expired blocks"
        exit 1
        ;;
esac
