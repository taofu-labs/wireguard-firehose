#!/usr/bin/env zsh

# ============================================================
# WireGuard Firehose - Auto-provisioning WireGuard Server
# ============================================================
# This entrypoint script automatically provisions a WireGuard
# server with client configurations on container startup.
# ============================================================

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Global error handler to log failures before exit
trap 'print "\033[0;31m[ERROR] Script failed at line $LINENO with exit code $?\033[0m" >&2; exit 1' ERR

# ------------------------------------------------------------
# Section 1: Color Logging Helpers
# ------------------------------------------------------------
# Terminal colors for visual feedback on container operations.
# Grey: informational, Green: success, Red: error, Orange: warning

readonly COLOR_GREY=$'\033[0;90m'
readonly COLOR_GREEN=$'\033[0;32m'
readonly COLOR_RED=$'\033[0;31m'
readonly COLOR_ORANGE=$'\033[0;33m'
readonly COLOR_RESET=$'\033[0m'

# Log informational message (grey) - nice to know, can be ignored
log_grey() {
    print "${COLOR_GREY}[INFO] $1${COLOR_RESET}" >&2
}

# Log success message (green) - explicit success
log_green() {
    print "${COLOR_GREEN}[SUCCESS] $1${COLOR_RESET}" >&2
}

# Log error message (red) - explicit failure (to stderr)
log_red() {
    print "${COLOR_RED}[ERROR] $1${COLOR_RESET}" >&2
}

# Log warning/suggestion message (orange)
log_orange() {
    print "${COLOR_ORANGE}[WARNING] $1${COLOR_RESET}" >&2
}


# ------------------------------------------------------------
# Section 2: Dependency and Capability Checks
# ------------------------------------------------------------
# Verify all required tools and container permissions are available
# before attempting any WireGuard operations.

check_dependencies() {
    log_grey "Checking required dependencies..."

    local dependencies=( "wg" "wg-quick" "ip" "iptables" "curl" "nc" "inotifywait" )
    local missing=()

    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=( "$dep" )
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_red "Missing dependencies: ${missing[*]}"
        exit 1
    fi

    log_green "All dependencies available"
}

check_capabilities() {
    log_grey "Checking container capabilities..."

    # Check if we can create a network interface (requires NET_ADMIN)
    if ! ip link add dummy0 type dummy 2>/dev/null; then
        log_red "Missing NET_ADMIN capability - cannot create network interfaces"
        log_orange "Run container with: --cap-add=NET_ADMIN"
        exit 1
    fi
    ip link delete dummy0 2>/dev/null

    # Check if /dev/net/tun exists (required for WireGuard)
    if [[ ! -c /dev/net/tun ]]; then
        log_red "TUN device not available at /dev/net/tun"
        log_orange "Ensure the container has access to /dev/net/tun"
        exit 1
    fi

    log_green "Container capabilities verified"
}

# Get the default network interface (for NAT rules)
# Falls back to eth0 if detection fails
get_default_interface() {
    local default_if=""

    # Try to get the default route interface
    default_if=$( ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' )

    # Security: Validate interface name format to prevent injection
    # Interface names should only contain alphanumeric, underscore, hyphen
    if [[ -n "$default_if" && "$default_if" =~ ^[a-zA-Z0-9_-]+$ ]] && ip link show "$default_if" &>/dev/null; then
        echo "$default_if"
    else
        if [[ -n "$default_if" && ! "$default_if" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            log_orange "Invalid interface name detected, falling back to eth0"
        else
            log_orange "Could not detect default interface, falling back to eth0"
        fi
        echo "eth0"
    fi
}


# ------------------------------------------------------------
# Section 3: System Configuration Verification
# ------------------------------------------------------------
# Verify kernel parameters required for WireGuard routing are set.
# These should be configured via docker-compose sysctls.

verify_sysctl_values() {
    log_grey "Verifying required sysctl values..."

    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    local src_valid_mark=$(sysctl -n net.ipv4.conf.all.src_valid_mark 2>/dev/null)

    if [[ "$ip_forward" != "1" ]]; then
        log_red "net.ipv4.ip_forward is not enabled"
        log_orange "Ensure docker-compose.yml includes: sysctls: - net.ipv4.ip_forward=1"
        exit 1
    fi

    if [[ "$src_valid_mark" != "1" ]]; then
        log_red "net.ipv4.conf.all.src_valid_mark is not enabled"
        log_orange "Ensure docker-compose.yml includes: sysctls: - net.ipv4.conf.all.src_valid_mark=1"
        exit 1
    fi

    log_green "Sysctl values verified"
}


# ------------------------------------------------------------
# Section 4: Validation Functions
# ------------------------------------------------------------
# Validate user-provided configuration values to ensure the
# container can operate correctly.

# Validate CIDR notation format and values
validate_cidr() {
    local cidr="$1"

    log_grey "Validating CIDR: $cidr"

    # Regex pattern for valid CIDR notation
    local cidr_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$'

    if [[ ! "$cidr" =~ $cidr_pattern ]]; then
        log_red "Invalid CIDR format: $cidr"
        log_orange "Expected format: x.x.x.x/y (e.g., 10.0.0.0/16)"
        exit 1
    fi

    # Validate each octet is 0-255
    local ip_part="${cidr%/*}"
    local octets=( ${(s:.:)ip_part} )

    for octet in "${octets[@]}"; do
        if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
            log_red "Invalid IP octet in CIDR: $octet"
            exit 1
        fi
    done

    log_green "CIDR format validated: $cidr"
}

# Calculate available IP addresses from CIDR
# Returns the number of usable client IPs (excluding network, broadcast, and server)
calculate_available_ips() {
    local cidr="$1"
    local prefix="${cidr#*/}"

    # Calculate total IPs: 2^(32 - prefix)
    # Subtract 2 for network and broadcast, subtract 1 for server (.1)
    local total_ips=$(( (2 ** (32 - prefix)) - 3 ))

    echo "$total_ips"
}

# Validate MAX_CONFIGS against available IPs in the subnet
validate_max_configs() {
    local max_configs="$1"
    local cidr="$2"

    # Check if MAX_CONFIGS is a positive integer
    if [[ ! "$max_configs" =~ ^[0-9]+$ ]] || [[ "$max_configs" -lt 1 ]]; then
        log_red "MAX_CONFIGS must be a positive integer: $max_configs"
        exit 1
    fi

    local available_ips=$( calculate_available_ips "$cidr" )

    if [[ "$max_configs" -gt "$available_ips" ]]; then
        log_red "MAX_CONFIGS ($max_configs) exceeds available IPs ($available_ips) for subnet $cidr"
        log_orange "Either increase subnet size or decrease MAX_CONFIGS"
        exit 1
    fi

    log_green "MAX_CONFIGS validated: $max_configs configs possible in $cidr (max: $available_ips)"
}

# Validate DNS_SERVERS format (comma-separated IPs)
validate_dns_servers() {
    local dns_servers="$1"

    log_grey "Validating DNS_SERVERS: $dns_servers"

    if [[ -z "$dns_servers" ]]; then
        log_red "DNS_SERVERS cannot be empty"
        exit 1
    fi

    # Split by comma and validate each IP
    local ips=( ${(s:,:)dns_servers} )

    for ip in "${ips[@]}"; do
        # Trim whitespace
        ip="${ip// /}"
        if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log_red "Invalid DNS server IP format: $ip"
            log_orange "Expected format: x.x.x.x (e.g., 1.1.1.1)"
            exit 1
        fi

        # Validate each octet is 0-255
        local octets=( ${(s:.:)ip} )
        for octet in "${octets[@]}"; do
            if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
                log_red "Invalid DNS server IP octet: $octet in $ip"
                log_orange "Each octet must be 0-255"
                exit 1
            fi
        done
    done

    log_green "DNS_SERVERS validated: $dns_servers"
}

# Validate ALLOWEDIPS format (comma-separated CIDRs)
validate_allowed_ips() {
    local allowed_ips="$1"

    log_grey "Validating ALLOWEDIPS: $allowed_ips"

    if [[ -z "$allowed_ips" ]]; then
        log_red "ALLOWEDIPS cannot be empty"
        exit 1
    fi

    # Split by comma and validate each CIDR
    local cidrs=( ${(s:,:)allowed_ips} )
    local cidr_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$'

    for cidr in "${cidrs[@]}"; do
        # Trim whitespace
        cidr="${cidr// /}"
        if [[ ! "$cidr" =~ $cidr_pattern ]]; then
            log_red "Invalid ALLOWEDIPS entry: $cidr"
            log_orange "Expected format: x.x.x.x/y (e.g., 0.0.0.0/0)"
            exit 1
        fi

        # Validate each octet is in range 0-255
        # Extract IP part (before the slash)
        local ip_part="${cidr%/*}"
        local octets=( ${(s:.:)ip_part} )
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                log_red "Invalid octet in ALLOWEDIPS: $octet (must be 0-255)"
                log_orange "Invalid CIDR: $cidr"
                exit 1
            fi
        done
    done

    log_green "ALLOWEDIPS validated: $allowed_ips"
}

# Validate FILENAME_FORMAT (ip or increment)
validate_filename_format() {
    local format="$1"

    log_grey "Validating FILENAME_FORMAT: $format"

    if [[ "$format" != "ip" && "$format" != "increment" ]]; then
        log_red "Invalid FILENAME_FORMAT: $format"
        log_orange "Valid values are: ip, increment"
        exit 1
    fi

    log_green "FILENAME_FORMAT validated: $format"
}

# Validate ISOLATE_CLIENTS (true or false)
validate_isolate_clients() {
    local value="$1"

    log_grey "Validating ISOLATE_CLIENTS: $value"

    if [[ "$value" != "true" && "$value" != "false" ]]; then
        log_red "Invalid ISOLATE_CLIENTS: $value"
        log_orange "Valid values are: true, false"
        exit 1
    fi

    log_green "ISOLATE_CLIENTS validated: $value"
}

# Validate WIREGUARD_PORT (1-65535)
validate_port() {
    local port="$1"

    log_grey "Validating WIREGUARD_PORT: $port"

    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        log_red "Invalid WIREGUARD_PORT: $port (must be a number)"
        exit 1
    fi

    if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        log_red "Invalid WIREGUARD_PORT: $port (must be 1-65535)"
        exit 1
    fi

    log_green "WIREGUARD_PORT validated: $port"
}

# Handle forced config regeneration
handle_force_regeneration() {
    if [[ "${FORCE_CONFIG_REGENERATION:-false}" == "true" ]]; then
        log_orange "FORCE_CONFIG_REGENERATION is enabled - removing all existing data"
        # (D) includes dotfiles, (N) prevents error if no matches
        rm -rf /configs/*(DN)
        rm -rf /keys/*(DN)
        rm -rf /regen_requests/*(DN)
        log_green "Removed: client configs, server keys, cached pubkeys, pending regen requests"
    fi
}


# ------------------------------------------------------------
# Section 5: Public IP Discovery
# ------------------------------------------------------------
# Discover the server's public IP using multiple services with failover.

get_public_ip() {
    log_grey "Discovering server public IP..."

    # Failover list of IP discovery services
    local services=(
        "https://icanhazip.com"
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://ipinfo.io/ip"
        "https://checkip.amazonaws.com"
    )

    local public_ip=""

    for service in "${services[@]}"; do
        log_grey "  Trying $service..."

        public_ip=$( curl -s --max-time 5 "$service" 2>/dev/null | tr -d '[:space:]' )

        # Validate the response looks like an IP address
        if [[ "$public_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log_green "Public IP discovered: $public_ip"
            echo "$public_ip"
            return 0
        fi
    done

    log_red "Failed to discover public IP from any service"
    exit 1
}


# ------------------------------------------------------------
# Section 6: WireGuard Key Management
# ------------------------------------------------------------
# Generate and manage WireGuard keypairs for server and clients.

# Generate a new keypair and return as "private:public"
generate_keypair() {
    local private_key=$( wg genkey )
    local public_key=$( echo "$private_key" | wg pubkey )

    echo "${private_key}:${public_key}"
}

# Pre-generate keypairs in batch for better performance
# Populates global KEYPAIR_BATCH array
typeset -ga KEYPAIR_BATCH
KEYPAIR_BATCH_INDEX=0

generate_keypair_batch() {
    local count="$1"
    KEYPAIR_BATCH=()
    KEYPAIR_BATCH_INDEX=0

    log_grey "Pre-generating $count keypairs (this improves performance)..."

    # Generate all private keys, then derive public keys in a pipeline
    # This is much faster than spawning 2 processes per keypair
    local privkeys=( $(for i in {1..$count}; do wg genkey; done) )

    for privkey in "${privkeys[@]}"; do
        local pubkey=$( echo "$privkey" | wg pubkey )
        KEYPAIR_BATCH+=( "${privkey}:${pubkey}" )
    done

    log_green "Pre-generated $count keypairs"
}

# Get next keypair from pre-generated batch
get_next_keypair() {
    if [[ "$KEYPAIR_BATCH_INDEX" -ge "${#KEYPAIR_BATCH[@]}" ]]; then
        # Fallback to single generation if batch exhausted
        generate_keypair
        return
    fi

    echo "${KEYPAIR_BATCH[$((++KEYPAIR_BATCH_INDEX))]}"
}

# Get or create server keys (persistent in /keys)
# Sets global variables: SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
get_or_create_server_keys() {
    local server_private_key_file="/keys/server_private_key"
    local server_public_key_file="/keys/server_public_key"
    local need_regenerate=0

    if [[ -f "$server_private_key_file" ]] && [[ -f "$server_public_key_file" ]]; then
        log_grey "Loading existing server keys..."
        SERVER_PRIVATE_KEY=$( tr -d '[:space:]' < "$server_private_key_file" )
        SERVER_PUBLIC_KEY=$( tr -d '[:space:]' < "$server_public_key_file" )

        # Validate key format (WireGuard keys are 44 chars base64)
        if [[ ${#SERVER_PRIVATE_KEY} -ne 44 ]]; then
            log_orange "Server private key is invalid (${#SERVER_PRIVATE_KEY} chars, expected 44)"
            need_regenerate=1
        elif [[ ${#SERVER_PUBLIC_KEY} -ne 44 ]]; then
            log_orange "Server public key is invalid (${#SERVER_PUBLIC_KEY} chars, expected 44)"
            need_regenerate=1
        else
            log_grey "Server keys validated"
        fi
    else
        need_regenerate=1
    fi

    if [[ "$need_regenerate" -eq 1 ]]; then
        log_grey "Generating new server keypair..."

        local keypair=$( generate_keypair )
        SERVER_PRIVATE_KEY="${keypair%:*}"
        SERVER_PUBLIC_KEY="${keypair#*:}"

        # Save keys for persistence across container restarts
        echo "$SERVER_PRIVATE_KEY" > "$server_private_key_file"
        echo "$SERVER_PUBLIC_KEY" > "$server_public_key_file"

        # Secure the private key file
        chmod 600 "$server_private_key_file"

        log_green "Server keypair generated and saved"
    else
        log_green "Using existing server keys"
    fi
}


# ------------------------------------------------------------
# Section 7: IP Address Management
# ------------------------------------------------------------
# Track and allocate IP addresses within the VPN subnet.

# Convert IP address to integer for arithmetic operations
ip_to_int() {
    local ip="$1"
    local octets=( ${(s:.:)ip} )
    echo $(( octets[1] * 16777216 + octets[2] * 65536 + octets[3] * 256 + octets[4] ))
}

# Convert integer back to IP address
int_to_ip() {
    local int="$1"
    echo "$(( int / 16777216 % 256 )).$(( int / 65536 % 256 )).$(( int / 256 % 256 )).$(( int % 256 ))"
}

# Calculate the server IP (first usable address in the subnet)
# For 10.0.0.0/16 -> 10.0.0.1
# For 10.0.1.128/25 -> 10.0.1.129
calculate_server_ip() {
    local cidr="$1"
    local network="${cidr%/*}"

    # Server IP is network address + 1
    local network_int=$( ip_to_int "$network" )
    local server_int=$(( network_int + 1 ))

    int_to_ip "$server_int"
}

# Get list of IPs already used by existing configs as a set (associative array for O(1) lookup)
# Populates the global USED_IPS_SET associative array
# Also tracks the highest peer number for increment mode
typeset -g NEXT_PEER_NUMBER=1

load_used_ips() {
    typeset -gA USED_IPS_SET
    USED_IPS_SET=()
    NEXT_PEER_NUMBER=1

    local highest_peer=0

    # Parse existing config files to extract their IPs
    # Use (N) glob qualifier to return empty list if no matches
    for config_file in /configs/*.conf(N); do
        [[ -f "$config_file" ]] || continue

        local filename=$( basename "$config_file" .conf )
        local client_ip=""

        # Try to get IP from filename first (ip format)
        if [[ "$filename" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            client_ip="$filename"
        else
            # Parse IP from Address line in config (increment format)
            client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null || true )
        fi

        if [[ -n "$client_ip" ]]; then
            USED_IPS_SET[$client_ip]=1
        fi

        # Track highest peer number for increment mode
        if [[ "$filename" =~ ^peer([0-9]+)$ ]]; then
            local peer_num="${match[1]}"
            if [[ "$peer_num" -gt "$highest_peer" ]]; then
                highest_peer="$peer_num"
            fi
        fi
    done

    NEXT_PEER_NUMBER=$(( highest_peer + 1 ))
}

# Check if an IP is already used (O(1) lookup)
is_ip_used() {
    local ip="$1"
    [[ -n "${USED_IPS_SET[$ip]:-}" ]]
}

# Mark an IP as used
mark_ip_used() {
    local ip="$1"
    USED_IPS_SET[$ip]=1
}

# Get count of used IPs
get_used_ip_count() {
    echo "${#USED_IPS_SET[@]}"
}

# IP iterator state (for efficient sequential allocation)
typeset -g NEXT_IP_INT=0
typeset -g END_IP_INT=0

# Initialize IP iterator for a subnet
init_ip_iterator() {
    local cidr="$1"
    local network="${cidr%/*}"
    local prefix="${cidr#*/}"

    local network_int=$( ip_to_int "$network" )
    local host_bits=$(( 32 - prefix ))
    local num_hosts=$(( 2 ** host_bits ))

    # Start from network + 2 (skip .0 network, .1 server)
    NEXT_IP_INT=$(( network_int + 2 ))
    END_IP_INT=$(( network_int + num_hosts - 2 ))  # Skip broadcast
}

# Get next available IP using iterator (O(1) amortized)
get_next_available_ip() {
    while [[ "$NEXT_IP_INT" -le "$END_IP_INT" ]]; do
        local ip=$( int_to_ip "$NEXT_IP_INT" )
        (( NEXT_IP_INT++ ))

        # O(1) lookup using associative array
        if ! is_ip_used "$ip"; then
            echo "$ip"
            return 0
        fi
    done

    return 1  # No available IPs
}


# ------------------------------------------------------------
# Section 8: Config Generation
# ------------------------------------------------------------
# Generate WireGuard configuration files for clients and server.

# Get the next peer number and increment counter
get_next_peer_number() {
    local num="$NEXT_PEER_NUMBER"
    (( ++NEXT_PEER_NUMBER ))
    echo "$num"
}

# Generate a client configuration file
# Also caches the public key for faster server config generation
generate_client_config() {
    local client_ip="$1"
    local client_private_key="$2"
    local client_public_key="$3"
    local server_public_key="$4"
    local server_endpoint="$5"
    local dns_servers="$6"
    local allowed_ips="$7"
    local filename_format="$8"

    local config_name
    if [[ "$filename_format" == "increment" ]]; then
        # Use global counter directly (avoids subshell overhead)
        config_name="peer${NEXT_PEER_NUMBER}"
        (( ++NEXT_PEER_NUMBER ))
    else
        config_name="${client_ip}"
    fi

    local config_file="/configs/${config_name}.conf"
    local pubkey_file="/keys/${client_ip}.pubkey"

    cat > "$config_file" << EOF
[Interface]
# Client configuration for ${client_ip}
PrivateKey = ${client_private_key}
Address = ${client_ip}/32
DNS = ${dns_servers}

[Peer]
# Server connection details
PublicKey = ${server_public_key}
AllowedIPs = ${allowed_ips}
Endpoint = ${server_endpoint}:${WIREGUARD_PORT}
PersistentKeepalive = 25
EOF

    chmod 600 "$config_file"

    # Cache the public key for faster server config regeneration (always keyed by IP)
    echo "$client_public_key" > "$pubkey_file"
    chmod 644 "$pubkey_file"
}

# Generate the server configuration with all client peers
# Uses cached public keys when available for performance
generate_server_config() {
    local server_ip="$1"
    local cidr="$2"
    local default_interface="$3"
    local isolate_clients="$4"

    log_grey "Generating server configuration (client isolation: $isolate_clients)..."

    # Create /etc/wireguard directory if it doesn't exist
    mkdir -p /etc/wireguard

    # Build peer sections for all client configs
    local peer_sections=""
    local client_count=0

    for config_file in /configs/*.conf(N); do
        [[ -f "$config_file" ]] || continue

        local filename=$( basename "$config_file" .conf )
        local client_ip=""

        # Get IP from filename (ip format) or from config content (increment format)
        if [[ "$filename" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            client_ip="$filename"
        else
            # Parse IP from Address line in config
            client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null || true )
        fi

        # Skip if we couldn't determine the IP
        [[ -n "$client_ip" ]] || continue

        local client_public_key=""
        local pubkey_file="/keys/${client_ip}.pubkey"

        # Try to use cached public key first (much faster)
        # Validate it's a proper 44-char base64 key
        if [[ -f "$pubkey_file" ]]; then
            client_public_key=$( tr -d '[:space:]' < "$pubkey_file" )
        fi

        # Validate key format (WireGuard keys are 44 chars base64)
        if [[ ${#client_public_key} -ne 44 ]]; then
            # Fall back to deriving from private key
            local client_private_key=$( grep "^PrivateKey" "$config_file" | sed 's/.*=\s*//' | tr -d '[:space:]' )
            if [[ ${#client_private_key} -eq 44 ]]; then
                client_public_key=$( echo "$client_private_key" | wg pubkey 2>/dev/null ) || {
                    log_orange "Skipping $client_ip: could not derive public key"
                    continue
                }
                # Cache it for next time
                echo "$client_public_key" > "$pubkey_file"
                chmod 644 "$pubkey_file"
            else
                log_orange "Skipping $client_ip: invalid private key in config"
                continue
            fi
        fi

        peer_sections+="
[Peer]
# Client ${client_ip}
PublicKey = ${client_public_key}
AllowedIPs = ${client_ip}/32
"
        (( ++client_count ))
    done

    # Build iptables rules based on client isolation setting
    local post_up=""
    local post_down=""

    if [[ "$isolate_clients" == "true" ]]; then
        # Isolated: clients can only reach internet, not each other
        post_up="iptables -A FORWARD -i %i -o ${default_interface} -j ACCEPT; iptables -A FORWARD -i ${default_interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE"
        post_down="iptables -D FORWARD -i %i -o ${default_interface} -j ACCEPT; iptables -D FORWARD -i ${default_interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE"
    else
        # Not isolated: clients can communicate with each other
        post_up="iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE"
        post_down="iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE"
    fi

    # Write server config with NAT rules for routing client traffic
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
# WireGuard Firehose Server
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = ${server_ip}/${cidr#*/}
ListenPort = ${WIREGUARD_PORT}

# NAT rules (client isolation: ${isolate_clients})
PostUp = ${post_up}
PostDown = ${post_down}
${peer_sections}
EOF

    chmod 600 /etc/wireguard/wg0.conf
    log_green "Server configuration generated with $client_count peers"
}

# Generate missing client configs up to MAX_CONFIGS
generate_missing_configs() {
    local cidr="$1"
    local max_configs="$2"
    local server_endpoint="$3"
    local filename_format="$4"

    log_grey "Checking for existing configurations..."

    # Load used IPs into associative array for O(1) lookup
    load_used_ips
    local existing_count=$( get_used_ip_count )

    log_grey "Found $existing_count existing configurations"

    # Calculate how many to generate
    local to_generate=$(( max_configs - existing_count ))

    if [[ "$to_generate" -le 0 ]]; then
        log_green "All $max_configs configurations already exist"
        return 0
    fi

    log_grey "Generating $to_generate new configurations (format: $filename_format)..."

    # ================================================================
    # PERFORMANCE OPTIMIZATION: Pre-generate all keypairs in batch
    # ================================================================
    # Instead of spawning 2 processes (wg genkey + wg pubkey) per config,
    # we generate all keypairs upfront. This batches the CPU-intensive
    # cryptographic work together before we start doing file I/O.
    generate_keypair_batch "$to_generate"

    # Initialize IP iterator for efficient allocation
    init_ip_iterator "$cidr"

    local generated=0
    local last_logged_percent=0

    # ================================================================
    # PERFORMANCE OPTIMIZATION: Inlined hot-path variables
    # ================================================================
    # We declare these outside the loop to avoid repeated 'local' overhead.
    # These hold the current client's data for each iteration.
    local client_ip=""
    local keypair=""
    local client_private_key=""
    local client_public_key=""

    while [[ "$generated" -lt "$to_generate" ]]; do

        # ============================================================
        # INLINED: get_next_available_ip()
        # ============================================================
        # Original function spawned a subshell and called int_to_ip()
        # which spawned another subshell. For 50k configs = 100k subshells.
        #
        # Now we inline both:
        # - The IP iterator loop (find next unused IP)
        # - The int_to_ip conversion (integer to dotted-quad string)
        #
        # How it works:
        # - NEXT_IP_INT holds the current IP as a 32-bit integer
        # - END_IP_INT is the last usable IP in the subnet
        # - USED_IPS_SET is an associative array for O(1) "is used?" lookup
        # - We convert integer to IP using division/modulo on each octet:
        #   - Octet 1 (leftmost):  int / 16777216 (2^24) % 256
        #   - Octet 2:             int / 65536    (2^16) % 256
        #   - Octet 3:             int / 256      (2^8)  % 256
        #   - Octet 4 (rightmost): int % 256
        # ============================================================
        client_ip=""
        while [[ "$NEXT_IP_INT" -le "$END_IP_INT" ]]; do
            # Convert integer to dotted-quad IP address (inlined int_to_ip)
            client_ip="$(( NEXT_IP_INT / 16777216 % 256 )).$(( NEXT_IP_INT / 65536 % 256 )).$(( NEXT_IP_INT / 256 % 256 )).$(( NEXT_IP_INT % 256 ))"

            # Advance iterator for next iteration
            (( NEXT_IP_INT++ ))

            # Check if this IP is already used (O(1) associative array lookup)
            # If not used, we found our IP - break out of the search loop
            if [[ -z "${USED_IPS_SET[$client_ip]:-}" ]]; then
                break
            fi

            # IP was used, clear it and try next
            client_ip=""
        done

        # Check if we exhausted the IP range
        if [[ -z "$client_ip" ]]; then
            log_orange "No more IPs available in subnet"
            break
        fi

        # ============================================================
        # INLINED: get_next_keypair()
        # ============================================================
        # Original function spawned a subshell to return the keypair.
        # For 50k configs = 50k subshells just for this.
        #
        # Now we access the pre-generated KEYPAIR_BATCH array directly:
        # - KEYPAIR_BATCH_INDEX tracks our position (1-based for zsh)
        # - Pre-increment (++INDEX) then access array
        # - Each entry is "privatekey:publickey" format
        # - We split using zsh parameter expansion:
        #   - ${var%:*} = everything before the last ':'
        #   - ${var#*:} = everything after the first ':'
        # ============================================================
        (( ++KEYPAIR_BATCH_INDEX ))
        keypair="${KEYPAIR_BATCH[$KEYPAIR_BATCH_INDEX]}"

        # Safety check: ensure keypair was retrieved successfully
        if [[ -z "$keypair" ]]; then
            log_red "Keypair batch exhausted unexpectedly at index $KEYPAIR_BATCH_INDEX"
            exit 1
        fi

        client_private_key="${keypair%:*}"
        client_public_key="${keypair#*:}"

        # Generate the config file (this still does file I/O, unavoidable)
        generate_client_config \
            "$client_ip" \
            "$client_private_key" \
            "$client_public_key" \
            "$SERVER_PUBLIC_KEY" \
            "$server_endpoint" \
            "$DNS_SERVERS" \
            "$ALLOWEDIPS" \
            "$filename_format"

        # ============================================================
        # INLINED: mark_ip_used()
        # ============================================================
        # Original was a trivial function, but still spawned a subshell
        # due to the function call overhead. Now we just set directly.
        # ============================================================
        USED_IPS_SET[$client_ip]=1

        (( ++generated ))

        # Progress logging every 10%
        # (kept as-is since it only runs ~10 times total, not per-iteration)
        local current_percent=$(( generated * 100 / to_generate ))
        if [[ $(( current_percent / 10 )) -gt $(( last_logged_percent / 10 )) ]]; then
            local display_percent=$(( (current_percent / 10) * 10 ))
            log_grey "Progress ${display_percent}% ($generated/$to_generate)"
            last_logged_percent="$current_percent"
        fi
    done

    log_green "Generated $generated new configurations"
}


# ------------------------------------------------------------
# Section 9: WireGuard Server Management
# ------------------------------------------------------------
# Start and manage the WireGuard interface with graceful shutdown.

# Graceful shutdown handler
shutdown_wireguard() {
    log_grey "Received shutdown signal..."

    # Stop the key regeneration watcher
    if [[ "$REGEN_WATCHER_PID" -gt 0 ]]; then
        log_grey "Stopping key regeneration watcher (PID: $REGEN_WATCHER_PID)..."
        kill "$REGEN_WATCHER_PID" 2>/dev/null || true
        wait "$REGEN_WATCHER_PID" 2>/dev/null || true
    fi

    # Stop WireGuard
    if wg show wg0 &>/dev/null; then
        log_grey "Stopping WireGuard..."
        wg-quick down wg0
        log_green "WireGuard stopped gracefully"
    fi

    exit 0
}

# Set up signal handlers for graceful shutdown
setup_signal_handlers() {
    trap shutdown_wireguard SIGTERM SIGINT SIGHUP
}

start_wireguard() {
    log_grey "Starting WireGuard server..."

    # Bring up the WireGuard interface
    if wg-quick up wg0; then
        log_green "WireGuard server started successfully"

        # Display summary interface info (suppress peer list for large configs)
        local peer_count=$( wg show wg0 peers | wc -l )
        log_grey "Interface: wg0"
        log_grey "Public key: $( wg show wg0 public-key )"
        log_grey "Listen port: $( wg show wg0 listen-port )"
        log_grey "Connected peers: $peer_count"
    else
        log_red "Failed to start WireGuard server"
        exit 1
    fi
}

# Keep container running while handling signals
wait_forever() {
    log_grey "Container running. Press Ctrl+C or send SIGTERM to stop."

    # Wait indefinitely while allowing signal handling
    while true; do
        sleep 86400 &
        wait $! || true
    done
}


# ------------------------------------------------------------
# Section 10: Key Regeneration Watcher
# ------------------------------------------------------------
# Watch for regeneration requests and hot-swap client keys.

# Global PID for the background watcher (for cleanup on shutdown)
typeset -g REGEN_WATCHER_PID=0

# Regenerate keys for a specific client config
# Usage: regenerate_client_keys <identifier>
# Where identifier is either an IP (10.0.0.5) or peer name (peer5)
regenerate_client_keys() {
    local identifier="$1"
    local client_ip=""
    local config_file=""

    # Security: Validate identifier format strictly to prevent path traversal
    # Only allow: IP addresses (10.0.0.5) or peer names (peer5)
    if [[ ! "$identifier" =~ ^(peer[0-9]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$ ]]; then
        log_red "Invalid identifier format: $identifier (must be IP or peerN)"
        return 1
    fi

    # Additional validation: if IP format, validate each octet is 0-255
    if [[ "$identifier" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local octets=( ${(s:.:)identifier} )
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                log_red "Invalid IP octet in identifier: $octet (must be 0-255)"
                return 1
            fi
        done
    fi

    # Determine if identifier is an IP or peer name
    if [[ "$identifier" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        client_ip="$identifier"
        # Try IP-based filename first, then search for peer file
        if [[ -f "/configs/${client_ip}.conf" ]]; then
            config_file="/configs/${client_ip}.conf"
        else
            # Search for config with this IP in Address field
            config_file=$( grep -l "Address = ${client_ip}/32" /configs/*.conf 2>/dev/null | head -1 )
        fi
    elif [[ "$identifier" =~ ^peer[0-9]+$ ]]; then
        config_file="/configs/${identifier}.conf"
        if [[ -f "$config_file" ]]; then
            # Extract IP from config
            client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null )
        fi
    else
        log_red "Invalid identifier format: $identifier (expected IP or peerN)"
        return 1
    fi

    # Validate we found the config
    if [[ -z "$config_file" || ! -f "$config_file" ]]; then
        log_red "Config file not found for: $identifier"
        return 1
    fi

    if [[ -z "$client_ip" ]]; then
        log_red "Could not determine IP for: $identifier"
        return 1
    fi

    local pubkey_file="/keys/${client_ip}.pubkey"

    # Get old public key (needed to remove from WireGuard)
    local old_pubkey=""
    if [[ -f "$pubkey_file" ]]; then
        old_pubkey=$( tr -d '[:space:]' < "$pubkey_file" )
    fi

    # Validate or derive old public key
    if [[ ${#old_pubkey} -ne 44 ]]; then
        # Derive from config's private key
        local old_privkey=$( grep "^PrivateKey" "$config_file" | sed 's/.*=\s*//' | tr -d '[:space:]' )
        if [[ ${#old_privkey} -eq 44 ]]; then
            old_pubkey=$( echo "$old_privkey" | wg pubkey 2>/dev/null ) || old_pubkey=""
        fi
    fi

    log_grey "Regenerating keys for $identifier ($client_ip)..."

    # Generate new keypair
    local keypair=$( generate_keypair )
    local new_private_key="${keypair%:*}"
    local new_public_key="${keypair#*:}"

    # Define temp file paths for atomic writes
    local temp_config="${config_file}.tmp.$$"
    local temp_pubkey="${pubkey_file}.tmp.$$"

    # Cleanup function for temp files on error
    cleanup_temp_files() {
        rm -f "$temp_config" "$temp_pubkey" 2>/dev/null || true
    }

    # Update config file with new private key (atomic write via temp file + rename)
    if ! sed "s|^PrivateKey = .*|PrivateKey = ${new_private_key}|" "$config_file" > "$temp_config"; then
        cleanup_temp_files
        log_red "Failed to create temp config file"
        return 1
    fi
    chmod 600 "$temp_config"

    # Update cached public key (atomic write)
    if ! echo "$new_public_key" > "$temp_pubkey"; then
        cleanup_temp_files
        log_red "Failed to create temp pubkey file"
        return 1
    fi
    chmod 644 "$temp_pubkey"

    # Atomic moves (these should not fail, but if they do, cleanup)
    if ! mv "$temp_config" "$config_file"; then
        cleanup_temp_files
        log_red "Failed to move temp config file"
        return 1
    fi

    if ! mv "$temp_pubkey" "$pubkey_file"; then
        # Config was already updated, pubkey move failed - try to cleanup
        rm -f "$temp_pubkey" 2>/dev/null || true
        log_red "Failed to move temp pubkey file"
        return 1
    fi

    # Hot-swap peer in WireGuard interface
    if [[ -n "$old_pubkey" ]]; then
        wg set wg0 peer "$old_pubkey" remove 2>/dev/null || true
    fi
    wg set wg0 peer "$new_public_key" allowed-ips "${client_ip}/32"

    log_green "Keys regenerated for $identifier ($client_ip)"
    return 0
}

# Process all pending regeneration requests
process_regen_requests() {
    for request_file in /regen_requests/*(N); do
        [[ -f "$request_file" ]] || continue

        local identifier=$( basename "$request_file" )

        # Skip hidden files and temp files
        [[ "$identifier" == .* ]] && continue

        if regenerate_client_keys "$identifier"; then
            rm -f "$request_file"
        else
            log_orange "Failed to process regen request: $identifier (file kept for retry)"
        fi
    done
}

# Start the inotifywait watcher as a background process
start_regen_watcher() {
    log_grey "Starting key regeneration watcher..."

    # Process any existing requests first
    process_regen_requests

    # Start watching for new requests in background
    (
        inotifywait -m -e create -e moved_to --format '%f' /regen_requests 2>/dev/null | while read identifier; do
            # Skip hidden files and temp files
            [[ "$identifier" == .* ]] && continue

            # Small delay to ensure file is fully written
            sleep 0.1

            if [[ -f "/regen_requests/${identifier}" ]]; then
                if regenerate_client_keys "$identifier"; then
                    rm -f "/regen_requests/${identifier}"
                fi
            fi
        done
    ) &
    REGEN_WATCHER_PID=$!

    log_green "Key regeneration watcher started (PID: $REGEN_WATCHER_PID)"
}


# ------------------------------------------------------------
# Section 11: Main Execution
# ------------------------------------------------------------
# Orchestrate the complete setup process.

main() {
    echo ""
    echo "============================================================"
    echo "  WireGuard Firehose - Auto-provisioning Server"
    echo "============================================================"
    echo ""

    # Set up signal handlers for graceful shutdown
    setup_signal_handlers

    # Step 1: Check dependencies and capabilities
    check_dependencies
    check_capabilities

    # Step 2: Verify system configuration (set via docker-compose sysctls)
    verify_sysctl_values

    # Step 3: Validate all configuration
    validate_port "$WIREGUARD_PORT"
    validate_cidr "$INTERNAL_SUBNET_CIDR"
    validate_max_configs "$MAX_CONFIGS" "$INTERNAL_SUBNET_CIDR"
    validate_dns_servers "$DNS_SERVERS"
    validate_allowed_ips "$ALLOWEDIPS"
    validate_filename_format "$FILENAME_FORMAT"
    validate_isolate_clients "$ISOLATE_CLIENTS"

    # Step 4: Handle forced regeneration (before anything else touches configs)
    handle_force_regeneration

    # Step 5: Detect default network interface for NAT
    local default_interface=$( get_default_interface )
    log_grey "Using network interface: $default_interface"

    # Step 6: Discover public IP for client configs
    local public_ip=$( get_public_ip )

    # Step 7: Initialize server keys (persistent across restarts)
    get_or_create_server_keys

    # Step 8: Calculate server IP (first usable address in subnet)
    local server_ip=$( calculate_server_ip "$INTERNAL_SUBNET_CIDR" )
    log_grey "Server internal IP: $server_ip"

    # Step 9: Ensure directories exist
    mkdir -p /configs
    mkdir -p /keys
    mkdir -p /regen_requests

    # Step 10: Generate missing client configs
    generate_missing_configs "$INTERNAL_SUBNET_CIDR" "$MAX_CONFIGS" "$public_ip" "$FILENAME_FORMAT"

    # Step 11: Generate server config with all client peers
    generate_server_config "$server_ip" "$INTERNAL_SUBNET_CIDR" "$default_interface" "$ISOLATE_CLIENTS"

    # Step 12: Start WireGuard server
    start_wireguard

    # Step 13: Start key regeneration watcher
    start_regen_watcher

    log_green "WireGuard Firehose is ready!"
    log_grey "Client configs available in /configs"
    log_grey "To regenerate keys: touch regen_requests/<ip-or-peer-name>"

    # Keep container running with proper signal handling
    wait_forever
}

main "$@"
