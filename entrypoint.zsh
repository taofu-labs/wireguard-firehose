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
    local ip_mode="${1:-ipv4}"

    log_grey "Checking required dependencies for IP_MODE=$ip_mode..."

    local dependencies=( "wg" "wg-quick" "ip" "curl" "nc" "inotifywait" )

    # Add iptables for IPv4 modes
    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        dependencies+=( "iptables" )
    fi

    # Add ip6tables for IPv6 modes
    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        dependencies+=( "ip6tables" )
    fi

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
    local ip_mode="${1:-ipv4}"

    log_grey "Verifying required sysctl values for IP_MODE=$ip_mode..."

    # Check IPv4 sysctls for ipv4 and dual modes
    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
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
    fi

    # Check IPv6 sysctls for ipv6 and dual modes
    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        local ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)

        if [[ "$ipv6_forward" != "1" ]]; then
            log_red "net.ipv6.conf.all.forwarding is not enabled"
            log_orange "Ensure docker-compose.yml includes: sysctls: - net.ipv6.conf.all.forwarding=1"
            exit 1
        fi
    fi

    log_green "Sysctl values verified for IP_MODE=$ip_mode"
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

# Validate IPv6 CIDR notation format and values
validate_cidr_v6() {
    local cidr="$1"

    log_grey "Validating IPv6 CIDR: $cidr"

    # Extract address and prefix
    local addr="${cidr%/*}"
    local prefix="${cidr#*/}"

    # Validate prefix exists and is 0-128
    if [[ -z "$prefix" || ! "$prefix" =~ ^[0-9]+$ ]]; then
        log_red "Invalid IPv6 CIDR format: $cidr (missing or invalid prefix)"
        log_orange "Expected format: xxxx:xxxx::xxxx/yy (e.g., fd00::/64)"
        exit 1
    fi

    if [[ "$prefix" -lt 0 || "$prefix" -gt 128 ]]; then
        log_red "Invalid IPv6 prefix length: $prefix (must be 0-128)"
        exit 1
    fi

    # Validate IPv6 address format (simplified check for valid hex groups separated by colons)
    # IPv6 addresses consist of up to 8 groups of 4 hex digits, with :: compression allowed
    if [[ ! "$addr" =~ ^[0-9a-fA-F:]+$ ]]; then
        log_red "Invalid IPv6 address format: $addr"
        log_orange "IPv6 addresses should contain only hex digits and colons"
        exit 1
    fi

    # Check for valid :: usage (only one allowed)
    local double_colon_count=$(echo "$addr" | grep -o '::' | wc -l)
    if [[ "$double_colon_count" -gt 1 ]]; then
        log_red "Invalid IPv6 address: $addr (multiple :: not allowed)"
        exit 1
    fi

    log_green "IPv6 CIDR format validated: $cidr"
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
# Parameters:
#   $1 - dns_servers: comma-separated list of DNS server IPs
#   $2 - allow_v6: "true" to allow IPv6 addresses, "false" for IPv4 only (default: "false")
validate_dns_servers() {
    local dns_servers="$1"
    local allow_v6="${2:-false}"

    log_grey "Validating DNS_SERVERS: $dns_servers (IPv6 allowed: $allow_v6)"

    if [[ -z "$dns_servers" ]]; then
        log_red "DNS_SERVERS cannot be empty"
        exit 1
    fi

    # Split by comma and validate each IP
    local ips=( ${(s:,:)dns_servers} )

    for ip in "${ips[@]}"; do
        # Trim whitespace
        ip="${ip// /}"

        # Check for IPv4 format
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            # Validate each octet is 0-255
            local octets=( ${(s:.:)ip} )
            for octet in "${octets[@]}"; do
                if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
                    log_red "Invalid DNS server IP octet: $octet in $ip"
                    log_orange "Each octet must be 0-255"
                    exit 1
                fi
            done
        # Check for IPv6 format (hex digits and colons)
        elif [[ "$allow_v6" == "true" && "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
            # Validate IPv6: only one :: allowed
            local double_colon_count=$(echo "$ip" | grep -o '::' | wc -l)
            if [[ "$double_colon_count" -gt 1 ]]; then
                log_red "Invalid IPv6 DNS server: $ip (multiple :: not allowed)"
                exit 1
            fi
        else
            if [[ "$allow_v6" == "true" ]]; then
                log_red "Invalid DNS server IP format: $ip"
                log_orange "Expected IPv4 (x.x.x.x) or IPv6 (xxxx:xxxx::xxxx)"
            else
                log_red "Invalid DNS server IP format: $ip"
                log_orange "Expected format: x.x.x.x (e.g., 1.1.1.1)"
            fi
            exit 1
        fi
    done

    log_green "DNS_SERVERS validated: $dns_servers"
}

# Validate ALLOWEDIPS format (comma-separated CIDRs)
# Parameters:
#   $1 - allowed_ips: comma-separated list of CIDRs
#   $2 - allow_v6: "true" to allow IPv6 CIDRs, "false" for IPv4 only (default: "false")
validate_allowed_ips() {
    local allowed_ips="$1"
    local allow_v6="${2:-false}"

    log_grey "Validating ALLOWEDIPS: $allowed_ips (IPv6 allowed: $allow_v6)"

    if [[ -z "$allowed_ips" ]]; then
        log_red "ALLOWEDIPS cannot be empty"
        exit 1
    fi

    # Split by comma and validate each CIDR
    local cidrs=( ${(s:,:)allowed_ips} )
    local cidr_v4_pattern='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$'
    local cidr_v6_pattern='^[0-9a-fA-F:]+/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$'

    for cidr in "${cidrs[@]}"; do
        # Trim whitespace
        cidr="${cidr// /}"

        # Check for IPv4 CIDR format
        if [[ "$cidr" =~ $cidr_v4_pattern ]]; then
            # Validate each octet is in range 0-255
            local ip_part="${cidr%/*}"
            local octets=( ${(s:.:)ip_part} )
            for octet in "${octets[@]}"; do
                if (( octet < 0 || octet > 255 )); then
                    log_red "Invalid octet in ALLOWEDIPS: $octet (must be 0-255)"
                    log_orange "Invalid CIDR: $cidr"
                    exit 1
                fi
            done
        # Check for IPv6 CIDR format
        elif [[ "$allow_v6" == "true" && "$cidr" =~ $cidr_v6_pattern ]]; then
            # Extract address part and validate
            local addr="${cidr%/*}"
            # Check for valid :: usage (only one allowed)
            local double_colon_count=$(echo "$addr" | grep -o '::' | wc -l)
            if [[ "$double_colon_count" -gt 1 ]]; then
                log_red "Invalid IPv6 CIDR: $cidr (multiple :: not allowed)"
                exit 1
            fi
        else
            if [[ "$allow_v6" == "true" ]]; then
                log_red "Invalid ALLOWEDIPS entry: $cidr"
                log_orange "Expected IPv4 CIDR (x.x.x.x/y) or IPv6 CIDR (xxxx::xxxx/yy)"
            else
                log_red "Invalid ALLOWEDIPS entry: $cidr"
                log_orange "Expected format: x.x.x.x/y (e.g., 0.0.0.0/0)"
            fi
            exit 1
        fi
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

# Validate IP_MODE (ipv4, ipv6, or dual)
validate_ip_mode() {
    local mode="$1"

    log_grey "Validating IP_MODE: $mode"

    if [[ "$mode" != "ipv4" && "$mode" != "ipv6" && "$mode" != "dual" ]]; then
        log_red "Invalid IP_MODE: $mode"
        log_orange "Valid values are: ipv4, ipv6, dual"
        exit 1
    fi

    log_green "IP_MODE validated: $mode"
}

# Validate WIREGUARD_PORT (1-65535)
validate_port() {
    local port="$1"
    local var_name="${2:-WIREGUARD_PORT}"

    log_grey "Validating ${var_name}: $port"

    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        log_red "Invalid ${var_name}: $port (must be a number)"
        exit 1
    fi

    if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        log_red "Invalid ${var_name}: $port (must be 1-65535)"
        exit 1
    fi

    log_green "${var_name} validated: $port"
}

# Validate PERSISTENT_KEEPALIVE (empty or 1-65535)
validate_persistent_keepalive() {
    local value="${1:-}"

    # Empty value is valid (means no PersistentKeepalive line in config)
    if [[ -z "$value" ]]; then
        log_grey "PERSISTENT_KEEPALIVE: not set (no keepalive line in client configs)"
        return 0
    fi

    log_grey "Validating PERSISTENT_KEEPALIVE: $value"

    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        log_red "Invalid PERSISTENT_KEEPALIVE: $value (must be a number)"
        exit 1
    fi

    if [[ "$value" -lt 1 || "$value" -gt 65535 ]]; then
        log_red "Invalid PERSISTENT_KEEPALIVE: $value (must be 1-65535)"
        exit 1
    fi

    log_green "PERSISTENT_KEEPALIVE validated: $value"
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

# Discover the server's public IPv6 address using multiple services with failover.
# Returns empty string if no IPv6 connectivity (non-fatal)
get_public_ip_v6() {
    log_grey "Discovering server public IPv6..."

    # Failover list of IPv6 discovery services
    # Use curl -6 to force IPv6 resolution
    local services=(
        "https://ipv6.icanhazip.com"
        "https://api64.ipify.org"
        "https://ifconfig.co"
        "https://v6.ident.me"
    )

    local public_ip_v6=""

    for service in "${services[@]}"; do
        log_grey "  Trying $service..."

        public_ip_v6=$( curl -6 -s --max-time 5 "$service" 2>/dev/null | tr -d '[:space:]' )

        # Validate the response looks like an IPv6 address (contains colons)
        if [[ "$public_ip_v6" =~ ^[0-9a-fA-F:]+$ && "$public_ip_v6" == *":"* ]]; then
            log_green "Public IPv6 discovered: $public_ip_v6"
            echo "$public_ip_v6"
            return 0
        fi
    done

    log_orange "Could not discover public IPv6 address (IPv6 may not be available)"
    echo ""
    return 1
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

# Pre-generate preshared keys in batch for better performance
# Populates global PSK_BATCH array
typeset -ga PSK_BATCH
PSK_BATCH_INDEX=0

generate_keypair_batch() {
    local count="$1"
    KEYPAIR_BATCH=()
    KEYPAIR_BATCH_INDEX=0
    PSK_BATCH=()
    PSK_BATCH_INDEX=0

    log_grey "Pre-generating $count keypairs and preshared keys (this improves performance)..."

    # Generate all private keys, then derive public keys in a pipeline
    # This is much faster than spawning 2 processes per keypair
    local privkeys=( $(for i in {1..$count}; do wg genkey; done) )

    for privkey in "${privkeys[@]}"; do
        local pubkey=$( echo "$privkey" | wg pubkey )
        KEYPAIR_BATCH+=( "${privkey}:${pubkey}" )
    done

    # Generate all preshared keys in batch
    local psks=( $(for i in {1..$count}; do wg genpsk; done) )
    PSK_BATCH=( "${psks[@]}" )

    log_green "Pre-generated $count keypairs and preshared keys"
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
# Populates the global USED_IPS_SET and USED_IPS_SET_V6 associative arrays
# Also tracks the highest peer number for increment mode
typeset -g NEXT_PEER_NUMBER=1

load_used_ips() {
    typeset -gA USED_IPS_SET
    typeset -gA USED_IPS_SET_V6
    USED_IPS_SET=()
    USED_IPS_SET_V6=()
    NEXT_PEER_NUMBER=1

    local highest_peer=0

    # Parse existing config files to extract their IPs
    # Use (N) glob qualifier to return empty list if no matches
    for config_file in /configs/*.conf(N); do
        [[ -f "$config_file" ]] || continue

        local filename=$( basename "$config_file" .conf )
        local client_ip=""
        local client_ip_v6=""

        # Try to get IPv4 from filename first (ip format)
        if [[ "$filename" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            client_ip="$filename"
        else
            # Parse IPv4 from Address line in config (increment format or dual-stack)
            client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null || true )
        fi

        # Parse IPv6 from Address line (may be comma-separated with IPv4)
        # Match IPv6 addresses (simplified: hex:hex::hex format)
        client_ip_v6=$( grep -oP '^Address\s*=.*\K[0-9a-fA-F:]+::[0-9a-fA-F:]+' "$config_file" 2>/dev/null | head -1 || true )
        # Also try sanitized filename format (colons replaced with dashes)
        if [[ -z "$client_ip_v6" && "$filename" =~ ^fd[0-9a-fA-F-]+ ]]; then
            # Restore colons from dashes for tracking
            client_ip_v6="${filename//-/:}"
        fi

        if [[ -n "$client_ip" ]]; then
            USED_IPS_SET[$client_ip]=1
        fi

        if [[ -n "$client_ip_v6" ]]; then
            USED_IPS_SET_V6[$client_ip_v6]=1
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
# Section 7b: IPv6 Address Management
# ------------------------------------------------------------
# Track and allocate IPv6 addresses within the VPN subnet.
# Since zsh cannot handle 128-bit integers, we use a sequential suffix approach
# for /64 subnets: fd00::1 (server), fd00::2, fd00::3, etc.

# Global state for IPv6 address tracking
typeset -gA USED_IPS_SET_V6
typeset -g NEXT_IP_V6_SUFFIX=2   # Start client allocation at ::2 (::1 is server)
typeset -g V6_PREFIX=""          # Stores the prefix portion (e.g., "fd00:")

# Initialize IPv6 address allocation
# Extracts the prefix from the CIDR and sets up the iterator
init_v6_iterator() {
    local cidr="$1"
    local addr="${cidr%/*}"

    # Extract prefix - everything before the last ::
    # For fd00::/64, the prefix is "fd00:"
    # For fd00:1::/64, the prefix is "fd00:1:"
    if [[ "$addr" == *"::"* ]]; then
        V6_PREFIX="${addr%%::*}:"
    else
        # Full address without ::, take up to the last segment
        V6_PREFIX="${addr%:*}:"
    fi

    NEXT_IP_V6_SUFFIX=2
    log_grey "IPv6 iterator initialized with prefix: ${V6_PREFIX}:"
}

# Calculate the server IPv6 address (first usable: prefix::1)
calculate_server_ip_v6() {
    local cidr="$1"
    local addr="${cidr%/*}"

    # For prefix::/64, server is prefix::1
    if [[ "$addr" == *"::"* ]]; then
        local prefix="${addr%%::*}"
        echo "${prefix}::1"
    else
        # If no ::, append ::1
        echo "${addr%:*}::1"
    fi
}

# Get next available IPv6 address using sequential suffix
get_next_available_ip_v6() {
    # Simple sequential allocation: prefix::2, prefix::3, etc.
    # This works well for /64 subnets which have ~18 quintillion addresses
    while true; do
        local candidate_suffix="$NEXT_IP_V6_SUFFIX"
        (( NEXT_IP_V6_SUFFIX++ ))

        # Build full IPv6 address
        local candidate="${V6_PREFIX}:${candidate_suffix}"

        # Check if already used (O(1) lookup)
        if [[ -z "${USED_IPS_SET_V6[$candidate]:-}" ]]; then
            echo "$candidate"
            return 0
        fi

        # Safety limit (unlikely to hit with /64 subnet)
        if [[ "$NEXT_IP_V6_SUFFIX" -gt 1000000 ]]; then
            log_red "IPv6 address allocation limit reached"
            return 1
        fi
    done
}

# Check if an IPv6 address is already used
is_ip_v6_used() {
    local ip="$1"
    [[ -n "${USED_IPS_SET_V6[$ip]:-}" ]]
}

# Mark an IPv6 address as used
mark_ip_v6_used() {
    local ip="$1"
    USED_IPS_SET_V6[$ip]=1
}

# Get count of used IPv6 addresses
get_used_ip_v6_count() {
    echo "${#USED_IPS_SET_V6[@]}"
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
# Also caches the public key and preshared key for faster server config generation
# Parameters:
#   $1 - client_ip: IPv4 address (empty for ipv6-only mode)
#   $2 - client_ip_v6: IPv6 address (empty for ipv4-only mode)
#   $3 - client_private_key
#   $4 - client_public_key
#   $5 - server_public_key
#   $6 - server_endpoint
#   $7 - dns_servers
#   $8 - allowed_ips
#   $9 - filename_format
#   $10 - preshared_key
#   $11 - ip_mode (ipv4, ipv6, or dual)
generate_client_config() {
    local client_ip="$1"
    local client_ip_v6="$2"
    local client_private_key="$3"
    local client_public_key="$4"
    local server_public_key="$5"
    local server_endpoint="$6"
    local dns_servers="$7"
    local allowed_ips="$8"
    local filename_format="$9"
    local preshared_key="${10}"
    local ip_mode="${11:-ipv4}"

    # Determine config name based on format and available IPs
    local config_name
    if [[ "$filename_format" == "increment" ]]; then
        # Use global counter directly (avoids subshell overhead)
        config_name="peer${NEXT_PEER_NUMBER}"
        (( ++NEXT_PEER_NUMBER ))
    else
        # Use IPv4 if available, otherwise sanitize IPv6 (replace : with -)
        if [[ -n "$client_ip" ]]; then
            config_name="${client_ip}"
        else
            config_name="${client_ip_v6//:/-}"
        fi
    fi

    # Determine key file paths (prefer IPv4 for keying, fall back to sanitized IPv6)
    local key_identifier
    if [[ -n "$client_ip" ]]; then
        key_identifier="$client_ip"
    else
        key_identifier="${client_ip_v6//:/-}"
    fi

    local config_file="/configs/${config_name}.conf"
    local pubkey_file="/keys/${key_identifier}.pubkey"
    local psk_file="/keys/${key_identifier}.psk"

    # Build Address line based on IP mode
    local address_line=""
    case "$ip_mode" in
        ipv4)
            address_line="Address = ${client_ip}/32"
            ;;
        ipv6)
            address_line="Address = ${client_ip_v6}/128"
            ;;
        dual)
            address_line="Address = ${client_ip}/32, ${client_ip_v6}/128"
            ;;
    esac

    # Only include ListenPort if CLIENT_LISTEN_PORT is set
    local listen_port_line=""
    [[ -n "$CLIENT_LISTEN_PORT" ]] && listen_port_line="ListenPort = ${CLIENT_LISTEN_PORT}"

    # Only include PersistentKeepalive if PERSISTENT_KEEPALIVE is set
    local keepalive_line=""
    [[ -n "${PERSISTENT_KEEPALIVE:-}" ]] && keepalive_line="PersistentKeepalive = ${PERSISTENT_KEEPALIVE}"

    # Build description for config comment
    local config_desc=""
    case "$ip_mode" in
        ipv4)
            config_desc="${client_ip}"
            ;;
        ipv6)
            config_desc="${client_ip_v6}"
            ;;
        dual)
            config_desc="${client_ip}, ${client_ip_v6}"
            ;;
    esac

    cat > "$config_file" << EOF
[Interface]
# Client configuration for ${config_desc}
PrivateKey = ${client_private_key}
${address_line}
DNS = ${dns_servers}
${listen_port_line}

[Peer]
# Server connection details
PublicKey = ${server_public_key}
PresharedKey = ${preshared_key}
AllowedIPs = ${allowed_ips}
Endpoint = ${server_endpoint}:${WIREGUARD_PORT}
${keepalive_line}
EOF

    chmod 600 "$config_file"

    # Cache the public key for faster server config regeneration
    echo "$client_public_key" > "$pubkey_file"
    chmod 644 "$pubkey_file"

    # Save the preshared key for server config generation
    echo "$preshared_key" > "$psk_file"
    chmod 600 "$psk_file"
}

# Generate the server configuration with all client peers
# Uses cached public keys when available for performance
# Parameters:
#   $1 - server_ip: IPv4 address (empty for ipv6-only mode)
#   $2 - server_ip_v6: IPv6 address (empty for ipv4-only mode)
#   $3 - cidr: IPv4 CIDR (used for prefix extraction)
#   $4 - cidr_v6: IPv6 CIDR (used for prefix extraction)
#   $5 - default_interface
#   $6 - isolate_clients
#   $7 - ip_mode (ipv4, ipv6, or dual)
generate_server_config() {
    local server_ip="$1"
    local server_ip_v6="$2"
    local cidr="$3"
    local cidr_v6="$4"
    local default_interface="$5"
    local isolate_clients="$6"
    local ip_mode="${7:-ipv4}"

    log_grey "Generating server configuration (mode: $ip_mode, isolation: $isolate_clients)..."

    # Create /etc/wireguard directory if it doesn't exist
    mkdir -p /etc/wireguard

    # Build peer sections for all client configs
    local peer_sections=""
    local client_count=0

    for config_file in /configs/*.conf(N); do
        [[ -f "$config_file" ]] || continue

        local filename=$( basename "$config_file" .conf )
        local client_ip=""
        local client_ip_v6=""

        # Get IPv4 from filename (ip format) or from config content
        if [[ "$filename" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            client_ip="$filename"
        else
            # Parse IPv4 from Address line in config
            client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null || true )
        fi

        # Parse IPv6 from Address line (may be comma-separated with IPv4)
        client_ip_v6=$( grep -oP '^Address\s*=.*\K[0-9a-fA-F:]+::[0-9a-fA-F:]*' "$config_file" 2>/dev/null | head -1 || true )
        # Handle sanitized filename format (colons replaced with dashes)
        if [[ -z "$client_ip_v6" && "$filename" =~ ^fd[0-9a-fA-F-]+ ]]; then
            client_ip_v6="${filename//-/:}"
        fi

        # Determine key file identifier (prefer IPv4, fall back to sanitized IPv6)
        local key_identifier=""
        if [[ -n "$client_ip" ]]; then
            key_identifier="$client_ip"
        elif [[ -n "$client_ip_v6" ]]; then
            key_identifier="${client_ip_v6//:/-}"
        else
            # Skip if we couldn't determine any IP
            continue
        fi

        local client_public_key=""
        local pubkey_file="/keys/${key_identifier}.pubkey"
        local psk_file="/keys/${key_identifier}.psk"

        # Try to use cached public key first (much faster)
        if [[ -f "$pubkey_file" ]]; then
            client_public_key=$( tr -d '[:space:]' < "$pubkey_file" )
        fi

        # Validate key format (WireGuard keys are 44 chars base64)
        if [[ ${#client_public_key} -ne 44 ]]; then
            # Fall back to deriving from private key
            local client_private_key=$( grep "^PrivateKey" "$config_file" | sed 's/.*=\s*//' | tr -d '[:space:]' )
            if [[ ${#client_private_key} -eq 44 ]]; then
                client_public_key=$( echo "$client_private_key" | wg pubkey 2>/dev/null ) || {
                    log_orange "Skipping $key_identifier: could not derive public key"
                    continue
                }
                # Cache it for next time
                echo "$client_public_key" > "$pubkey_file"
                chmod 644 "$pubkey_file"
            else
                log_orange "Skipping $key_identifier: invalid private key in config"
                continue
            fi
        fi

        # Read preshared key if available
        local psk_line=""
        if [[ -f "$psk_file" ]]; then
            local preshared_key=$( tr -d '[:space:]' < "$psk_file" )
            if [[ ${#preshared_key} -eq 44 ]]; then
                psk_line="PresharedKey = ${preshared_key}"
            fi
        fi

        # Build AllowedIPs based on IP mode
        local allowed_ips_peer=""
        case "$ip_mode" in
            ipv4)
                allowed_ips_peer="${client_ip}/32"
                ;;
            ipv6)
                allowed_ips_peer="${client_ip_v6}/128"
                ;;
            dual)
                if [[ -n "$client_ip" && -n "$client_ip_v6" ]]; then
                    allowed_ips_peer="${client_ip}/32, ${client_ip_v6}/128"
                elif [[ -n "$client_ip" ]]; then
                    allowed_ips_peer="${client_ip}/32"
                elif [[ -n "$client_ip_v6" ]]; then
                    allowed_ips_peer="${client_ip_v6}/128"
                fi
                ;;
        esac

        # Build client description
        local client_desc=""
        if [[ -n "$client_ip" && -n "$client_ip_v6" ]]; then
            client_desc="${client_ip}, ${client_ip_v6}"
        elif [[ -n "$client_ip" ]]; then
            client_desc="${client_ip}"
        else
            client_desc="${client_ip_v6}"
        fi

        peer_sections+="
[Peer]
# Client ${client_desc}
PublicKey = ${client_public_key}
${psk_line}
AllowedIPs = ${allowed_ips_peer}
"
        (( ++client_count ))
    done

    # Build firewall rules based on IP mode and client isolation
    local post_up=""
    local post_down=""

    # IPv4 rules
    local iptables_up=""
    local iptables_down=""
    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        if [[ "$isolate_clients" == "true" ]]; then
            iptables_up="iptables -A FORWARD -i %i -o ${default_interface} -j ACCEPT; iptables -A FORWARD -i ${default_interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE"
            iptables_down="iptables -D FORWARD -i %i -o ${default_interface} -j ACCEPT; iptables -D FORWARD -i ${default_interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE"
        else
            iptables_up="iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE"
            iptables_down="iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE"
        fi
    fi

    # IPv6 rules
    local ip6tables_up=""
    local ip6tables_down=""
    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        if [[ "$isolate_clients" == "true" ]]; then
            ip6tables_up="ip6tables -A FORWARD -i %i -o ${default_interface} -j ACCEPT; ip6tables -A FORWARD -i ${default_interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE"
            ip6tables_down="ip6tables -D FORWARD -i %i -o ${default_interface} -j ACCEPT; ip6tables -D FORWARD -i ${default_interface} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE"
        else
            ip6tables_up="ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -A FORWARD -o %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${default_interface} -j MASQUERADE"
            ip6tables_down="ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -D FORWARD -o %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${default_interface} -j MASQUERADE"
        fi
    fi

    # Combine rules based on mode
    case "$ip_mode" in
        ipv4)
            post_up="$iptables_up"
            post_down="$iptables_down"
            ;;
        ipv6)
            post_up="$ip6tables_up"
            post_down="$ip6tables_down"
            ;;
        dual)
            post_up="${iptables_up}; ${ip6tables_up}"
            post_down="${iptables_down}; ${ip6tables_down}"
            ;;
    esac

    # Build Address line based on IP mode
    local address_line=""
    case "$ip_mode" in
        ipv4)
            address_line="Address = ${server_ip}/${cidr#*/}"
            ;;
        ipv6)
            address_line="Address = ${server_ip_v6}/${cidr_v6#*/}"
            ;;
        dual)
            address_line="Address = ${server_ip}/${cidr#*/}, ${server_ip_v6}/${cidr_v6#*/}"
            ;;
    esac

    # Write server config with NAT rules for routing client traffic
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
# WireGuard Firehose Server (IP mode: ${ip_mode})
PrivateKey = ${SERVER_PRIVATE_KEY}
${address_line}
ListenPort = ${WIREGUARD_PORT}

# NAT rules (client isolation: ${isolate_clients})
PostUp = ${post_up}
PostDown = ${post_down}
${peer_sections}
EOF

    chmod 600 /etc/wireguard/wg0.conf
    log_green "Server configuration generated with $client_count peers (mode: $ip_mode)"
}

# Generate missing client configs up to MAX_CONFIGS
# Parameters:
#   $1 - cidr: IPv4 CIDR
#   $2 - cidr_v6: IPv6 CIDR (empty for ipv4-only)
#   $3 - max_configs
#   $4 - server_endpoint
#   $5 - filename_format
#   $6 - dns_servers: Combined DNS servers (may include v4 and v6)
#   $7 - allowed_ips: Combined AllowedIPs (may include v4 and v6)
#   $8 - ip_mode (ipv4, ipv6, or dual)
generate_missing_configs() {
    local cidr="$1"
    local cidr_v6="$2"
    local max_configs="$3"
    local server_endpoint="$4"
    local filename_format="$5"
    local dns_servers="$6"
    local allowed_ips="$7"
    local ip_mode="${8:-ipv4}"

    log_grey "Checking for existing configurations (mode: $ip_mode)..."

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

    log_grey "Generating $to_generate new configurations (format: $filename_format, mode: $ip_mode)..."

    # ================================================================
    # PERFORMANCE OPTIMIZATION: Pre-generate all keypairs in batch
    # ================================================================
    generate_keypair_batch "$to_generate"

    # Initialize IP iterators based on mode
    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        init_ip_iterator "$cidr"
    fi
    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        init_v6_iterator "$cidr_v6"
    fi

    local generated=0
    local last_logged_percent=0

    # Variables for current client data
    local client_ip=""
    local client_ip_v6=""
    local keypair=""
    local client_private_key=""
    local client_public_key=""
    local preshared_key=""

    while [[ "$generated" -lt "$to_generate" ]]; do

        # ============================================================
        # Allocate IPv4 address (for ipv4 and dual modes)
        # ============================================================
        client_ip=""
        if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
            while [[ "$NEXT_IP_INT" -le "$END_IP_INT" ]]; do
                # Convert integer to dotted-quad IP address (inlined int_to_ip)
                client_ip="$(( NEXT_IP_INT / 16777216 % 256 )).$(( NEXT_IP_INT / 65536 % 256 )).$(( NEXT_IP_INT / 256 % 256 )).$(( NEXT_IP_INT % 256 ))"

                (( NEXT_IP_INT++ ))

                if [[ -z "${USED_IPS_SET[$client_ip]:-}" ]]; then
                    break
                fi

                client_ip=""
            done

            if [[ -z "$client_ip" && "$ip_mode" == "ipv4" ]]; then
                log_orange "No more IPv4 addresses available in subnet"
                break
            fi
        fi

        # ============================================================
        # Allocate IPv6 address (for ipv6 and dual modes)
        # ============================================================
        client_ip_v6=""
        if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
            # Simple sequential allocation for IPv6
            local v6_suffix="$NEXT_IP_V6_SUFFIX"
            (( NEXT_IP_V6_SUFFIX++ ))

            # Build IPv6 address from prefix
            local v6_prefix="${cidr_v6%%::*}"
            client_ip_v6="${v6_prefix}::${v6_suffix}"

            # Check if used (unlikely but handle it)
            while [[ -n "${USED_IPS_SET_V6[$client_ip_v6]:-}" && "$NEXT_IP_V6_SUFFIX" -lt 1000000 ]]; do
                v6_suffix="$NEXT_IP_V6_SUFFIX"
                (( NEXT_IP_V6_SUFFIX++ ))
                client_ip_v6="${v6_prefix}::${v6_suffix}"
            done

            if [[ -z "$client_ip_v6" && "$ip_mode" == "ipv6" ]]; then
                log_orange "No more IPv6 addresses available in subnet"
                break
            fi
        fi

        # ============================================================
        # Get keypair and PSK from pre-generated batches
        # ============================================================
        (( ++KEYPAIR_BATCH_INDEX ))
        keypair="${KEYPAIR_BATCH[$KEYPAIR_BATCH_INDEX]}"

        if [[ -z "$keypair" ]]; then
            log_red "Keypair batch exhausted unexpectedly at index $KEYPAIR_BATCH_INDEX"
            exit 1
        fi

        client_private_key="${keypair%:*}"
        client_public_key="${keypair#*:}"

        (( ++PSK_BATCH_INDEX ))
        preshared_key="${PSK_BATCH[$PSK_BATCH_INDEX]}"

        if [[ -z "$preshared_key" ]]; then
            log_red "PSK batch exhausted unexpectedly at index $PSK_BATCH_INDEX"
            exit 1
        fi

        # Generate the config file with dual-stack support
        generate_client_config \
            "$client_ip" \
            "$client_ip_v6" \
            "$client_private_key" \
            "$client_public_key" \
            "$SERVER_PUBLIC_KEY" \
            "$server_endpoint" \
            "$dns_servers" \
            "$allowed_ips" \
            "$filename_format" \
            "$preshared_key" \
            "$ip_mode"

        # Mark IPs as used
        [[ -n "$client_ip" ]] && USED_IPS_SET[$client_ip]=1
        [[ -n "$client_ip_v6" ]] && USED_IPS_SET_V6[$client_ip_v6]=1

        (( ++generated ))

        # Progress logging every 10%
        local current_percent=$(( generated * 100 / to_generate ))
        if [[ $(( current_percent / 10 )) -gt $(( last_logged_percent / 10 )) ]]; then
            local display_percent=$(( (current_percent / 10) * 10 ))
            log_grey "Progress ${display_percent}% ($generated/$to_generate)"
            last_logged_percent="$current_percent"
        fi
    done

    log_green "Generated $generated new configurations (mode: $ip_mode)"
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

# Check public connectivity for WireGuard port
# Verifies the container is reachable from the public internet
# Parameters:
#   $1 - public_ip: Public IPv4 address (empty to skip IPv4 check)
#   $2 - public_ip_v6: Public IPv6 address (empty to skip IPv6 check)
#   $3 - ip_mode: IP mode (ipv4, ipv6, or dual)
check_public_connectivity() {
    local public_ip="$1"
    local public_ip_v6="$2"
    local ip_mode="${3:-ipv4}"

    log_grey "Checking public connectivity..."
    local failed=0

    # IPv4 check (if ipv4 or dual mode)
    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        if [[ -n "$public_ip" ]]; then
            log_grey "Testing IPv4 connectivity on port ${WIREGUARD_PORT}..."
            if nc -z -w 5 -u "$public_ip" "$WIREGUARD_PORT" 2>/dev/null; then
                log_green "✓ IPv4 UDP port ${WIREGUARD_PORT} is reachable on ${public_ip}"
            else
                log_orange "=============================================="
                log_orange "WARNING: IPv4 CONNECTIVITY CHECK FAILED"
                log_orange "=============================================="
                log_orange "Could not reach ${public_ip}:${WIREGUARD_PORT}/udp"
                log_orange "Possible causes:"
                log_orange "  - Firewall blocking UDP port ${WIREGUARD_PORT}"
                log_orange "  - Port forwarding not configured"
                log_orange "  - NAT/router not forwarding traffic"
                log_orange "=============================================="
                failed=1
            fi
        fi
    fi

    # IPv6 check (if ipv6 or dual mode)
    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        if [[ -n "$public_ip_v6" ]]; then
            log_grey "Testing IPv6 connectivity on port ${WIREGUARD_PORT}..."
            if nc -6 -z -w 5 -u "$public_ip_v6" "$WIREGUARD_PORT" 2>/dev/null; then
                log_green "✓ IPv6 UDP port ${WIREGUARD_PORT} is reachable on ${public_ip_v6}"
            else
                log_orange "=============================================="
                log_orange "WARNING: IPv6 CONNECTIVITY CHECK FAILED"
                log_orange "=============================================="
                log_orange "Could not reach [${public_ip_v6}]:${WIREGUARD_PORT}/udp"
                log_orange "Possible causes:"
                log_orange "  - Firewall blocking UDP port ${WIREGUARD_PORT}"
                log_orange "  - IPv6 not properly configured on host"
                log_orange "  - Router not forwarding IPv6 traffic"
                log_orange "=============================================="
                failed=1
            fi
        else
            log_orange "=============================================="
            log_orange "WARNING: IPv6 PUBLIC IP NOT DISCOVERED"
            log_orange "=============================================="
            log_orange "Could not determine public IPv6 address"
            log_orange "IPv6 clients may not be able to connect"
            log_orange "=============================================="
            failed=1
        fi
    fi

    if [[ "$failed" -eq 0 ]]; then
        log_green "All connectivity checks passed!"
    else
        log_orange "Some connectivity checks failed - container will continue running"
        log_orange "Clients may experience connection issues"
    fi

    # Do NOT exit - just warn
    return 0
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
# Where identifier is an IPv4 (10.0.0.5), sanitized IPv6 (fd00--2), or peer name (peer5)
regenerate_client_keys() {
    local identifier="$1"
    local client_ip=""
    local client_ip_v6=""
    local config_file=""
    local key_identifier=""

    # Security: Validate identifier format strictly to prevent path traversal
    # Allow: IPv4 addresses (10.0.0.5), peer names (peer5), or sanitized IPv6 (fd00--2)
    if [[ ! "$identifier" =~ ^(peer[0-9]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|fd[0-9a-fA-F-]+)$ ]]; then
        log_red "Invalid identifier format: $identifier (must be IPv4, sanitized IPv6, or peerN)"
        return 1
    fi

    # Additional validation: if IPv4 format, validate each octet is 0-255
    if [[ "$identifier" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local octets=( ${(s:.:)identifier} )
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                log_red "Invalid IP octet in identifier: $octet (must be 0-255)"
                return 1
            fi
        done
    fi

    # Determine if identifier is an IPv4, IPv6, or peer name
    if [[ "$identifier" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # IPv4 identifier
        client_ip="$identifier"
        key_identifier="$client_ip"
        if [[ -f "/configs/${client_ip}.conf" ]]; then
            config_file="/configs/${client_ip}.conf"
        else
            config_file=$( grep -l "Address = ${client_ip}/32" /configs/*.conf 2>/dev/null | head -1 )
        fi
    elif [[ "$identifier" =~ ^fd[0-9a-fA-F-]+$ ]]; then
        # Sanitized IPv6 identifier (fd00--2 format)
        key_identifier="$identifier"
        client_ip_v6="${identifier//-/:}"  # Restore colons
        if [[ -f "/configs/${identifier}.conf" ]]; then
            config_file="/configs/${identifier}.conf"
        else
            config_file=$( grep -l "Address.*${client_ip_v6}" /configs/*.conf 2>/dev/null | head -1 )
        fi
    elif [[ "$identifier" =~ ^peer[0-9]+$ ]]; then
        config_file="/configs/${identifier}.conf"
        if [[ -f "$config_file" ]]; then
            # Extract IPv4 from config
            client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null || true )
            # Extract IPv6 from config
            client_ip_v6=$( grep -oP '^Address\s*=.*\K[0-9a-fA-F:]+::[0-9a-fA-F:]*' "$config_file" 2>/dev/null | head -1 || true )
            # Determine key identifier (prefer IPv4)
            if [[ -n "$client_ip" ]]; then
                key_identifier="$client_ip"
            elif [[ -n "$client_ip_v6" ]]; then
                key_identifier="${client_ip_v6//:/-}"
            fi
        fi
    else
        log_red "Invalid identifier format: $identifier"
        return 1
    fi

    # Validate we found the config
    if [[ -z "$config_file" || ! -f "$config_file" ]]; then
        log_red "Config file not found for: $identifier"
        return 1
    fi

    # If we only have config file, try to extract IPs
    if [[ -z "$client_ip" && -z "$client_ip_v6" ]]; then
        client_ip=$( grep -oP '^Address\s*=\s*\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$config_file" 2>/dev/null || true )
        client_ip_v6=$( grep -oP '^Address\s*=.*\K[0-9a-fA-F:]+::[0-9a-fA-F:]*' "$config_file" 2>/dev/null | head -1 || true )
        if [[ -n "$client_ip" ]]; then
            key_identifier="$client_ip"
        elif [[ -n "$client_ip_v6" ]]; then
            key_identifier="${client_ip_v6//:/-}"
        fi
    fi

    if [[ -z "$key_identifier" ]]; then
        log_red "Could not determine key identifier for: $identifier"
        return 1
    fi

    local pubkey_file="/keys/${key_identifier}.pubkey"
    local psk_file="/keys/${key_identifier}.psk"

    # Get old public key (needed to remove from WireGuard)
    local old_pubkey=""
    if [[ -f "$pubkey_file" ]]; then
        old_pubkey=$( tr -d '[:space:]' < "$pubkey_file" )
    fi

    # Validate or derive old public key
    if [[ ${#old_pubkey} -ne 44 ]]; then
        local old_privkey=$( grep "^PrivateKey" "$config_file" | sed 's/.*=\s*//' | tr -d '[:space:]' )
        if [[ ${#old_privkey} -eq 44 ]]; then
            old_pubkey=$( echo "$old_privkey" | wg pubkey 2>/dev/null ) || old_pubkey=""
        fi
    fi

    # Build description for logging
    local desc=""
    if [[ -n "$client_ip" && -n "$client_ip_v6" ]]; then
        desc="$client_ip, $client_ip_v6"
    elif [[ -n "$client_ip" ]]; then
        desc="$client_ip"
    else
        desc="$client_ip_v6"
    fi

    log_grey "Regenerating keys for $identifier ($desc)..."

    # Generate new keypair and preshared key
    local keypair=$( generate_keypair )
    local new_private_key="${keypair%:*}"
    local new_public_key="${keypair#*:}"
    local new_psk=$( wg genpsk )

    # Define temp file paths for atomic writes
    local temp_config="${config_file}.tmp.$$"
    local temp_pubkey="${pubkey_file}.tmp.$$"
    local temp_psk="${psk_file}.tmp.$$"

    # Cleanup function for temp files on error
    cleanup_temp_files() {
        rm -f "$temp_config" "$temp_pubkey" "$temp_psk" 2>/dev/null || true
    }

    # Update config file with new private key and preshared key
    if ! sed -e "s|^PrivateKey = .*|PrivateKey = ${new_private_key}|" \
             -e "s|^PresharedKey = .*|PresharedKey = ${new_psk}|" "$config_file" > "$temp_config"; then
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

    # Update cached preshared key (atomic write)
    if ! echo "$new_psk" > "$temp_psk"; then
        cleanup_temp_files
        log_red "Failed to create temp psk file"
        return 1
    fi
    chmod 600 "$temp_psk"

    # Atomic moves
    if ! mv "$temp_config" "$config_file"; then
        cleanup_temp_files
        log_red "Failed to move temp config file"
        return 1
    fi

    if ! mv "$temp_pubkey" "$pubkey_file"; then
        rm -f "$temp_pubkey" "$temp_psk" 2>/dev/null || true
        log_red "Failed to move temp pubkey file"
        return 1
    fi

    if ! mv "$temp_psk" "$psk_file"; then
        rm -f "$temp_psk" 2>/dev/null || true
        log_red "Failed to move temp psk file"
        return 1
    fi

    # Build AllowedIPs for wg set command
    local allowed_ips=""
    if [[ -n "$client_ip" && -n "$client_ip_v6" ]]; then
        allowed_ips="${client_ip}/32,${client_ip_v6}/128"
    elif [[ -n "$client_ip" ]]; then
        allowed_ips="${client_ip}/32"
    else
        allowed_ips="${client_ip_v6}/128"
    fi

    # Hot-swap peer in WireGuard interface (with new PSK)
    if [[ -n "$old_pubkey" ]]; then
        wg set wg0 peer "$old_pubkey" remove 2>/dev/null || true
    fi
    # Use process substitution to pass PSK securely
    wg set wg0 peer "$new_public_key" preshared-key <(echo "$new_psk") allowed-ips "$allowed_ips"

    log_green "Keys regenerated for $identifier ($desc)"
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

    # Get IP mode early for dependency and sysctl checks
    local ip_mode="${IP_MODE:-ipv4}"

    # Set up signal handlers for graceful shutdown
    setup_signal_handlers

    # Step 1: Check dependencies and capabilities (mode-aware)
    check_dependencies "$ip_mode"
    check_capabilities

    # Step 2: Verify system configuration (mode-aware)
    verify_sysctl_values "$ip_mode"

    # Step 3: Validate IP_MODE first
    validate_ip_mode "$ip_mode"

    # Step 4: Validate all configuration based on IP mode
    validate_port "$WIREGUARD_PORT" "WIREGUARD_PORT"
    [[ -n "$CLIENT_LISTEN_PORT" ]] && validate_port "$CLIENT_LISTEN_PORT" "CLIENT_LISTEN_PORT"
    validate_filename_format "$FILENAME_FORMAT"
    validate_isolate_clients "$ISOLATE_CLIENTS"
    validate_persistent_keepalive "${PERSISTENT_KEEPALIVE:-}"

    # Validate IPv4 settings (for ipv4 and dual modes)
    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        validate_cidr "$INTERNAL_SUBNET_CIDR"
        validate_max_configs "$MAX_CONFIGS" "$INTERNAL_SUBNET_CIDR"
        validate_dns_servers "$DNS_SERVERS" "false"
        validate_allowed_ips "$ALLOWEDIPS" "false"
    fi

    # Validate IPv6 settings (for ipv6 and dual modes)
    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        validate_cidr_v6 "$INTERNAL_SUBNET_CIDR_V6"
        validate_dns_servers "$DNS_SERVERS_V6" "true"
        validate_allowed_ips "$ALLOWEDIPS_V6" "true"
    fi

    # Step 5: Handle forced regeneration (before anything else touches configs)
    handle_force_regeneration

    # Step 6: Detect default network interface for NAT
    local default_interface=$( get_default_interface )
    log_grey "Using network interface: $default_interface"

    # Step 7: Discover public IP(s) for client configs
    local public_ip=""
    local public_ip_v6=""
    local server_endpoint=""

    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        public_ip=$( get_public_ip )
        server_endpoint="$public_ip"
    fi

    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        public_ip_v6=$( get_public_ip_v6 ) || true  # Non-fatal if IPv6 discovery fails
        if [[ "$ip_mode" == "ipv6" ]]; then
            if [[ -n "$public_ip_v6" ]]; then
                server_endpoint="$public_ip_v6"
            else
                log_red "IPv6 mode requires public IPv6 address but none was discovered"
                exit 1
            fi
        fi
    fi

    # Step 8: Initialize server keys (persistent across restarts)
    get_or_create_server_keys

    # Step 9: Calculate server IP(s) (first usable address in subnet)
    local server_ip=""
    local server_ip_v6=""

    if [[ "$ip_mode" == "ipv4" || "$ip_mode" == "dual" ]]; then
        server_ip=$( calculate_server_ip "$INTERNAL_SUBNET_CIDR" )
        log_grey "Server internal IPv4: $server_ip"
    fi

    if [[ "$ip_mode" == "ipv6" || "$ip_mode" == "dual" ]]; then
        server_ip_v6=$( calculate_server_ip_v6 "$INTERNAL_SUBNET_CIDR_V6" )
        log_grey "Server internal IPv6: $server_ip_v6"
    fi

    # Step 10: Build combined DNS servers and AllowedIPs based on mode
    local combined_dns=""
    local combined_allowed_ips=""

    case "$ip_mode" in
        ipv4)
            combined_dns="$DNS_SERVERS"
            combined_allowed_ips="$ALLOWEDIPS"
            ;;
        ipv6)
            combined_dns="$DNS_SERVERS_V6"
            combined_allowed_ips="$ALLOWEDIPS_V6"
            ;;
        dual)
            combined_dns="${DNS_SERVERS},${DNS_SERVERS_V6}"
            combined_allowed_ips="${ALLOWEDIPS},${ALLOWEDIPS_V6}"
            ;;
    esac

    # Step 11: Ensure directories exist
    mkdir -p /configs
    mkdir -p /keys
    mkdir -p /regen_requests

    # Step 12: Generate missing client configs
    generate_missing_configs \
        "$INTERNAL_SUBNET_CIDR" \
        "$INTERNAL_SUBNET_CIDR_V6" \
        "$MAX_CONFIGS" \
        "$server_endpoint" \
        "$FILENAME_FORMAT" \
        "$combined_dns" \
        "$combined_allowed_ips" \
        "$ip_mode"

    # Step 13: Generate server config with all client peers
    generate_server_config \
        "$server_ip" \
        "$server_ip_v6" \
        "$INTERNAL_SUBNET_CIDR" \
        "$INTERNAL_SUBNET_CIDR_V6" \
        "$default_interface" \
        "$ISOLATE_CLIENTS" \
        "$ip_mode"

    # Step 14: Start WireGuard server
    start_wireguard

    # Step 15: Check public connectivity
    check_public_connectivity "$public_ip" "$public_ip_v6" "$ip_mode"

    # Step 16: Start key regeneration watcher
    start_regen_watcher

    log_green "WireGuard Firehose is ready! (IP mode: $ip_mode)"
    log_grey "Client configs available in /configs"
    log_grey "To regenerate keys: touch regen_requests/<ip-or-peer-name>"

    # Keep container running with proper signal handling
    wait_forever
}

main "$@"
