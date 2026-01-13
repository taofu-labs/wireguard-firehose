#!/bin/bash
# ============================================================
# WireGuard Firehose - QR Code Generator
# ============================================================
# Generates QR codes from client configs for easy mobile setup
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/configs"

# Get sorted list of config files
# Handles both IP format (10.0.0.2.conf) and increment format (peer1.conf)
get_sorted_configs() {
    local configs=()
    local ip_configs=()
    local peer_configs=()

    while IFS= read -r file; do
        local name=$(basename "$file" .conf)
        if [[ "$name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ip_configs+=("$name.conf")
        elif [[ "$name" =~ ^peer[0-9]+$ ]]; then
            peer_configs+=("$name.conf")
        fi
    done < <(find "$CONFIGS_DIR" -maxdepth 1 -name '*.conf' -type f 2>/dev/null)

    # Sort IP configs by IP address
    if [[ ${#ip_configs[@]} -gt 0 ]]; then
        printf '%s\n' "${ip_configs[@]}" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n
    fi

    # Sort peer configs by peer number
    if [[ ${#peer_configs[@]} -gt 0 ]]; then
        printf '%s\n' "${peer_configs[@]}" | sort -t'r' -k2,2n
    fi
}

# Display QR code for a config file
show_qr() {
    local config_name="$1"
    local config_path="${CONFIGS_DIR}/${config_name}"

    if [[ ! -f "$config_path" ]]; then
        echo "Error: Config not found: $config_path" >&2
        return 1
    fi

    echo "=== ${config_name} ==="
    qrencode -t ansiutf8 -r "$config_path"
    echo ""
}

main() {
    if [[ ! -d "$CONFIGS_DIR" ]]; then
        echo "Error: Configs directory not found: $CONFIGS_DIR" >&2
        exit 1
    fi

    # Get sorted config list into array
    mapfile -t configs < <(get_sorted_configs)

    if [[ ${#configs[@]} -eq 0 ]]; then
        echo "Error: No config files found in $CONFIGS_DIR" >&2
        exit 1
    fi

    local count=${#configs[@]}

    if [[ $# -gt 0 ]]; then
        # Show QR for specified config(s)
        for config in "$@"; do
            # Add .conf extension if not provided
            [[ "$config" == *.conf ]] || config="${config}.conf"
            show_qr "$config"
        done
    else
        # Show first, middle, and last
        local first=0
        local middle=$(( count / 2 ))
        local last=$(( count - 1 ))

        show_qr "${configs[$first]}"

        # Only show middle if different from first and last
        if [[ $middle -ne $first && $middle -ne $last ]]; then
            show_qr "${configs[$middle]}"
        fi

        # Only show last if different from first
        if [[ $last -ne $first ]]; then
            show_qr "${configs[$last]}"
        fi
    fi
}

main "$@"
