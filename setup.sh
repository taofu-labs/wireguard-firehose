#!/bin/bash
# ============================================================
# WireGuard Firehose - Setup & Update Script
# ============================================================
# Usage: curl -fsSL https://raw.githubusercontent.com/taofu-labs/wireguard-firehose/main/setup.sh | bash
# ============================================================

set -euo pipefail

# Configuration
REPO_RAW_URL="https://raw.githubusercontent.com/taofu-labs/wireguard-firehose/main"
WIREGUARD_PORT="${WIREGUARD_PORT:-51820}"

# Mode detection (set after INSTALL_DIR is defined)
IS_UPDATE=0

# Detect actual user when run with sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    ACTUAL_USER="$SUDO_USER"
    ACTUAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    ACTUAL_USER="$(whoami)"
    ACTUAL_HOME="$HOME"
fi

INSTALL_DIR="${INSTALL_DIR:-${ACTUAL_HOME}/wireguard-firehose}"

# Track if docker group was modified (requires logout/login)
DOCKER_GROUP_CHANGED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        log_warn "This script is designed for Ubuntu/Debian. Proceeding anyway..."
    fi
}

# Install Docker using official script
install_docker() {
    if command -v docker &> /dev/null; then
        log_info "Docker is already installed"
    else
        log_info "Installing Docker..."
        curl -fsSL https://get.docker.com | sh -s -- --quiet

        # Enable and start Docker
        systemctl enable --now docker &> /dev/null

        log_info "Docker installed successfully"
    fi

    # Add user to docker group for rootless operation
    if ! groups "$ACTUAL_USER" | grep -q '\bdocker\b'; then
        log_info "Adding $ACTUAL_USER to docker group..."
        usermod -aG docker "$ACTUAL_USER"
        DOCKER_GROUP_CHANGED=1
    fi
}

# Install WireGuard kernel module
install_wireguard() {
    if lsmod | grep -q wireguard; then
        log_info "WireGuard kernel module is already loaded"
        return 0
    fi

    log_info "Installing WireGuard tools..."
    apt-get update -qq
    apt-get install -y -qq wireguard-tools > /dev/null

    # Load the module
    modprobe wireguard 2>/dev/null || true

    log_info "WireGuard installed successfully"
}

# Configure sysctl for IP forwarding
configure_sysctl() {
    log_info "Configuring kernel parameters..."

    local sysctl_file="/etc/sysctl.d/99-wireguard-firehose.conf"

    cat > "$sysctl_file" << 'EOF'
# WireGuard Firehose - IP forwarding configuration
net.ipv4.ip_forward=1
net.ipv4.conf.all.src_valid_mark=1
EOF

    sysctl -p "$sysctl_file" > /dev/null 2>&1

    log_info "Kernel parameters configured"
}

# Configure firewall
configure_firewall() {
    if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
        log_info "Configuring UFW firewall..."
        ufw allow "${WIREGUARD_PORT}/udp" > /dev/null 2>&1
        log_info "Firewall rule added for port ${WIREGUARD_PORT}/udp"
    else
        log_info "UFW not active, skipping firewall configuration"
    fi
}

# Detect if this is an update
detect_mode() {
    if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]]; then
        IS_UPDATE=1
        log_info "Existing installation detected - running in update mode"
    else
        log_info "Fresh installation"
    fi
}

# Download required files
download_files() {
    mkdir -p "${INSTALL_DIR}"
    cd "${INSTALL_DIR}"

    log_info "Downloading docker-compose.yml..."
    curl -fsSL "${REPO_RAW_URL}/docker-compose.yml" -o docker-compose.yml

    # Create configs directory
    mkdir -p configs

    # Create default .env file if it doesn't exist (preserve existing on update)
    if [[ ! -f .env ]]; then
        log_info "Creating default .env file..."
        cat > .env << EOF
# WireGuard Firehose Configuration
WIREGUARD_PORT=${WIREGUARD_PORT}
INTERNAL_SUBNET_CIDR=10.0.0.0/16
MAX_CONFIGS=50000
ALLOWEDIPS=0.0.0.0/0
DNS_SERVERS=1.1.1.1,8.8.8.8,8.8.4.4
EOF
    else
        log_info "Preserving existing .env file"
    fi

    # Set ownership to actual user (not root) for rootless docker
    chown -R "${ACTUAL_USER}:${ACTUAL_USER}" "${INSTALL_DIR}"

    log_info "Files downloaded to ${INSTALL_DIR}"
}

# Pull Docker image
pull_image() {
    log_info "Pulling WireGuard Firehose Docker image..."
    docker pull taofuprotocol/wireguard-firehose:latest -q
    log_info "Docker image pulled successfully"
}

# Restart container if running (for updates)
restart_container() {
    cd "${INSTALL_DIR}"

    if docker compose ps --quiet 2>/dev/null | grep -q .; then
        log_info "Restarting container with updated image..."
        sudo -u "${ACTUAL_USER}" docker compose up -d --pull always
        log_info "Container restarted successfully"
    else
        log_info "Container not running - skipping restart"
    fi
}

# Print completion message
print_complete() {
    echo ""
    echo "============================================================"
    if [[ "$IS_UPDATE" -eq 1 ]]; then
        echo -e "${GREEN}WireGuard Firehose Update Complete!${NC}"
    else
        echo -e "${GREEN}WireGuard Firehose Setup Complete!${NC}"
    fi
    echo "============================================================"
    echo ""
    echo "Installation directory: ${INSTALL_DIR}"
    echo ""

    if [[ "$IS_UPDATE" -eq 1 ]]; then
        echo "Updated components:"
        echo "  - docker-compose.yml"
        echo "  - Docker image (latest)"
        echo ""
        echo "Preserved:"
        echo "  - .env configuration"
        echo "  - configs/ directory"
        echo ""
        echo "If the container was running, it has been restarted."
        echo "Otherwise, start it with:"
        echo ""
        echo "  cd ${INSTALL_DIR}"
        echo "  docker compose up -d"
    elif [[ "$DOCKER_GROUP_CHANGED" -eq 1 ]]; then
        echo -e "${YELLOW}IMPORTANT: You were added to the docker group.${NC}"
        echo "Log out and back in, then start the server:"
        echo ""
        echo "  cd ${INSTALL_DIR}"
        echo "  docker compose up -d"
        echo ""
        echo "Or run now using newgrp (no logout required):"
        echo ""
        echo "  newgrp docker"
        echo "  cd ${INSTALL_DIR}"
        echo "  docker compose up -d"
    else
        echo "To start the server:"
        echo ""
        echo "  cd ${INSTALL_DIR}"
        echo "  docker compose up -d"
    fi

    echo ""
    echo "To view logs:"
    echo "  docker compose logs -f"
    echo ""
    echo "Client configs will be available in:"
    echo "  ${INSTALL_DIR}/configs/"
    echo ""
    if [[ "$IS_UPDATE" -eq 0 ]]; then
        echo "To customize, edit ${INSTALL_DIR}/.env before starting."
    fi
    echo "============================================================"
}

# Main installation flow
main() {
    echo ""
    echo "============================================================"
    echo "  WireGuard Firehose - Setup & Update"
    echo "============================================================"
    echo ""

    check_root
    detect_os
    detect_mode
    install_docker
    install_wireguard
    configure_sysctl
    configure_firewall
    download_files
    pull_image

    if [[ "$IS_UPDATE" -eq 1 ]]; then
        restart_container
    fi

    print_complete
}

main "$@"
