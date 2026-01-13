# ============================================================
# WireGuard Firehose - Auto-provisioning WireGuard Server
# ============================================================
# Alpine-based container with WireGuard and auto-provisioning
# ============================================================

FROM alpine:latest

# Install required dependencies:
# - wireguard-tools: provides wg and wg-quick commands
# - zsh: required shell for entrypoint (per specification)
# - iproute2: required by wg-quick for ip command
# - iptables: for NAT and firewall rules
# - curl: for fetching public IP from external services
# - netcat-openbsd: for health check (nc command)
# - bash: dependency of wg-quick
# - grep: GNU grep for -P (Perl regex) support (BusyBox grep lacks this)
RUN apk add --no-cache \
    wireguard-tools \
    zsh \
    iproute2 \
    iptables \
    curl \
    netcat-openbsd \
    bash \
    inotify-tools \
    grep

# Copy entrypoint script and make executable
COPY entrypoint.zsh /entrypoint.zsh
RUN chmod +x /entrypoint.zsh

# Volumes for persistent data
VOLUME /configs
VOLUME /keys
VOLUME /regen_requests

# Environment variable defaults
ENV WIREGUARD_PORT=51820 \
    INTERNAL_SUBNET_CIDR=10.0.0.0/16 \
    MAX_CONFIGS=50000 \
    ALLOWEDIPS=0.0.0.0/0 \
    DNS_SERVERS=1.1.1.1,8.8.8.8,8.8.4.4 \
    FILENAME_FORMAT=ip \
    FORCE_CONFIG_REGENERATION=false \
    ISOLATE_CLIENTS=true

# Health check: verify WireGuard is listening on the configured port
# Uses nc to check UDP port as specified in the specification
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD nc -zu 127.0.0.1 ${WIREGUARD_PORT} 2>/dev/null || exit 1

# Expose WireGuard UDP port
EXPOSE 51820/udp

# Run the entrypoint script
ENTRYPOINT ["/entrypoint.zsh"]
