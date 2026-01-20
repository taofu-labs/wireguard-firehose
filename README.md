# WireGuard Firehose

Auto-provisioning WireGuard VPN server in Docker. Generates thousands of client configurations automatically on startup.

## TL;DR

```bash
# One-liner setup (Ubuntu 24 LTS)
curl -fsSL https://raw.githubusercontent.com/taofu-labs/wireguard-firehose/main/setup.sh | sudo bash

# Start
cd ~/wireguard-firehose && docker compose up -d

# Configs in ./configs/, keys in ./keys/
# Regenerate a client: touch regen_requests/<ip-or-peer-name>
# QR codes: ./qr.sh peer5
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WIREGUARD_PORT` | `51820` | WireGuard UDP listen port |
| `IP_MODE` | `ipv4` | Protocol mode: `ipv4`, `ipv6`, or `dual` |
| `INTERNAL_SUBNET_CIDR` | `10.0.0.0/16` | IPv4 VPN internal subnet |
| `INTERNAL_SUBNET_CIDR_V6` | `fd00::/64` | IPv6 VPN internal subnet (ULA) |
| `MAX_CONFIGS` | `50000` | Maximum client configs to generate |
| `ALLOWEDIPS` | `0.0.0.0/0` | IPv4 client routing (full tunnel by default) |
| `ALLOWEDIPS_V6` | `::/0` | IPv6 client routing (full tunnel by default) |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8,8.8.4.4` | IPv4 DNS servers for clients |
| `DNS_SERVERS_V6` | `2606:4700:4700::1111,2001:4860:4860::8888` | IPv6 DNS servers for clients |
| `FILENAME_FORMAT` | `ip` | Config naming: `ip` (10.0.0.2.conf) or `increment` (peer1.conf) |
| `FORCE_CONFIG_REGENERATION` | `false` | Delete all configs and regenerate on startup |
| `ISOLATE_CLIENTS` | `true` | Prevent client-to-client communication |
| `CLIENT_LISTEN_PORT` | (empty) | Fixed client listen port (empty = random) |
| `PERSISTENT_KEEPALIVE` | (empty) | Keepalive interval in seconds for NAT traversal |

## IP Modes

- **ipv4** (default): IPv4 only, clients get `Address = 10.0.0.x/32`
- **ipv6**: IPv6 only, clients get `Address = fd00::x/128`, requires IPv6 connectivity
- **dual**: Both protocols, clients get `Address = 10.0.0.x/32, fd00::x/128`

## Key Regeneration

Regenerate keys for a specific client without restarting the container:

```bash
touch regen_requests/10.0.0.50      # By IPv4
touch regen_requests/fd00--50       # By IPv6 (colons → dashes)
touch regen_requests/peer5          # By peer name
```

The container watches `regen_requests/`, generates new keys, updates the config, and hot-updates WireGuard.

## Manual Setup

Clone the repo, copy `.env.example` to `.env`, then `docker compose up -d`. Configs appear in `./configs/`.

**Host requirements:** Docker, WireGuard kernel module, IP forwarding enabled, firewall port open (51820/udp).

## Directory Structure

```
wireguard-firehose/
├── configs/              # Client .conf files
├── keys/                 # Server keys and client public key cache
├── regen_requests/       # Drop files here to trigger key regeneration
├── .env                  # Configuration
├── docker-compose.yml
└── qr.sh                 # QR code generator
```

## Building

```bash
docker build -t taofuprotocol/wireguard-firehose .
```

## Docker Hub

Images at `taofuprotocol/wireguard-firehose`: `latest`, `<version>`, `latest-development`
