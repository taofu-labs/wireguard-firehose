# Wireguard docker container: firehose mode

This docker container is designed to set up a wireguard server and auto-provision it with a configurable subnet setting. It uses `zsh` for the entrypoint.

Docker repo: `taofuprotocol/wireguard-firehose`

## File structure

- `Dockerfile` specifies the container
- `docker-compose.yml` specifies the usage of the container, includes default values as fallbacks
- `entrypoint.zsh` main container entrypoint script
- `setup.sh` one-liner installation script for Ubuntu/Debian hosts
- `qr.sh` QR code generator script for client configs
- `.github/workflows` contains the actions declarations
- `.env.example` contains example environment variable configs that work out of the box
- `README.md` documentation explaining how to use this repository

## Configuration

This container is configured with the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `WIREGUARD_PORT` | `51820` | WireGuard UDP listen port (1-65535) |
| `INTERNAL_SUBNET_CIDR` | `10.0.0.0/16` | VPN internal subnet |
| `MAX_CONFIGS` | `50000` | Maximum client configs to generate |
| `ALLOWEDIPS` | `0.0.0.0/0` | Client routing (comma-separated CIDRs) |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8,8.8.4.4` | DNS servers for clients (comma-separated) |
| `FILENAME_FORMAT` | `ip` | Config naming: `ip` (10.0.0.2.conf) or `increment` (peer1.conf) |
| `FORCE_CONFIG_REGENERATION` | `false` | Delete all configs/keys and regenerate on startup |
| `ISOLATE_CLIENTS` | `true` | Prevent clients from communicating with each other |

## Volume mounts

The container expects the following mounted volumes:

| Path | Purpose |
|------|---------|
| `/configs` | Client .conf files (persistent) |
| `/keys` | Server keys and client public key cache (persistent) |
| `/regen_requests` | Drop files here to trigger key regeneration |

## Container behavior

### Startup sequence

The container on boot performs the following:

1. **Logging setup** - helpers for `grey` (info), `green` (success), `red` (error), `orange` (warning)
2. **Dependency check** - validates all required tools and capabilities are available
3. **Input validation** - validates all environment variables:
   - Port numbers (1-65535)
   - CIDR notation with octet validation (0-255)
   - DNS server format with octet validation
   - Boolean values for flags
4. **Sysctl configuration** - sets required kernel parameters for VPN routing
5. **Public IP detection** - failover strategy using `icanhazip.com`, `ifconfig.me`, `ipinfo.io/ip`
6. **Server key management** - loads or generates server keypair in `/keys`
7. **Batch key generation** - pre-generates keypairs in batches for performance
8. **Config generation** - generates missing client configs, preserving existing ones
9. **WireGuard startup** - creates interface and adds all peers
10. **Firewall rules** - sets up NAT and optional client isolation
11. **Key regeneration watcher** - starts background process monitoring `/regen_requests`

### Key regeneration

The container watches the `/regen_requests` folder using `inotifywait`. When a file is created:

1. Validates the identifier (IP address or peer name)
2. Generates new keypair for the client
3. Updates the client config file atomically
4. Hot-updates WireGuard interface (removes old peer, adds new peer)
5. Deletes the request file on success

Usage:
```bash
# Regenerate by IP address
touch regen_requests/10.0.0.50

# Regenerate by peer name (increment mode)
touch regen_requests/peer5
```

### Client isolation

When `ISOLATE_CLIENTS=true` (default), iptables rules prevent VPN clients from communicating with each other. Each client can only reach the internet through the VPN tunnel.

Set `ISOLATE_CLIENTS=false` to allow client-to-client communication.

### Graceful shutdown

On SIGTERM/SIGINT, the container:
1. Stops the key regeneration watcher process
2. Cleans up temporary files
3. Brings down the WireGuard interface

## Docker image

The docker image has the following properties:

- Base image: `alpine:latest`
- Required packages: `wireguard-tools`, `zsh`, `iproute2`, `iptables`, `curl`, `netcat-openbsd`, `bash`, `inotify-tools`, `grep`
- Volume mounts: `/configs`, `/keys`, `/regen_requests`
- Required capabilities: `NET_ADMIN`
- Security options: `no-new-privileges:true`
- Device access: `/dev/net/tun`
- Healthcheck: UDP port check using `nc` against `WIREGUARD_PORT`

## Security features

- **Input validation** - all environment variables validated with strict patterns
- **Octet validation** - IP addresses validated for 0-255 range per octet
- **Path traversal protection** - identifiers validated to prevent directory escape
- **Atomic file writes** - configs written to temp files then renamed
- **No privilege escalation** - `no-new-privileges` security option
- **Key validation** - WireGuard keys validated for correct length (44 chars base64)

## Host scripts

### setup.sh

One-liner installation script for Ubuntu/Debian:
```bash
curl -fsSL https://raw.githubusercontent.com/taofu-labs/wireguard-firehose/main/setup.sh | sudo bash
```

Installs Docker, WireGuard tools, configures kernel parameters, firewall, and downloads docker-compose.yml.

### qr.sh

QR code generator for client configs:
```bash
./qr.sh              # Show QR for first, middle, and last config
./qr.sh peer5        # Show QR for specific config
./qr.sh 10.0.0.5     # Show QR for specific IP-named config
./qr.sh peer1 peer2  # Show QR for multiple configs
```

Requires `qrencode` on the host (installed by setup.sh).

## Deployment flow

This project deploys to Docker Hub using GitHub Actions:

- Triggered by new git tags
- Development branch: `:<version>-development` and `:latest-development`
- Main branch: `:<version>` and `:latest`
- Uses buildx caching with `cache-from` and `cache-to` type gha

Required GitHub secrets:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
