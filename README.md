# WireGuard Firehose

Auto-provisioning WireGuard VPN server in Docker. Generates thousands of client configurations automatically on startup.

## Quick Start

1. Clone this repository
2. Copy `.env.example` to `.env` and configure as needed
3. Run the container:

```bash
docker-compose up -d
```

4. Client configurations are available in the `./configs` directory

## Host Dependencies (Ubuntu 24 LTS)

Install the required packages on your Ubuntu 24 LTS host:

```bash
# Install Docker using the official install script
curl -fsSL https://get.docker.com | sudo sh

# Add your user to the docker group (logout/login required)
sudo usermod -aG docker $USER

# Install WireGuard kernel module (usually pre-installed on Ubuntu 24)
sudo apt install -y wireguard-tools

# Verify the WireGuard module is available
sudo modprobe wireguard
lsmod | grep wireguard
```

Enable IP forwarding (persists across reboots):

```bash
# Enable IPv4 forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wireguard.conf
echo 'net.ipv4.conf.all.src_valid_mark=1' | sudo tee -a /etc/sysctl.d/99-wireguard.conf

# Apply immediately
sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
```

Open the firewall port (if UFW is enabled):

```bash
sudo ufw allow 51820/udp
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WIREGUARD_PORT` | `51820` | WireGuard UDP listen port |
| `INTERNAL_SUBNET_CIDR` | `10.0.0.0/16` | VPN internal subnet |
| `MAX_CONFIGS` | `50000` | Maximum client configs to generate |
| `ALLOWEDIPS` | `0.0.0.0/0` | Client routing (full tunnel by default) |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8,8.8.4.4` | DNS servers for clients |

## Client Configuration Files

Client configs are named by their internal IP address:
- `10.0.0.2.conf`
- `10.0.0.3.conf`
- etc.

The server uses `.1` of the subnet (e.g., `10.0.0.1`).

## Persistence

- Client configurations are stored in `/configs` (mounted as `./configs`)
- Server keys are persisted in `/configs/.server_private_key` and `/configs/.server_public_key`
- Existing configurations are preserved on restart

## Requirements

The container requires:
- `NET_ADMIN` capability
- `SYS_MODULE` capability (for some kernels)
- Access to `/dev/net/tun`
- UDP port access for WireGuard

These are configured in the provided `docker-compose.yml`.

## Building

```bash
docker build -t taofuprotocol/wireguard-firehose .
```

## Docker Hub

Images are published to `taofuprotocol/wireguard-firehose`:
- `latest` - Latest stable release
- `<version>` - Specific version
- `latest-development` - Latest development build
- `<version>-development` - Specific development version

## GitHub Secrets Required

For CI/CD deployment to Docker Hub, configure these repository secrets:
- `DOCKERHUB_USERNAME` - Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token
