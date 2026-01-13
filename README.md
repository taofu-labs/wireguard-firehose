# WireGuard Firehose

Auto-provisioning WireGuard VPN server in Docker. Generates thousands of client configurations automatically on startup.

## Automatic Setup (Recommended)

Run this one-liner on a fresh Ubuntu 24 LTS server to install everything:

```bash
curl -fsSL https://raw.githubusercontent.com/taofu-labs/wireguard-firehose/main/setup.sh | sudo bash
```

This will:
- Install Docker, WireGuard, and qrencode
- Configure kernel parameters and firewall
- Download the docker-compose.yml to `~/wireguard-firehose`
- Create a default `.env` configuration file
- Pull the Docker image

After setup, start the server:

```bash
cd ~/wireguard-firehose
docker compose up -d
```

## Manual Setup

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

# Install WireGuard and qrencode
sudo apt install -y wireguard-tools qrencode

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
| `FILENAME_FORMAT` | `ip` | Config naming: `ip` (10.0.0.2.conf) or `increment` (peer1.conf) |
| `FORCE_CONFIG_REGENERATION` | `false` | Set to `true` to delete all configs and regenerate on startup |
| `ISOLATE_CLIENTS` | `true` | Prevent clients from communicating with each other |

### Client Isolation

By default, `ISOLATE_CLIENTS=true` prevents VPN clients from communicating with each other. Each client can only reach the internet through the VPN tunnel.

Set `ISOLATE_CLIENTS=false` to allow client-to-client communication (e.g., for LAN gaming, file sharing between clients).

## Client Configuration Files

Client configs are named based on `FILENAME_FORMAT`:

**ip mode (default):**
- `10.0.0.2.conf`
- `10.0.0.3.conf`
- etc.

**increment mode:**
- `peer1.conf`
- `peer2.conf`
- etc.

The server uses `.1` of the subnet (e.g., `10.0.0.1`).

## Scripts

### QR Code Generator

Generate QR codes for client configs to easily import on mobile devices:

```bash
./qr.sh              # Show QR for first, middle, and last config
./qr.sh peer5        # Show QR for specific config
./qr.sh 10.0.0.5     # Show QR for specific IP-named config
./qr.sh peer1 peer2  # Show QR for multiple configs
```

Requires `qrencode` on the host (installed automatically by setup.sh).

## Key Regeneration

Regenerate keys for a specific client to invalidate existing connections and allow new clients to use the config. This works without restarting the container.

```bash
# Regenerate by IP address
touch regen_requests/10.0.0.50

# Regenerate by peer name (increment mode)
touch regen_requests/peer5
```

The container watches the `regen_requests/` folder. When a file is created:
1. New keypair is generated
2. Client config file is updated with new private key
3. WireGuard interface is hot-updated (old peer removed, new peer added)
4. Request file is deleted on success

Use cases:
- Rotate compromised credentials
- Disconnect a client and reassign the config
- Periodic key rotation

## Directory Structure

```
wireguard-firehose/
├── configs/              # Client .conf files
│   ├── peer1.conf        # (or 10.0.0.2.conf in ip mode)
│   └── ...
├── keys/                 # Server keys and cached client public keys
│   ├── server_private_key
│   ├── server_public_key
│   ├── 10.0.0.2.pubkey
│   └── ...
├── regen_requests/       # Drop files here to trigger key regeneration
├── .env                  # Configuration
├── docker-compose.yml
└── qr.sh                 # QR code generator
```

## Persistence

- Client configurations are stored in `/configs` (mounted as `./configs`)
- Server keys and public key cache are stored in `/keys` (mounted as `./keys`)
- Existing configurations are preserved on restart (unless `FORCE_CONFIG_REGENERATION=true`)

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
