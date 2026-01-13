# Wireguard docker container: firehose mode

This docker container is designed to set up a wireguard server and auto-provision it with a configurable subnet setting. It uses `zsh` for the entrypoint.

Docker repo: `taofuprotocol/wireguard-firehose`

## File structure:

- `Dockerfile` specifies the container
- `docker-compose.yml` specifies the usage of the container, includes default values as fallbacks
- `.github/workflows` contains the actions declarations
- `.env.example` contains example environment variable configs that work out of the box
- `README.md` documentation explaining how to use this repository

## Configuration

This container is configured with the following environment variables:

- `WIREGUARD_PORT` - this sets the wireguard port. Default value: `51820`
- `INTERNAL_SUBNET_CIDR` - this sets the subnet that wireguard will use. Default value: `10.0.0.0/16`
- `MAX_CONFIGS` - this sets the maximum amount of configurations to generate. Default value: `50000`
- `ALLOWEDIPS` - this sets the wireguard allowed ips for the clients. Default value: `0.0.0.0/0`
- `DNS_SERVERS` - this sets the default DNS servers. Default value: `1.1.1.1,8.8.8.8,8.8.4.4`

## Container behavior

The container on boot will do the following things:

- container has logging helpers for `grey`, `green`, `red`, `orange`. They change the color of terminal lines.
- the container logs our what it does where `grey` is info that is nice to know but can be ignored, `red` is an explicit fail, `green` is an explicit success, `orange` is a suggestion
- Check that all needed dependencies and permissions are set up, including container capabilities
- Set required `sysctl` for the connections to work
- Validate the `INTERNAL_SUBNET_CIDR` and `MAX_CONFIGS` values to check them for validity, including checking if `MAX_CONFIGS` is possible with the current `SUBNET_CIDR`
- Gets the server public ip using failover-strategy call of common ip getting services like `icanhazip.com`
- Generate wireguard client configs that do not exist yet (so skip existing configs and handle the ip addresses already in the config list) including all needed info that such a config needs in order to connect. Naming scheme is based on the internal ip of the client, example: `10.0.0.4.conf`
- Generate the server config for the wireguard server, the server ip is `.1`
- Start the wireguard server

## Docker image 

The docker image has the following properties:

- uses `alpine:latest` as a base for the `Dockerfile`
- has all required dependencies preinstalled
- expects a mounted volume at `/configs` which is where the client configs are stored
- expects the correct permissions like network capabilities, which is documented using a `docker-compose.yml` file
- has a healthcheck based on a port check using `nc` against `WIREGUARD_PORT`

## Deployment flow

This project deploys to docker hub using Github actions:

- if there is a new git tag, this triggers a deploy
- if the current branch is development, the tag is `:<version>-development` and `:latest-development`
- if the current branch is main, the tag is `:<version>` and `:latest`
- the github actions logs into dockerhub and uses buildx caching with `cache-from` and `cache-to` type gha
