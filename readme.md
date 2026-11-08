# Snapper VPN

Snapper is a **self-hosted WireGuard gateway and device manager** for a real Linux VPN server. The tunnel cryptography and packet transport are provided by WireGuard (kernel implementation and `wireguard-tools`); this project does not invent a VPN protocol or wrap TCP messages in custom encryption. The Node.js service provisions and revokes WireGuard peers, persists them into the gateway configuration, and issues one-time client configuration downloads.

This is a single-gateway, IPv4-addressed peer manager. Pick a client subnet that does not overlap networks already used by your server or clients. Client profiles route IPv4 and IPv6 default traffic into the tunnel. The included gateway setup provides IPv4 forwarding/NAT; it does **not** provide IPv6 internet egress, so IPv6 traffic is securely routed into the tunnel but will not reach IPv6 destinations until you configure routed IPv6 on the host. Do not advertise IPv6 egress until you have implemented and tested that separately.

## What works

- Creates an independent WireGuard keypair and VPN address for each device using the system `wg` binary.
- Applies peer changes to the live interface and persists them for the next `wg-quick` start.
- Revokes a managed peer from both the live interface and on-disk configuration.
- Shows configured peers, actual WireGuard handshake timestamps, and transferred bytes from the live interface.
- Generates a client `.conf` once at web-admin creation. The private client key is not written to the server's peer database or WireGuard config.
- Issues ten-minute, single-use enrollment invitations and accepts client-generated WireGuard public keys without receiving the client's private key (`POST /api/invitations`, `POST /api/enroll`).
- Provides a small, token-protected admin dashboard with no sample devices or fabricated connection status.
- Uses only Node.js built-ins; no JavaScript runtime dependencies are required.

## Requirements and deployment boundary

Use a dedicated, currently patched Debian/Ubuntu Linux host with Node.js 20+, systemd, WireGuard (`wg` and `wg-quick`), `iproute2`, and `iptables`. The host must have a public IPv4 address or working UDP port-forward and a default IPv4 route. A public DNS name is recommended. The host/cloud firewall must allow **UDP 51820** and TCP 443 (plus SSH for administration). The setup script enables IPv4 forwarding and installs an iptables masquerade rule for the VPN subnet.

The dashboard manager intentionally listens on `127.0.0.1:3000`. Expose it only through a properly configured HTTPS reverse proxy. Do not bind the manager directly to a public interface. The manager needs root-level ownership of the WireGuard config and `CAP_NET_ADMIN`; the provided systemd unit confines writes to `/etc/wireguard` and `/var/lib/snapper-vpn`, but it is still a highly trusted gateway process. Keep the host and repository secure, restrict administrative access at the reverse proxy/firewall, use a strong private admin token, and patch the host. This repo is not a hosted VPN provider, does not include billing/accounts, and does not claim independent security audit or production certification.

## Install a real gateway

1. Provision a clean Debian/Ubuntu Linux server. Point a DNS A record such as `vpn.example.com` at its public IPv4 address. If the server is behind NAT, forward UDP 51820 to it. Install the required OS packages and Node.js 20 or newer using your distribution's trusted package source.

   ```sh
   sudo apt update
   sudo apt install -y wireguard iptables iproute2
   node --version  # must be v20 or newer
   ```

2. Put this repository at `/opt/snapper-vpn` and install it as a root-owned deployment. The setup command refuses to overwrite an existing WireGuard config or `.env` file.

   ```sh
   sudo install -d -o root -g root -m 0755 /opt/snapper-vpn
   sudo git clone https://github.com/BengalEmpire/Snapper-VPN.git /opt/snapper-vpn
   cd /opt/snapper-vpn
   sudo npm run setup -- vpn.example.com
   ```

   The installer generates a unique server private key, creates `/etc/wireguard/wg0.conf` with mode `0600`, enables IPv4 forwarding and starts `wg-quick@wg0`. It creates `/opt/snapper-vpn/.env` with mode `0600` and prints a random 256-bit admin token **once**. Save the token in a password manager. Do not commit, email, or paste `.env` or client `.conf` files into tickets. The setup script is the only source of the production `.env`; this repository does not ship placeholder credentials.

   Ensure UDP 51820 is allowed by both the host firewall and the cloud/network firewall. Do not expose TCP 3000. `CLIENT_ALLOWED_IPS` defaults to `0.0.0.0/0, ::/0`: IPv4 uses the configured NAT egress; IPv6 is routed into the tunnel and blocked at the gateway unless you separately configure IPv6 forwarding/routing. This avoids silently sending client IPv6 traffic outside the tunnel. DNS defaults to `1.1.1.1` and can be changed in `.env`.

3. Start the peer manager with the supplied restricted systemd unit. The unit assumes this repository path and the default `wg0` interface. If you chose a different path or `WG_INTERFACE`, update its `WorkingDirectory`, `ExecStart`, and `After` dependencies before installing it.

   ```sh
   sudo cp scripts/snapper-vpn.service /etc/systemd/system/snapper-vpn.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now snapper-vpn
   sudo systemctl status snapper-vpn --no-pager
   ```

4. Configure Nginx (or another maintained reverse proxy) with a valid TLS certificate. Example Nginx location; use your actual domain and configure TLS in the `server` block. Add an IP allowlist at the proxy when practical.

   ```nginx
   server {
       listen 443 ssl;
       server_name vpn.example.com;
       add_header Strict-Transport-Security "max-age=31536000" always;
       # Configure ssl_certificate and ssl_certificate_key for this hostname.
       location / {
           proxy_pass http://127.0.0.1:3000;
           proxy_http_version 1.1;
           proxy_set_header Host $host;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header X-Forwarded-Proto https;
       }
   }
   ```

   Open TCP 443 at the firewalls. Visit `https://vpn.example.com`, enter the admin token, and add a device. Import its downloaded `.conf` in the official WireGuard application. The file contains that device's private key; treat it like a password. Each device should get its own peer. If the download is lost, revoke that peer and create a replacement rather than attempting to recover its private key.

## Native-client enrollment API

The Flutter client must not receive `ADMIN_TOKEN`. An administrator creates an invitation over the manager's HTTPS URL; keep the token in an operator-only shell variable and do not paste it into chat or source control:

```sh
read -rsp 'Snapper admin token: ' SNAPPER_ADMIN_TOKEN; export SNAPPER_ADMIN_TOKEN; echo
curl --fail-with-body --silent --show-error -X POST 'https://vpn.example.com/api/invitations' \
  -H "Authorization: Bearer $SNAPPER_ADMIN_TOKEN"
```

The response contains a random invitation valid for ten minutes. Deliver it to the intended user through a trusted channel. A native client generates its WireGuard keypair locally, stores its private key in OS-protected storage, then sends the invitation, device name, and public key to `POST /api/enroll` over HTTPS. That endpoint returns only the allocated VPN address, server public key, endpoint, DNS, and allowed routes; it never returns or stores the client's private key. Invitations can be retried with the same public key during their validity window, but cannot enroll a different key.

The enrollment API currently has no user accounts or per-device login session. The administrator remains responsible for issuing invitations from the dashboard and revoking enrolled peers from the management dashboard/API. Native mobile/desktop app UI and tunnel adapters are future work.

## Operations

- `sudo systemctl status wg-quick@wg0` checks the tunnel interface; `sudo wg show wg0` shows live peers and handshakes.
- `sudo systemctl status snapper-vpn` and `sudo journalctl -u snapper-vpn` inspect the manager. Request logs intentionally do not print client private keys or bearer tokens.
- Back up `/etc/wireguard/wg0.conf`, `/var/lib/snapper-vpn/peers.json`, and the protected `.env` securely. Losing the server private key or peer state requires recovery; store backups encrypted and offline.
- If the manager is stopped, already-connected tunnels continue operating. While it is stopped, peer changes cannot be applied. The UI reports actual kernel state, not cached demo data.
- Peer creation uses atomic config/state writes and live WireGuard updates. Revocation records a durable intent before removing the live peer and config; a small recovery loop completes interrupted revocations. Avoid manually editing managed peer blocks while the service is running. Existing unmanaged peers are displayed as externally managed and cannot be revoked from this UI.
- To change the interface, endpoint, subnet, DNS, or allowed networks, edit the protected `.env` and matching WireGuard config as appropriate, then restart the manager. Changing the tunnel subnet also requires changing the interface address and existing client configurations. Take a backup first.
- The setup uses IPv4 iptables rules. It does not configure IPv6 egress, nftables policy, cloud firewall rules, DNS, TLS certificates, or network-provider port forwarding for you.

## Client platform roadmap

The Flutter Android/iOS/Windows clients, browser extension, and Rust WebView shell are not implemented yet. Their platform-specific integration plan, security boundaries, prerequisites, and acceptance gates are documented in [the client and browser roadmap](docs/mobile-desktop-browser-plan.md). The server now supports one-time client-public-key enrollment, but the admin token must never be embedded in a distributed client.

## Local development and checks

The dashboard and API require a real active WireGuard interface for runtime operations; there is no simulated backend or fake tunnel mode. You can run the dependency-free unit suite on any OS:

```sh
npm test
```

On a configured gateway, start with `npm start` (the process must be able to read the WireGuard config and run `wg show`/`wg set`). The service validates its environment, interface config, and live interface on startup and fails closed if they are not available.
