'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const net = require('node:net');
const { parseCIDR, parseIPv4 } = require('../server/config');

function command(cmd, args) {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function fail(message) {
  console.error(`Setup stopped: ${message}`);
  process.exit(1);
}

function main() {
  if (process.platform !== 'linux') fail('Run this installer on the Linux server that will host WireGuard.');
  if (process.getuid?.() !== 0) fail('Run as root: sudo npm run setup -- vpn.example.com');
  const suppliedEndpoint = process.argv[2];
  if (!suppliedEndpoint) fail('Provide your public DNS name or IP, for example: sudo npm run setup -- vpn.example.com');
  const endpoint = suppliedEndpoint.startsWith('[') && suppliedEndpoint.endsWith(']')
    ? `${suppliedEndpoint}:51820`
    : suppliedEndpoint.includes(':') ? suppliedEndpoint : `${suppliedEndpoint}:51820`;
  const host = endpoint.slice(0, endpoint.lastIndexOf(':'));
  const hostnameValid = (value) => value.length <= 253 && value.split('.').every((label) => label.length >= 1 && label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label));
  const addressValid = host.startsWith('[')
    ? net.isIP(host.slice(1, -1)) === 6
    : net.isIP(host) === 4 || (net.isIP(host) === 0 && !/^\d+(?:\.\d+){3}$/.test(host) && hostnameValid(host));
  if (!endpoint.endsWith(':51820') || !addressValid) fail('Use a valid public IPv4/hostname or bracketed IPv6 address. This setup uses UDP port 51820.');
  if (net.isIP(host) === 0 && /^\d+(?:\.\d+){3}$/.test(host)) {
    try { parseIPv4(host); } catch { fail('The IPv4 endpoint is invalid.'); }
  }

  const iface = process.env.WG_INTERFACE || 'wg0';
  if (!/^[A-Za-z0-9_.-]{1,15}$/.test(iface)) fail('WG_INTERFACE must be a Linux interface name no longer than 15 characters.');
  const subnetText = process.env.WG_CLIENT_SUBNET || '10.77.0.0/24';
  const subnet = parseCIDR(subnetText);
  const privateRanges = [[0x0a000000, 0xff000000], [0xac100000, 0xfff00000], [0xc0a80000, 0xffff0000]];
  if (subnet.prefix < 16 || subnet.prefix > 30 || subnet.address !== subnet.network || !privateRanges.some(([network, mask]) => ((subnet.network & mask) >>> 0) === network)) {
    fail('WG_CLIENT_SUBNET must be a network-aligned RFC1918 IPv4 subnet between /16 and /30.');
  }
  const serverAddress = process.env.WG_SERVER_ADDRESS || '10.77.0.1';
  const serverNumber = parseIPv4(serverAddress);
  if (((serverNumber & subnet.mask) >>> 0) !== subnet.network || serverNumber === subnet.network || serverNumber === (subnet.network | (~subnet.mask >>> 0))) fail('WG_SERVER_ADDRESS must be a usable address inside WG_CLIENT_SUBNET.');
  try { command('which', ['ip']); } catch { fail("Required command 'ip' is missing. Install iproute2 first."); }
  const existingRoutes = command('ip', ['-4', 'route', 'show']).split(/\r?\n/);
  const subnetLast = subnet.network + (2 ** (32 - subnet.prefix) - 1);
  for (const line of existingRoutes) {
    const tokens = line.trim().split(/\s+/);
    const destination = /^[0-9]/.test(tokens[0]) ? tokens[0] : tokens[1];
    if (!destination || destination === 'default' || !/^[0-9]/.test(destination)) continue;
    const route = parseCIDR(destination.includes('/') ? destination : `${destination}/32`);
    const routeLast = route.network + (2 ** (32 - route.prefix) - 1);
    if (subnet.network <= routeLast && route.network <= subnetLast) fail(`WG_CLIENT_SUBNET ${subnetText} overlaps the server's existing route ${destination}; choose a different private subnet.`);
  }
  const route = command('ip', ['-4', 'route', 'show', 'default']);
  const device = /\bdev\s+([A-Za-z0-9_.:-]+)/.exec(route)?.[1];
  if (!device || !/^[A-Za-z0-9_.:-]{1,32}$/.test(device)) fail('Could not determine the public network interface. Set up a default IPv4 route first.');
  const wgDir = '/etc/wireguard';
  const configPath = path.join(wgDir, `${iface}.conf`);
  const appDir = path.resolve(__dirname, '..');
  const envPath = path.join(appDir, '.env');
  const sysctlPath = '/etc/sysctl.d/99-snapper-vpn.conf';
  const statePath = '/var/lib/snapper-vpn/peers.json';
  if (fs.existsSync(configPath)) fail(`${configPath} already exists. Refusing to overwrite an existing VPN.`);
  if (fs.existsSync(envPath)) fail(`${envPath} already exists. Back it up and remove it before running setup again.`);
  if (fs.existsSync(sysctlPath)) fail(`${sysctlPath} already exists. Refusing to replace an existing system configuration.`);
  if (fs.existsSync(statePath)) fail(`${statePath} already exists. Refusing to reuse existing peer state.`);
  let interfaceIsActive = false;
  try { command('wg', ['show', iface]); interfaceIsActive = true; } catch {}
  if (interfaceIsActive) fail(`WireGuard interface ${iface} is already active; choose an unused interface name.`);

  for (const tool of ['wg', 'wg-quick', 'iptables', 'systemctl', 'sysctl']) {
    try { command('which', [tool]); } catch { fail(`Required command '${tool}' is missing. Install WireGuard tools, iptables, and systemd first.`); }
  }
  let privateKey;
  let publicKey;
  try {
    privateKey = command('wg', ['genkey']);
    publicKey = execFileSync('wg', ['pubkey'], { input: `${privateKey}\n`, encoding: 'utf8' }).trim();
  } catch (error) { fail(`WireGuard key generation failed: ${error.message}`); }

  const udpPort = Number(endpoint.slice(endpoint.lastIndexOf(':') + 1));
  const wireguardConfig = [
    '[Interface]',
    `Address = ${serverAddress}/${subnet.prefix}`,
    `ListenPort = ${udpPort}`,
    `PrivateKey = ${privateKey}`,
    'SaveConfig = false',
    `PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${subnetText} -o ${device} -j MASQUERADE`,
    `PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${subnetText} -o ${device} -j MASQUERADE`,
    ''
  ].join('\n');
  const token = crypto.randomBytes(32).toString('hex');
  const envFile = [
    `WG_INTERFACE=${iface}`,
    `WG_ENDPOINT=${endpoint}`,
    `WG_CONFIG_PATH=${configPath}`,
    'WG_STATE_PATH=/var/lib/snapper-vpn/peers.json',
    `WG_CLIENT_SUBNET=${subnetText}`,
    `WG_SERVER_ADDRESS=${serverAddress}`,
    'CLIENT_DNS=1.1.1.1',
    'CLIENT_ALLOWED_IPS=0.0.0.0/0, ::/0',
    'HOST=127.0.0.1',
    'PORT=3000',
    `ADMIN_TOKEN=${token}`,
    ''
  ].join('\n');

  try {
    fs.mkdirSync(wgDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(configPath, wireguardConfig, { mode: 0o600, flag: 'wx' });
    fs.chmodSync(configPath, 0o600);
    fs.mkdirSync('/var/lib/snapper-vpn', { recursive: true, mode: 0o700 });
    fs.chmodSync('/var/lib/snapper-vpn', 0o700);
    fs.writeFileSync(envPath, envFile, { mode: 0o600, flag: 'wx' });
    fs.chmodSync(envPath, 0o600);
    fs.writeFileSync('/etc/sysctl.d/99-snapper-vpn.conf', 'net.ipv4.ip_forward=1\n', { mode: 0o644 });
    command('sysctl', ['--system']);
    command('systemctl', ['enable', '--now', `wg-quick@${iface}`]);
  } catch (error) {
    console.error(`Gateway setup did not complete: ${error.message}`);
    console.error(`Review ${configPath} and ${envPath} before retrying. No existing files were overwritten.`);
    process.exit(1);
  }

  console.log('\nWireGuard gateway configured.');
  console.log(`Server public key: ${publicKey}`);
  console.log(`Endpoint: ${endpoint} (UDP) · Public interface: ${device}`);
  console.log(`Admin token (save it now): ${token}`);
  console.log(`Environment saved with mode 0600 to ${envPath}`);
  console.log('\nNext: open UDP 51820 in your cloud firewall, install/start the Snapper management service as root,');
  console.log('and put it behind HTTPS before using the web dashboard remotely. See README.md.');
}

main();
