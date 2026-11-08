'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

function loadLocalEnv() {
  const file = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(file)) return;
  const stats = fs.statSync(file);
  if ((stats.mode & 0o177) !== 0) throw new Error(`${file} must be readable only by its owner (mode 0600 or stricter).`);
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || Object.hasOwn(process.env, match[1])) continue;
    process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
  }
}

function required(name, fallback) {
  const value = process.env[name] || fallback;
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function parseIPv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    throw new Error(`Invalid IPv4 address: ${value}`);
  }
  return parts.reduce((number, part) => number * 256 + Number(part), 0);
}

function parseCIDR(value) {
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/.exec(value);
  if (!match) throw new Error(`Invalid IPv4 CIDR: ${value}`);
  const address = parseIPv4(match[1]);
  const prefix = Number(match[2]);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { address: address >>> 0, prefix, mask, network: (address & mask) >>> 0 };
}

function validateAllowedIPs(value) {
  const entries = value.split(',').map((entry) => entry.trim());
  if (!entries.length || entries.some((entry) => !entry) || new Set(entries).size !== entries.length) throw new Error('CLIENT_ALLOWED_IPS contains an empty or duplicate network.');
  let hasIPv6 = false;
  for (const entry of entries) {
    if (entry === '::/0') {
      if (hasIPv6) throw new Error('CLIENT_ALLOWED_IPS contains duplicate IPv6 routes.');
      hasIPv6 = true;
    } else {
      parseCIDR(entry);
    }
  }
}

function loadConfig() {
  loadLocalEnv();
  const iface = required('WG_INTERFACE', 'wg0');
  if (!/^[a-zA-Z0-9_.-]{1,15}$/.test(iface)) throw new Error('WG_INTERFACE must be a valid Linux interface name (1-15 characters).');

  const endpoint = required('WG_ENDPOINT');
  const endpointMatch = /^(?:\[([0-9a-fA-F:]+)\]|([a-zA-Z0-9.-]+)):(\d{1,5})$/.exec(endpoint);
  const hostnameValid = (value) => value.length <= 253 && value.split('.').every((label) => label.length >= 1 && label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label));
  const hostValid = endpointMatch && (endpointMatch[1]
    ? net.isIP(endpointMatch[1]) === 6
    : net.isIP(endpointMatch[2]) === 4 || (net.isIP(endpointMatch[2]) === 0 && !/^\d+(?:\.\d+){3}$/.test(endpointMatch[2]) && hostnameValid(endpointMatch[2])));
  if (!endpointMatch || !hostValid || Number(endpointMatch[3]) < 1 || Number(endpointMatch[3]) > 65535) {
    throw new Error('WG_ENDPOINT must be a valid hostname or IP with a UDP port, e.g. vpn.example.com:51820.');
  }
  if (endpointMatch[2] && /^\d+(?:\.\d+){3}$/.test(endpointMatch[2])) parseIPv4(endpointMatch[2]);

  const subnetText = required('WG_CLIENT_SUBNET', '10.77.0.0/24');
  const subnet = parseCIDR(subnetText);
  const privateRanges = [[0x0a000000, 0xff000000], [0xac100000, 0xfff00000], [0xc0a80000, 0xffff0000]];
  if (subnet.prefix < 16 || subnet.prefix > 30 || subnet.address !== subnet.network || !privateRanges.some(([network, mask]) => (subnet.network & mask) >>> 0 === network)) {
    throw new Error('WG_CLIENT_SUBNET must be a network-aligned RFC1918 IPv4 subnet between /16 and /30.');
  }
  const serverAddress = required('WG_SERVER_ADDRESS', '10.77.0.1');
  const serverNumber = parseIPv4(serverAddress);
  if (serverNumber === subnet.network || serverNumber === (subnet.network | (~subnet.mask >>> 0)) || ((serverNumber & subnet.mask) >>> 0) !== subnet.network) {
    throw new Error('WG_SERVER_ADDRESS must be a usable address inside WG_CLIENT_SUBNET.');
  }

  const token = required('ADMIN_TOKEN');
  if (Buffer.byteLength(token, 'utf8') < 32) throw new Error('ADMIN_TOKEN must contain at least 32 bytes. Generate one with: openssl rand -hex 32');

  const configPath = path.resolve(required('WG_CONFIG_PATH', `/etc/wireguard/${iface}.conf`));
  const statePath = path.resolve(required('WG_STATE_PATH', '/var/lib/snapper-vpn/peers.json'));
  if (configPath === statePath) throw new Error('WG_CONFIG_PATH and WG_STATE_PATH must refer to different files.');
  const bind = required('HOST', '127.0.0.1');
  if (bind !== '127.0.0.1') throw new Error('HOST must remain 127.0.0.1; expose the dashboard only through a local HTTPS reverse proxy.');
  const port = Number(required('PORT', '3000'));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be a valid TCP port.');
  const dns = required('CLIENT_DNS', '1.1.1.1');
  parseIPv4(dns);
  const allowedIPs = required('CLIENT_ALLOWED_IPS', '0.0.0.0/0, ::/0');
  validateAllowedIPs(allowedIPs);
  return { iface, endpoint, subnet, subnetText, serverAddress, token, configPath, statePath, bind, port, dns, allowedIPs };
}

function readInterfaceConfig(configPath) {
  let content;
  try {
    const stats = fs.statSync(configPath);
    if ((stats.mode & 0o177) !== 0) throw new Error('file permissions must be 0600 or stricter');
    content = fs.readFileSync(configPath, 'utf8');
  } catch (error) { throw new Error(`Cannot read secure WireGuard config ${configPath}: ${error.message}`); }
  if (!/^\s*\[Interface\]\s*$/m.test(content) || !/^\s*PrivateKey\s*=\s*\S+/m.test(content) || !/^\s*Address\s*=\s*\S+/m.test(content)) {
    throw new Error(`WireGuard config ${configPath} must contain [Interface], PrivateKey, and Address. Run the setup instructions in README.md first.`);
  }
  const listenPort = /^\s*ListenPort\s*=\s*(\d+)/mi.exec(content);
  if (!listenPort) throw new Error(`WireGuard config ${configPath} must declare ListenPort.`);
  const serverKey = /^\s*PrivateKey\s*=\s*(\S+)/mi.exec(content)[1];
  return { content, listenPort: Number(listenPort[1]), serverKey };
}

module.exports = { loadConfig, parseCIDR, parseIPv4, readInterfaceConfig, validateAllowedIPs };
