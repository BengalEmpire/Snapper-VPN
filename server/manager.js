'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const { parseCIDR, parseIPv4 } = require('./config');
const { parsePeers, generateKeyPair, appendPeer, removePeer, atomicWrite, setPeer, removeLivePeer, status, serverPublicKey } = require('./wireguard');

function ipv4Text(number) {
  return [24, 16, 8, 0].map((shift) => (number >>> shift) & 255).join('.');
}

function loadState(statePath) {
  try {
    const stats = fs.statSync(statePath);
    if ((stats.mode & 0o177) !== 0) throw new Error('file permissions must be 0600 or stricter');
    const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    if (parsed.version !== 1 || !parsed.peers || typeof parsed.peers !== 'object' || Array.isArray(parsed.peers)) throw new Error('unsupported state format');
    if (parsed.revocations !== undefined && (!Array.isArray(parsed.revocations) || parsed.revocations.some((key) => typeof key !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(key)))) throw new Error('invalid revocation journal');
    if (parsed.invitations !== undefined && (!parsed.invitations || typeof parsed.invitations !== 'object' || Array.isArray(parsed.invitations))) throw new Error('invalid invitations');
    for (const [hash, invitation] of Object.entries(parsed.invitations || {})) {
      if (!/^[a-f0-9]{64}$/.test(hash) || !Number.isSafeInteger(invitation.expiresAt) || (invitation.consumedByPublicKey && !/^[A-Za-z0-9+/]{43}=$/.test(invitation.consumedByPublicKey))) throw new Error('invalid invitation record');
    }
    return { ...parsed, revocations: parsed.revocations || [], invitations: parsed.invitations || {} };
  } catch (error) {
    if (error.code === 'ENOENT') return { version: 1, peers: {}, revocations: [], invitations: {} };
    throw new Error(`Cannot load peer state ${statePath}: ${error.message}`);
  }
}

function operationError(message, statusCode) {
  return Object.assign(new Error(message), { statusCode });
}

function validWireGuardKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 32 && bytes.some((byte) => byte !== 0) && bytes.toString('base64') === value;
}

function validDeviceName(value) {
  return typeof value === 'string' && value.trim().length >= 1 && value.trim().length <= 64 && !/[\u0000-\u001f\u007f]/.test(value);
}

class Manager {
  constructor(config, ifaceConfig) {
    this.config = config;
    this.ifaceConfig = ifaceConfig;
    this.queue = Promise.resolve();
  }

  serialize(operation) {
    const next = this.queue.then(operation, operation);
    this.queue = next.catch(() => {});
    return next;
  }

  readConfig() {
    return fs.readFileSync(this.config.configPath, 'utf8');
  }

  readState() {
    return loadState(this.config.statePath);
  }

  async listPeers() {
    const conf = this.readConfig();
    const state = this.readState();
    const live = await status(this.config.iface);
    const liveByKey = new Map(live.peers.map((peer) => [peer.publicKey, peer]));
    return parsePeers(conf).map((peer) => {
      const publicKey = peer.fields.publickey;
      const saved = state.peers[publicKey];
      const address = peer.fields.allowedips.split(',')[0].trim();
      const runtime = liveByKey.get(publicKey);
      return {
        id: saved?.id || null,
        name: saved?.name || 'Externally managed peer',
        address,
        publicKey,
        managed: Boolean(saved),
        latestHandshake: runtime?.latestHandshake || 0,
        receivedBytes: runtime?.receivedBytes || 0,
        sentBytes: runtime?.sentBytes || 0
      };
    });
  }

  async getStatus() {
    const live = await status(this.config.iface);
    const publicKey = await serverPublicKey(this.ifaceConfig.serverKey);
    return {
      interface: this.config.iface,
      endpoint: this.config.endpoint,
      listenPort: this.ifaceConfig.listenPort,
      serverPublicKey: publicKey,
      connectedDevices: live.peers.filter((peer) => peer.latestHandshake > 0 && Date.now() / 1000 - peer.latestHandshake <= 180).length,
      configuredPeers: live.peers.length,
      clientSubnet: this.config.subnetText
    };
  }

  createInvitation() {
    return this.serialize(async () => {
      const state = this.readState();
      const now = Date.now();
      const invitations = Object.fromEntries(Object.entries(state.invitations).filter(([, entry]) => entry.expiresAt > now));
      const pending = Object.values(invitations).filter((entry) => !entry.consumedByPublicKey).length;
      if (pending >= 100) throw operationError('There are already 100 active invitations. Wait for some to expire or use them first.', 429);
      const token = crypto.randomBytes(32).toString('base64url');
      const expiresAt = now + 10 * 60 * 1000;
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      invitations[hash] = { createdAt: now, expiresAt };
      atomicWrite(this.config.statePath, `${JSON.stringify({ ...state, invitations }, null, 2)}\n`, 0o600);
      return { invitation: token, expiresAt: new Date(expiresAt).toISOString() };
    });
  }

  async ensureManagedPeer(publicKey, address, liveByKey = null) {
    let configText = this.readConfig();
    const configuredPeer = parsePeers(configText).find((peer) => peer.fields.publickey === publicKey);
    if (configuredPeer) {
      const configuredIPs = configuredPeer.fields.allowedips.split(',').map((value) => value.trim());
      if (configuredIPs.length !== 1 || configuredIPs[0] !== `${address}/32`) throw new Error('Managed peer address does not match its persistent WireGuard config.');
    } else {
      configText = appendPeer(configText, publicKey, address);
      atomicWrite(this.config.configPath, configText, 0o600);
    }
    if (!liveByKey) {
      const live = await status(this.config.iface);
      liveByKey = new Map(live.peers.map((peer) => [peer.publicKey, peer]));
    }
    const current = liveByKey.get(publicKey);
    if (!current || current.allowedIPs !== `${address}/32`) {
      await setPeer(this.config.iface, publicKey, `${address}/32`);
      liveByKey.set(publicKey, { publicKey, allowedIPs: `${address}/32` });
    }
  }

  enrollDevice(name, publicKey, token) {
    return this.serialize(async () => {
      if (!validDeviceName(name)) throw operationError('Device name must be 1-64 printable characters.', 400);
      if (!validWireGuardKey(publicKey)) throw operationError('A valid WireGuard public key is required.', 400);
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw operationError('Invalid or expired invitation.', 401);

      const state = this.readState();
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      const invitation = state.invitations[hash];
      if (!invitation) throw operationError('Invalid or expired invitation.', 401);
      if (invitation.expiresAt <= Date.now()) throw operationError('This invitation has expired.', 410);
      if (invitation.consumedByPublicKey) {
        if (invitation.consumedByPublicKey !== publicKey) throw operationError('This invitation has already been used.', 409);
        const saved = state.peers[publicKey];
        if (!saved) throw operationError('This invitation belongs to a device that has been revoked.', 410);
        await this.ensureManagedPeer(publicKey, saved.address);
        return this.enrollmentDetails(saved, await serverPublicKey(this.ifaceConfig.serverKey));
      }
      if (state.peers[publicKey]) throw operationError('This public key is already enrolled.', 409);

      const configText = this.readConfig();
      const live = await status(this.config.iface);
      if (parsePeers(configText).some((peer) => peer.fields.publickey === publicKey) || live.peers.some((peer) => peer.publicKey === publicKey)) {
        throw operationError('This public key is already configured on the gateway.', 409);
      }
      const address = this.allocateAddress(configText, live.peers);
      const serverKey = await serverPublicKey(this.ifaceConfig.serverKey);
      if (publicKey === serverKey) throw operationError('The server key cannot be enrolled as a client device.', 400);
      const peer = { id: crypto.randomUUID(), name: name.trim(), address, createdAt: new Date().toISOString() };
      const nextState = {
        ...state,
        peers: { ...state.peers, [publicKey]: peer },
        invitations: { ...state.invitations, [hash]: { ...invitation, consumedByPublicKey: publicKey } }
      };
      atomicWrite(this.config.statePath, `${JSON.stringify(nextState, null, 2)}\n`, 0o600);
      await this.ensureManagedPeer(publicKey, address);
      return this.enrollmentDetails(peer, serverKey);
    });
  }

  enrollmentDetails(peer, serverKey) {
    return {
      id: peer.id,
      name: peer.name,
      address: `${peer.address}/32`,
      serverPublicKey: serverKey || undefined,
      endpoint: this.config.endpoint,
      allowedIPs: this.config.allowedIPs,
      dns: this.config.dns
    };
  }

  async applyManagedPeers() {
    const state = this.readState();
    const live = await status(this.config.iface);
    const liveByKey = new Map(live.peers.map((peer) => [peer.publicKey, peer]));
    for (const [publicKey, peer] of Object.entries(state.peers)) {
      await this.ensureManagedPeer(publicKey, peer.address, liveByKey);
    }
  }

  async reconcile() {
    return this.serialize(async () => {
      await this.applyRevocations();
      await this.applyManagedPeers();
    });
  }

  async applyRevocations() {
    let state = this.readState();
    for (const publicKey of [...state.revocations]) {
      const live = await status(this.config.iface);
      if (live.peers.some((peer) => peer.publicKey === publicKey)) await removeLivePeer(this.config.iface, publicKey);
      const configText = this.readConfig();
      if (parsePeers(configText).some((peer) => peer.fields.publickey === publicKey)) {
        atomicWrite(this.config.configPath, removePeer(configText, publicKey), 0o600);
      }
      state = this.readState();
      atomicWrite(this.config.statePath, `${JSON.stringify({ ...state, revocations: state.revocations.filter((key) => key !== publicKey) }, null, 2)}\n`, 0o600);
    }
  }

  reconcileRevocations() {
    return this.serialize(() => this.applyRevocations());
  }

  allocateAddress(configText, livePeers = []) {
    const broadcast = this.config.subnet.network + (2 ** (32 - this.config.subnet.prefix) - 1);
    const used = new Set([this.config.subnet.network, broadcast]);
    const reservedNetworks = [];
    const configuredRoutes = parsePeers(configText).flatMap((peer) => peer.fields.allowedips.split(','));
    const liveRoutes = livePeers.flatMap((peer) => (peer.allowedIPs || '').split(','));
    for (const allowedValue of [...configuredRoutes, ...liveRoutes]) {
      const allowed = allowedValue.trim();
      if (allowed && !allowed.includes(':')) reservedNetworks.push(parseCIDR(allowed));
    }
    const first = this.config.subnet.network + 1;
    const last = broadcast - 1;
    const server = parseIPv4(this.config.serverAddress);
    for (let address = first; address <= last; address += 1) {
      if (address !== server && !used.has(address) && !reservedNetworks.some((range) => ((address & range.mask) >>> 0) === range.network)) return ipv4Text(address);
    }
    throw new Error('VPN client subnet is full. Expand WG_CLIENT_SUBNET before adding more devices.');
  }

  addPeer(name) {
    return this.serialize(async () => {
      const configText = this.readConfig();
      const state = this.readState();
      const live = await status(this.config.iface);
      const address = this.allocateAddress(configText, live.peers);
      const { privateKey, publicKey } = await generateKeyPair();
      const serverKey = await serverPublicKey(this.ifaceConfig.serverKey);
      const id = crypto.randomUUID();
      const nextConfig = appendPeer(configText, publicKey, address);
      const nextState = { ...state, peers: { ...state.peers, [publicKey]: { id, name, address, createdAt: new Date().toISOString() } } };
      atomicWrite(this.config.configPath, nextConfig, 0o600);
      try {
        await setPeer(this.config.iface, publicKey, address);
        atomicWrite(this.config.statePath, `${JSON.stringify(nextState, null, 2)}\n`, 0o600);
      } catch (error) {
        atomicWrite(this.config.configPath, configText, 0o600);
        try { await removeLivePeer(this.config.iface, publicKey); } catch {}
        throw error;
      }

      const clientConfig = [
        '[Interface]',
        `PrivateKey = ${privateKey}`,
        `Address = ${address}/32`,
        `DNS = ${this.config.dns}`,
        '',
        '[Peer]',
        `PublicKey = ${serverKey}`,
        `Endpoint = ${this.config.endpoint}`,
        `AllowedIPs = ${this.config.allowedIPs}`,
        'PersistentKeepalive = 25',
        ''
      ].join('\n');
      return { id, name, address: `${address}/32`, publicKey, config: clientConfig };
    });
  }

  removePeer(id) {
    return this.serialize(async () => {
      const state = this.readState();
      const entry = Object.entries(state.peers).find(([, peer]) => peer.id === id);
      if (!entry) return false;
      const [publicKey] = entry;
      const nextPeers = { ...state.peers };
      delete nextPeers[publicKey];
      const revocations = [...new Set([...state.revocations, publicKey])];
      atomicWrite(this.config.statePath, `${JSON.stringify({ ...state, peers: nextPeers, revocations }, null, 2)}\n`, 0o600);
      await this.applyRevocations();
      return true;
    });
  }
}

module.exports = { Manager };
