'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseCIDR, parseIPv4, readInterfaceConfig, validateAllowedIPs } = require('../server/config');
const { appendPeer, atomicWrite, getPeerNetwork, parsePeers, removePeer } = require('../server/wireguard');
const { Manager } = require('../server/manager');
const { authenticated } = require('../server/index');

const baseConfig = `[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51820\nPrivateKey = ${crypto.randomBytes(32).toString('base64')}\n`;
const peerKey = crypto.randomBytes(32).toString('base64');

test('parses IPv4 addresses and network-aligned CIDRs', () => {
  assert.equal(parseIPv4('10.77.0.9'), 172818441);
  assert.deepEqual(parseCIDR('10.77.0.0/24'), { address: 172818432, prefix: 24, mask: 4294967040, network: 172818432 });
  assert.throws(() => parseIPv4('256.1.1.1'), /Invalid IPv4/);
  assert.throws(() => parseCIDR('10.77.0.0/33'), /Invalid IPv4 CIDR/);
});

test('rejects malformed client route networks', () => {
  assert.doesNotThrow(() => validateAllowedIPs('0.0.0.0/0, ::/0'));
  assert.doesNotThrow(() => validateAllowedIPs('10.20.0.0/16'));
  assert.throws(() => validateAllowedIPs('300.20.0.0/16'), /Invalid IPv4/);
  assert.throws(() => validateAllowedIPs('10.20.0.0/16,, ::/0'), /empty or duplicate/);
  assert.throws(() => validateAllowedIPs('::/0, ::/0'), /empty or duplicate/);
});

test('requires restrictive permissions on the server WireGuard configuration', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'snapper-vpn-config-'));
  const file = path.join(directory, 'wg0.conf');
  try {
    fs.writeFileSync(file, baseConfig, { mode: 0o644 });
    assert.throws(() => readInterfaceConfig(file), /0600 or stricter/);
    fs.chmodSync(file, 0o600);
    assert.equal(readInterfaceConfig(file).listenPort, 51820);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('appends, parses, and removes a single WireGuard peer section', () => {
  const withPeer = appendPeer(baseConfig, peerKey, '10.77.0.2');
  const peers = parsePeers(withPeer);
  assert.equal(peers.length, 1);
  assert.equal(peers[0].fields.publickey, peerKey);
  assert.deepEqual(getPeerNetwork(peers[0]), { address: 172818434, prefix: 32 });
  assert.equal(parsePeers(removePeer(withPeer, peerKey)).length, 0);
  assert.throws(() => removePeer(baseConfig, peerKey), /not present/);
});

test('peer allocator skips gateway, existing peers, and overlapping routes', () => {
  const manager = new Manager({ subnet: parseCIDR('10.77.0.0/24'), subnetText: '10.77.0.0/24', serverAddress: '10.77.0.1' }, {});
  const peers = appendPeer(baseConfig, peerKey, '10.77.0.2');
  assert.equal(manager.allocateAddress(peers), '10.77.0.3');
  assert.equal(manager.allocateAddress(baseConfig, [{ allowedIPs: '10.77.0.2/32' }]), '10.77.0.3');
  const highRange = new Manager({ subnet: parseCIDR('192.168.240.0/24'), subnetText: '192.168.240.0/24', serverAddress: '192.168.240.1' }, {});
  assert.equal(highRange.allocateAddress(baseConfig), '192.168.240.2');
  const overlapping = appendPeer(baseConfig, peerKey, '10.77.0.2').replace('AllowedIPs = 10.77.0.2/32', 'AllowedIPs = 10.77.0.0/24');
  assert.throws(() => manager.allocateAddress(overlapping), /subnet is full/);
});

test('atomic writes use restrictive permissions and replace complete files', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'snapper-vpn-test-'));
  try {
    const file = path.join(directory, 'state', 'peers.json');
    atomicWrite(file, '{"version":1}\n');
    assert.equal(fs.readFileSync(file, 'utf8'), '{"version":1}\n');
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('bearer token authentication compares valid tokens and rejects missing or incorrect ones', () => {
  const secret = '0123456789abcdef0123456789abcdef';
  assert.equal(authenticated({ headers: { authorization: `Bearer ${secret}` } }, secret), true);
  assert.equal(authenticated({ headers: { authorization: `Bearer ${secret.slice(1)}` } }, secret), false);
  assert.equal(authenticated({ headers: {} }, secret), false);
});
