'use strict';

const { execFile, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { parseIPv4 } = require('./config');

const execFileAsync = promisify(execFile);

async function run(command, args, options = {}) {
  try {
    const { stdout } = await execFileAsync(command, args, { timeout: 10_000, maxBuffer: 1024 * 1024, ...options });
    return stdout.trim();
  } catch (error) {
    const detail = (error.stderr || error.message || 'command failed').trim();
    throw new Error(`${command} failed: ${detail}`);
  }
}

function runWithInput(command, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timeout = setTimeout(() => child.kill('SIGKILL'), 10_000);
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => { clearTimeout(timeout); reject(error); });
    child.on('close', (code) => {
      clearTimeout(timeout);
      if (code !== 0) reject(new Error(`${command} failed: ${(stderr || `exit code ${code}`).trim()}`));
      else resolve(stdout.trim());
    });
    child.stdin.end(input);
  });
}

async function generateKeyPair() {
  const privateKey = await run('wg', ['genkey']);
  const publicKey = await runWithInput('wg', ['pubkey'], `${privateKey}\n`);
  return { privateKey, publicKey };
}

function parsePeers(configText) {
  const lines = configText.split(/(?<=\n)/);
  const peers = [];
  let section = null;
  let cursor = 0;
  for (const line of lines) {
    const header = /^\s*\[(\w+)\]\s*(?:#.*)?\r?\n?$/.exec(line);
    if (header) {
      if (section && section.type === 'Peer') {
        section.end = cursor;
        peers.push(section);
      }
      section = header[1] === 'Peer' ? { type: 'Peer', start: cursor, fields: {} } : { type: header[1] };
    } else if (section && section.type === 'Peer') {
      const field = /^\s*([A-Za-z]+)\s*=\s*(.*?)\s*(?:#.*)?\r?\n?$/.exec(line);
      if (field) section.fields[field[1].toLowerCase()] = field[2];
    }
    cursor += line.length;
  }
  if (section && section.type === 'Peer') {
    section.end = cursor;
    peers.push(section);
  }
  return peers.filter((peer) => peer.fields.publickey && peer.fields.allowedips);
}

function getPeerNetwork(peer) {
  const cidr = peer.fields.allowedips.split(',')[0].trim();
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
  if (!match) return null;
  try { return { address: parseIPv4(match[1]), prefix: Number(match[2]) }; }
  catch { return null; }
}

function appendPeer(configText, publicKey, address) {
  const ending = configText.endsWith('\n') ? '' : '\n';
  return `${configText}${ending}\n[Peer]\nPublicKey = ${publicKey}\nAllowedIPs = ${address}/32\nPersistentKeepalive = 25\n`;
}

function removePeer(configText, publicKey) {
  const matches = parsePeers(configText);
  const peer = matches.find((item) => item.fields.publickey === publicKey);
  if (!peer) throw new Error('Peer is not present in the WireGuard configuration.');
  return configText.slice(0, peer.start) + configText.slice(peer.end);
}

function atomicWrite(filePath, content, mode = 0o600) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tempPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  try {
    fs.writeFileSync(tempPath, content, { mode, flag: 'wx' });
    fs.chmodSync(tempPath, mode);
    fs.renameSync(tempPath, filePath);
  } catch (error) {
    try { fs.unlinkSync(tempPath); } catch {}
    throw error;
  }
}

async function setPeer(iface, publicKey, allowedIPs, keepalive = '25') {
  const normalizedIPs = allowedIPs.includes('/') ? allowedIPs : `${allowedIPs}/32`;
  const args = ['set', iface, 'peer', publicKey, 'allowed-ips', normalizedIPs];
  if (keepalive !== null && keepalive !== undefined && keepalive !== '') args.push('persistent-keepalive', String(keepalive));
  return run('wg', args);
}

async function removeLivePeer(iface, publicKey) {
  return run('wg', ['set', iface, 'peer', publicKey, 'remove']);
}

async function status(iface) {
  const [handshakes, transfers, allowed] = await Promise.all([
    run('wg', ['show', iface, 'latest-handshakes']),
    run('wg', ['show', iface, 'transfer']),
    run('wg', ['show', iface, 'allowed-ips'])
  ]);
  const handshakeByKey = new Map(handshakes.split('\n').filter(Boolean).map((line) => line.split('\t')));
  const transferByKey = new Map(transfers.split('\n').filter(Boolean).map((line) => line.split('\t')));
  const peers = allowed.split('\n').filter(Boolean).map((line) => {
    const [publicKey, allowedIPs] = line.split('\t');
    const [receivedBytes = '0', sentBytes = '0'] = transferByKey.get(publicKey) || [];
    return {
      publicKey,
      allowedIPs,
      latestHandshake: Number(handshakeByKey.get(publicKey)?.[1] || 0),
      receivedBytes: Number(receivedBytes),
      sentBytes: Number(sentBytes)
    };
  });
  return { interface: iface, peers };
}

async function serverPublicKey(privateKey) {
  return runWithInput('wg', ['pubkey'], `${privateKey}\n`);
}

async function activeIdentity(iface) {
  const [publicKey, listenPort] = await Promise.all([
    run('wg', ['show', iface, 'public-key']),
    run('wg', ['show', iface, 'listen-port'])
  ]);
  return { publicKey, listenPort: Number(listenPort) };
}

module.exports = { activeIdentity, appendPeer, atomicWrite, generateKeyPair, getPeerNetwork, parsePeers, removeLivePeer, removePeer, serverPublicKey, setPeer, status };
