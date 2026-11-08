'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadConfig, readInterfaceConfig, parseCIDR, parseIPv4 } = require('./config');
const { Manager } = require('./manager');
const { activeIdentity, serverPublicKey, status } = require('./wireguard');

const publicDir = path.join(__dirname, '..', 'client');
const mimeTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };

function json(res, statusCode, value) {
  const body = JSON.stringify(value);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY'
  });
  res.end(body);
}

function unauthorized(res) {
  return json(res, 401, { error: 'Authentication required.' });
}

function authenticated(req, token) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return false;
  const provided = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}

function readJSON(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      body += chunk;
      if (Buffer.byteLength(body) > 16_384) { tooLarge = true; body = ''; }
    });
    req.on('end', () => {
      if (tooLarge) return reject(Object.assign(new Error('Request body is too large.'), { statusCode: 413 }));
      try { resolve(JSON.parse(body)); }
      catch { reject(Object.assign(new Error('Request body must be valid JSON.'), { statusCode: 400 })); }
    });
    req.on('error', reject);
  });
}

function createServer(config, manager) {
  return http.createServer(async (req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    let url;
    try { url = new URL(req.url, 'http://localhost'); }
    catch { return json(res, 400, { error: 'Invalid request target.' }); }
    try {
      if (url.pathname.startsWith('/api/')) {
        if (!authenticated(req, config.token)) return unauthorized(res);
        if (req.method === 'GET' && url.pathname === '/api/status') return json(res, 200, await manager.getStatus());
        if (req.method === 'GET' && url.pathname === '/api/peers') return json(res, 200, { peers: await manager.listPeers() });
        if (req.method === 'POST' && url.pathname === '/api/peers') {
          if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) return json(res, 415, { error: 'Send application/json.' });
          const body = await readJSON(req);
          if (!body || typeof body.name !== 'string' || body.name.trim().length < 1 || body.name.trim().length > 64 || /[\u0000-\u001f\u007f]/.test(body.name)) {
            return json(res, 400, { error: 'Device name must be 1-64 printable characters.' });
          }
          return json(res, 201, await manager.addPeer(body.name.trim()));
        }
        const match = /^\/api\/peers\/([0-9a-f-]{36})$/.exec(url.pathname);
        if (req.method === 'DELETE' && match) {
          const removed = await manager.removePeer(match[1]);
          return removed ? json(res, 200, { removed: true }) : json(res, 404, { error: 'Managed device not found.' });
        }
        return json(res, 404, { error: 'API route not found.' });
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed.' });
      const file = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
      if (!['index.html', 'app.js', 'styles.css'].includes(file)) return json(res, 404, { error: 'Not found.' });
      const content = fs.readFileSync(path.join(publicDir, file));
      res.writeHead(200, { 'Content-Type': mimeTypes[path.extname(file)], 'Cache-Control': file === 'index.html' ? 'no-cache' : 'public, max-age=300', 'Content-Length': content.length });
      res.end(req.method === 'HEAD' ? undefined : content);
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      if (error.statusCode) return json(res, error.statusCode, { error: error.message });
      console.error(`[request] ${req.method} ${url.pathname}: ${error.message}`);
      return json(res, 500, { error: 'The operation failed. Check the server logs.' });
    }
  });
}

async function main() {
  if (process.platform !== 'linux') throw new Error('Snapper VPN requires a Linux WireGuard gateway.');
  const config = loadConfig();
  const ifaceConfig = readInterfaceConfig(config.configPath);
  const configuredAddress = /^\s*Address\s*=\s*(\S+)/mi.exec(ifaceConfig.content)[1].split(',')[0].trim();
  const configuredIP = configuredAddress.split('/')[0];
  const configuredCIDR = parseCIDR(configuredAddress);
  const requestedNetwork = config.subnet;
  if (parseIPv4(configuredIP) !== parseIPv4(config.serverAddress) || configuredCIDR.network !== requestedNetwork.network || configuredCIDR.prefix !== requestedNetwork.prefix) {
    throw new Error('WG_SERVER_ADDRESS and WG_CLIENT_SUBNET must match the first Address entry in WG_CONFIG_PATH.');
  }
  await status(config.iface);
  const [active, configuredPublicKey] = await Promise.all([
    activeIdentity(config.iface),
    serverPublicKey(ifaceConfig.serverKey)
  ]);
  if (active.publicKey !== configuredPublicKey || active.listenPort !== ifaceConfig.listenPort) {
    throw new Error('The live WireGuard interface does not match its on-disk config. Reconcile the interface and config before starting the manager.');
  }
  const manager = new Manager(config, ifaceConfig);
  await manager.reconcileRevocations();
  const server = createServer(config, manager);
  const recoveryTimer = setInterval(() => {
    manager.reconcileRevocations().catch((error) => console.error(`[recovery] Pending peer revocation could not be completed: ${error.message}`));
  }, 15_000);
  recoveryTimer.unref();
  server.listen(config.port, config.bind, () => {
    console.log(`Snapper VPN manager listening on http://${config.bind}:${config.port}`);
    console.log(`WireGuard interface ${config.iface} is active; admin API is bearer-token protected.`);
  });
  const shutdown = () => { clearInterval(recoveryTimer); server.close(() => process.exit(0)); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`Startup failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { authenticated, createServer, readJSON };
