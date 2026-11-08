'use strict';

const tokenKey = 'snapper-admin-token';
const authPanel = document.getElementById('auth-panel');
const dashboard = document.getElementById('dashboard');
const tokenInput = document.getElementById('token');
const authError = document.getElementById('auth-error');
const deviceRows = document.getElementById('device-rows');
const emptyState = document.getElementById('empty-state');
const dialog = document.getElementById('device-dialog');
const form = document.getElementById('device-form');
const inviteDialog = document.getElementById('invite-dialog');
const deviceName = document.getElementById('device-name');
const deviceError = document.getElementById('device-error');
const createButton = document.getElementById('create-device');
let toastTimer;

function showToast(message, isError = false) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.toggle('error', isError);
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3600);
}

function setAuthenticated(value) {
  authPanel.hidden = value;
  dashboard.hidden = !value;
  document.getElementById('sign-out').hidden = !value;
}

async function api(path, options = {}) {
  const token = sessionStorage.getItem(tokenKey);
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), Authorization: `Bearer ${token}`, ...options.headers }
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    sessionStorage.removeItem(tokenKey);
    setAuthenticated(false);
    authError.textContent = 'That token was not accepted. Please try again.';
    throw new Error('Authentication required.');
  }
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatHandshake(timestamp) {
  if (!timestamp) return { label: 'Never connected', active: false };
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - timestamp);
  if (seconds < 180) return { label: 'Just now', active: true };
  if (seconds < 3600) return { label: `${Math.floor(seconds / 60)} min ago`, active: false };
  if (seconds < 86400) return { label: `${Math.floor(seconds / 3600)} hr ago`, active: false };
  return { label: `${Math.floor(seconds / 86400)} days ago`, active: false };
}

function renderPeers(peers) {
  deviceRows.replaceChildren();
  document.getElementById('nav-count').textContent = String(peers.length);
  emptyState.hidden = peers.length !== 0;
  for (const peer of peers) {
    const row = document.createElement('tr');
    const device = document.createElement('td');
    const deviceInfo = document.createElement('div');
    deviceInfo.className = 'device-name';
    const icon = document.createElement('span');
    icon.className = 'device-icon';
    icon.textContent = '⌘';
    const label = document.createElement('span');
    label.textContent = peer.name;
    const kind = document.createElement('small');
    kind.className = 'device-kind';
    kind.textContent = peer.managed ? 'Managed WireGuard peer' : 'Added outside Snapper';
    label.append(kind);
    deviceInfo.append(icon, label);
    device.append(deviceInfo);

    const address = document.createElement('td');
    address.className = 'code';
    address.textContent = peer.address;
    const handshake = document.createElement('td');
    handshake.className = 'handshake';
    const state = formatHandshake(peer.latestHandshake);
    const indicator = document.createElement('span');
    indicator.className = state.active ? 'live-indicator' : 'muted-dot';
    handshake.append(indicator, document.createTextNode(state.label));
    const traffic = document.createElement('td');
    traffic.textContent = formatBytes(peer.receivedBytes);
    const actions = document.createElement('td');
    if (peer.managed && peer.id) {
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'row-action';
      remove.textContent = 'Revoke';
      remove.setAttribute('aria-label', `Revoke ${peer.name}`);
      remove.addEventListener('click', async () => {
        if (!window.confirm(`Revoke access for “${peer.name}”? Its tunnel will stop working immediately.`)) return;
        remove.disabled = true;
        try {
          await api(`/api/peers/${encodeURIComponent(peer.id)}`, { method: 'DELETE' });
          showToast(`${peer.name} has been revoked.`);
          await refresh();
        } catch (error) {
          showToast(error.message, true);
          remove.disabled = false;
        }
      });
      actions.append(remove);
    }
    row.append(device, address, handshake, traffic, actions);
    deviceRows.append(row);
  }
}

async function refresh() {
  const [status, peerData] = await Promise.all([api('/api/status'), api('/api/peers')]);
  document.getElementById('gateway-label').textContent = 'Gateway online';
  document.getElementById('gateway-dot').classList.remove('offline');
  document.getElementById('stat-connected').textContent = String(status.connectedDevices);
  document.getElementById('stat-peers').textContent = String(status.configuredPeers);
  document.getElementById('stat-endpoint').textContent = status.endpoint;
  document.getElementById('stat-port').textContent = String(status.listenPort);
  document.getElementById('subnet-value').textContent = status.clientSubnet;
  renderPeers(peerData.peers);
  document.getElementById('last-updated').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}

function downloadConfig(peer) {
  const blob = new Blob([peer.config], { type: 'text/plain;charset=utf-8' });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  const safeName = peer.name.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'device';
  anchor.href = objectUrl;
  anchor.download = `snapper-${safeName}.conf`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

async function unlock(token) {
  sessionStorage.setItem(tokenKey, token);
  authError.textContent = '';
  setAuthenticated(true);
  try {
    await refresh();
  } catch (error) {
    if (sessionStorage.getItem(tokenKey)) {
      setAuthenticated(false);
      authError.textContent = error.message === 'Failed to fetch' ? 'Cannot reach the gateway. Check your connection and try again.' : error.message;
    }
  }
}

document.getElementById('auth-form').addEventListener('submit', (event) => {
  event.preventDefault();
  unlock(tokenInput.value);
});

document.getElementById('sign-out').addEventListener('click', () => {
  sessionStorage.removeItem(tokenKey);
  setAuthenticated(false);
  tokenInput.value = '';
  authError.textContent = '';
  tokenInput.focus();
});

function openDialog() {
  deviceError.textContent = '';
  deviceName.value = '';
  dialog.showModal();
  deviceName.focus();
}
document.getElementById('add-device').addEventListener('click', openDialog);
document.getElementById('empty-add').addEventListener('click', openDialog);
document.getElementById('close-dialog').addEventListener('click', () => dialog.close());
document.getElementById('cancel-dialog').addEventListener('click', () => dialog.close());
dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });

document.getElementById('invite-app').addEventListener('click', () => {
  document.getElementById('invite-error').textContent = '';
  document.getElementById('invite-result').hidden = true;
  document.getElementById('invite-start').hidden = false;
  inviteDialog.showModal();
});

function clearInvitation() {
  document.getElementById('invite-code').textContent = '';
  document.getElementById('invite-expiry').textContent = '';
}
document.getElementById('close-invite').addEventListener('click', () => inviteDialog.close());
inviteDialog.addEventListener('click', (event) => { if (event.target === inviteDialog) inviteDialog.close(); });
inviteDialog.addEventListener('close', clearInvitation);

document.getElementById('create-invite').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const error = document.getElementById('invite-error');
  error.textContent = '';
  button.disabled = true;
  button.textContent = 'Generating…';
  try {
    const invitation = await api('/api/invitations', { method: 'POST', body: JSON.stringify({}) });
    document.getElementById('invite-code').textContent = invitation.invitation;
    document.getElementById('invite-expiry').textContent = `Expires ${new Date(invitation.expiresAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}.`;
    document.getElementById('invite-start').hidden = true;
    document.getElementById('invite-result').hidden = false;
  } catch (apiError) {
    error.textContent = apiError.message;
  } finally {
    button.disabled = false;
    button.innerHTML = 'Generate invitation <span>→</span>';
  }
});

document.getElementById('copy-invite').addEventListener('click', async () => {
  const invitation = document.getElementById('invite-code').textContent;
  try {
    await navigator.clipboard.writeText(invitation);
    showToast('Invitation copied. Share it only with its intended user.');
  } catch {
    showToast('Clipboard access unavailable. Select and copy the invitation manually.', true);
  }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = deviceName.value.trim();
  if (!name) return;
  deviceError.textContent = '';
  createButton.disabled = true;
  createButton.textContent = 'Generating keys…';
  try {
    const peer = await api('/api/peers', { method: 'POST', body: JSON.stringify({ name }) });
    downloadConfig(peer);
    dialog.close();
    showToast(`Configuration downloaded for ${peer.name}. Import it into WireGuard.`);
    refresh().catch(() => showToast('Device created; gateway stats could not refresh.', true));
  } catch (error) {
    deviceError.textContent = error.message;
  } finally {
    createButton.disabled = false;
    createButton.innerHTML = 'Create configuration <span>→</span>';
  }
});

const existingToken = sessionStorage.getItem(tokenKey);
if (existingToken) unlock(existingToken);
else { setAuthenticated(false); tokenInput.focus(); }
setInterval(() => {
  if (!dashboard.hidden && sessionStorage.getItem(tokenKey)) refresh().catch((error) => {
    if (error.message === 'Failed to fetch') {
      document.getElementById('gateway-label').textContent = 'Gateway unreachable';
      document.getElementById('gateway-dot').classList.add('offline');
    }
  });
}, 30_000);
