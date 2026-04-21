const { execSync } = require('child_process');
const db = require('../db');

// Generate WireGuard keypair using wg tool
function generateKeypair() {
  const privateKey = execSync('wg genkey').toString().trim();
  const publicKey = execSync(`echo "${privateKey}" | wg pubkey`).toString().trim();
  const presharedKey = execSync('wg genpsk').toString().trim();
  return { privateKey, publicKey, presharedKey };
}

// Find next available IP in subnet (10.66.66.X)
function getNextPeerIP() {
  const subnet = process.env.VPN_SUBNET || '10.66.66';

  // IPs 2-254 available (1 = server)
  const used = db.prepare(`SELECT peer_ip FROM vpn_configs`).all().map(r => r.peer_ip);
  for (let i = 2; i <= 254; i++) {
    const ip = `${subnet}.${i}`;
    if (!used.includes(ip)) return ip;
  }
  throw new Error('No available IPs in VPN subnet');
}

// Build AmneziaWG client config
function buildConfig({ privateKey, presharedKey, peerIP }) {
  const {
    VPN_SERVER_IP,
    VPN_SERVER_PORT,
    VPN_SERVER_PUBLIC_KEY,
    VPN_DNS,
    AWG_JC,
    AWG_JMIN,
    AWG_JMAX,
    AWG_S1,
    AWG_S2,
    AWG_H1,
    AWG_H2,
    AWG_H3,
    AWG_H4,
  } = process.env;

  return `[Interface]
PrivateKey = ${privateKey}
Address = ${peerIP}/32
DNS = ${VPN_DNS}

Jc = ${AWG_JC}
Jmin = ${AWG_JMIN}
Jmax = ${AWG_JMAX}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}

[Peer]
PublicKey = ${VPN_SERVER_PUBLIC_KEY}
PresharedKey = ${presharedKey}
Endpoint = ${VPN_SERVER_IP}:${VPN_SERVER_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
}

// Add peer to live AWG server
function addPeerToServer(publicKey, presharedKey, peerIP) {
  const allowedIPs = `${peerIP}/32`;

  // Write preshared key to temp file
  const fs = require('fs');
  const tmpFile = `/tmp/psk_${Date.now()}`;
  fs.writeFileSync(tmpFile, presharedKey);

  try {
    execSync(
      `awg set awg0 peer ${publicKey} preshared-key ${tmpFile} allowed-ips ${allowedIPs}`,
      { stdio: 'pipe' }
    );
    // Persist to config
    execSync('awg-quick save awg0', { stdio: 'pipe' });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

// Remove peer from AWG server (on expiry)
function removePeerFromServer(publicKey) {
  try {
    execSync(`awg set awg0 peer ${publicKey} remove`, { stdio: 'pipe' });
    execSync('awg-quick save awg0', { stdio: 'pipe' });
  } catch (e) {
    console.error('Failed to remove peer:', e.message);
  }
}

// Main: generate and save config for user
function generateConfigForUser(userId) {
  // Check if config already exists
  const existing = db.prepare(`SELECT * FROM vpn_configs WHERE user_id = ?`).get(userId);
  if (existing) return existing;

  const { privateKey, publicKey, presharedKey } = generateKeypair();
  const peerIP = getNextPeerIP();
  const configText = buildConfig({ privateKey, presharedKey, peerIP });

  // Save to DB
  db.prepare(`
    INSERT INTO vpn_configs (user_id, peer_ip, private_key, public_key, preshared_key, config_text)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(userId, peerIP, privateKey, publicKey, presharedKey, configText);

  // Add to live server
  try {
    addPeerToServer(publicKey, presharedKey, peerIP);
  } catch (e) {
    console.error('Could not add peer to server (running locally?):', e.message);
  }

  return db.prepare(`SELECT * FROM vpn_configs WHERE user_id = ?`).get(userId);
}

module.exports = { generateConfigForUser, removePeerFromServer };
