const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const https = require('https');

require('dotenv').config({ path: '/var/www/amaemonvpn/server/.env' });

const app = express();
app.use(express.json());

// ── Константы ──
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ADMIN_EMAIL = 'toitol@mail.ru';
const DB_PATH = '/var/www/amaemonvpn/server/vpn.db';
const SITE_URL = 'https://amaemonvpn.ru';
const MAX_DEVICES = 4;
const PRICES = { 1: 200, 2: 350, 3: 500, 4: 650 };

// ── AmneziaWG параметры ──
const SCRIPT = '/etc/amnezia/amneziawg/add_client.sh';
const WG_INTERFACE_CONF = '/etc/amnezia/amneziawg/awg0.conf';
const WG_INTERFACE_HEADER = `[Interface]
Address = 10.8.0.1/24
ListenPort = 443
PrivateKey = +JIndR7C04ybl5QY8s+KTKld8WeJA0CCSMF4DvCQpHU=
Jc = 4
Jmin = 40
Jmax = 70
S1 = 50
S2 = 100
H1 = 1836923987
H2 = 1836923988
H3 = 1836923989
H4 = 1836923990

PostUp   = iptables -A FORWARD -i awg0 -j ACCEPT; iptables -A FORWARD -o awg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i awg0 -j ACCEPT; iptables -D FORWARD -o awg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
`;

// ── VLESS+Reality параметры ──
const SERVER_IP = process.env.SERVER_IP || '31.172.77.46';
const SERVER_PORT = process.env.SERVER_PORT || '443';
const REALITY_PUBLIC_KEY = process.env.REALITY_PUBLIC_KEY || '';
const REALITY_SHORT_ID = process.env.REALITY_SHORT_ID || '';
const REALITY_SNI = process.env.REALITY_SNI || 'www.microsoft.com';
const XRAY_CONFIG_PATH = process.env.XRAY_CONFIG_PATH || '/usr/local/etc/xray/config.json';

// ── База данных ──
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT UNIQUE NOT NULL,
    password_hash     TEXT NOT NULL,
    full_name         TEXT NOT NULL,
    subscription_ends INTEGER DEFAULT 0,
    created_at        INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    name           TEXT NOT NULL,
    protocol       TEXT NOT NULL DEFAULT 'amnezia',
    client_name    TEXT UNIQUE,
    config_path    TEXT,
    uuid           TEXT UNIQUE,
    download_token TEXT UNIQUE NOT NULL,
    paused         INTEGER DEFAULT 0,
    created_at     INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ── Middleware ──
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.email !== ADMIN_EMAIL)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ════════════════════════════════
// AMNEZIAWG
// ════════════════════════════════

function rebuildWgConfig() {
  try {
    const now = Math.floor(Date.now() / 1000);
    const activeDevices = db.prepare(`
      SELECT d.client_name, d.config_path FROM devices d
      JOIN users u ON u.id = d.user_id
      WHERE u.subscription_ends > ? AND d.paused = 0 AND d.protocol = 'amnezia'
    `).all(now);

    let conf = WG_INTERFACE_HEADER;
    activeDevices.forEach(d => {
      try {
        const pubKey = fs.readFileSync(
          `/etc/amnezia/amneziawg/clients/${d.client_name}/public.key`, 'utf8'
        ).trim();
        const clientConf = fs.readFileSync(d.config_path, 'utf8');
        const ipMatch = clientConf.match(/Address\s*=\s*(10\.8\.0\.\d+)/);
        if (ipMatch) {
          conf += `\n[Peer]\n# ${d.client_name}\nPublicKey = ${pubKey}\nAllowedIPs = ${ipMatch[1]}/32\n`;
          execSync(`sudo awg set awg0 peer ${pubKey} allowed-ips ${ipMatch[1]}/32`);
        }
      } catch(e) {}
    });

    fs.writeFileSync('/tmp/awg0_new.conf', conf);
    execSync('sudo cp /tmp/awg0_new.conf /etc/amnezia/amneziawg/awg0.conf');
    console.log(`WG config rebuilt: ${activeDevices.length} active peers`);
  } catch(e) {
    console.error('rebuildWgConfig error:', e.message);
  }
}

function addWgPeer(clientName, configPath) {
  try {
    const pubKey = fs.readFileSync(
      `/etc/amnezia/amneziawg/clients/${clientName}/public.key`, 'utf8'
    ).trim();
    const conf = fs.readFileSync(configPath, 'utf8');
    const ipMatch = conf.match(/Address\s*=\s*(10\.8\.0\.\d+)/);
    if (ipMatch) {
      execSync(`sudo awg set awg0 peer ${pubKey} allowed-ips ${ipMatch[1]}/32`);
    }
  } catch(e) {
    console.error('addWgPeer error:', e.message);
  }
}

function removeWgPeer(clientName) {
  try {
    const pubKey = fs.readFileSync(
      `/etc/amnezia/amneziawg/clients/${clientName}/public.key`, 'utf8'
    ).trim();
    execSync(`sudo awg set awg0 peer ${pubKey} remove`);
  } catch(e) {}
}

// ════════════════════════════════
// XRAY / VLESS+REALITY
// ════════════════════════════════

function buildVlessLink(uuid, label) {
  const params = new URLSearchParams({
    type: 'tcp',
    security: 'reality',
    pbk: REALITY_PUBLIC_KEY,
    fp: 'chrome',
    sni: REALITY_SNI,
    sid: REALITY_SHORT_ID,
    flow: 'xtls-rprx-vision'
  });
  const tag = encodeURIComponent(`VPN-${label}`);
  return `vless://${uuid}@${SERVER_IP}:${SERVER_PORT}?${params.toString()}#${tag}`;
}

function readXrayConfig() {
  try {
    return JSON.parse(fs.readFileSync(XRAY_CONFIG_PATH, 'utf8'));
  } catch(e) {
    console.error('readXrayConfig error:', e.message);
    return null;
  }
}

function writeXrayConfig(cfg) {
  fs.writeFileSync(XRAY_CONFIG_PATH, JSON.stringify(cfg, null, 2));
  try {
    execSync('sudo systemctl restart xray', { timeout: 5000 });
  } catch(e) {
    console.error('xray reload error:', e.message);
  }
}

function findVlessInbound(cfg) {
  return cfg.inbounds.findIndex(i => i.protocol === 'vless');
}

function xrayAddUser(uuid, email) {
  try {
    const cfg = readXrayConfig();
    if (!cfg) return false;
    const idx = findVlessInbound(cfg);
    if (idx === -1) return false;
    const clients = cfg.inbounds[idx].settings.clients;
    if (clients.find(c => c.id === uuid)) return true;
    clients.push({ id: uuid, email, flow: 'xtls-rprx-vision' });
    writeXrayConfig(cfg);
    return true;
  } catch(e) {
    console.error('xrayAddUser error:', e.message);
    return false;
  }
}

function xrayRemoveUser(uuid) {
  try {
    const cfg = readXrayConfig();
    if (!cfg) return;
    const idx = findVlessInbound(cfg);
    if (idx === -1) return;
    cfg.inbounds[idx].settings.clients =
      cfg.inbounds[idx].settings.clients.filter(c => c.id !== uuid);
    writeXrayConfig(cfg);
  } catch(e) {
    console.error('xrayRemoveUser error:', e.message);
  }
}

function rebuildXrayConfig() {
  try {
    const cfg = readXrayConfig();
    if (!cfg) return;
    const idx = findVlessInbound(cfg);
    if (idx === -1) return;
    const now = Math.floor(Date.now() / 1000);
    const activeDevices = db.prepare(`
      SELECT d.uuid, u.email FROM devices d
      JOIN users u ON u.id = d.user_id
      WHERE u.subscription_ends > ? AND d.paused = 0 AND d.protocol = 'vless'
    `).all(now);
    cfg.inbounds[idx].settings.clients = activeDevices.map(d => ({
      id: d.uuid, email: d.email, flow: 'xtls-rprx-vision'
    }));
    writeXrayConfig(cfg);
    console.log(`Xray config rebuilt: ${activeDevices.length} active clients`);
  } catch(e) {
    console.error('rebuildXrayConfig error:', e.message);
  }
}

// ════════════════════════════════
// ОБЩИЕ ФУНКЦИИ УПРАВЛЕНИЯ
// ════════════════════════════════

function activateDevice(device, userEmail) {
  if (device.protocol === 'amnezia') {
    addWgPeer(device.client_name, device.config_path);
  } else {
    xrayAddUser(device.uuid, userEmail);
  }
}

function deactivateDevice(device) {
  if (device.protocol === 'amnezia') {
    removeWgPeer(device.client_name);
  } else {
    xrayRemoveUser(device.uuid);
  }
}

// ── ЮКасса ──
function yooRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const authHeader = Buffer.from(
      `${process.env.YOOKASSA_SHOP_ID}:${process.env.YOOKASSA_SECRET_KEY}`
    ).toString('base64');
    const options = {
      hostname: 'api.yookassa.ru',
      path: `/v3/${path}`,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${authHeader}`,
        'Idempotence-Key': crypto.randomBytes(16).toString('hex'),
        'Content-Length': Buffer.byteLength(data)
      }
    };
    const req = https.request(options, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(JSON.parse(d)));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ── Регистрация ──
app.post('/api/register', async (req, res) => {
  const { email, password, full_name } = req.body;
  if (!email || !password || !full_name)
    return res.status(400).json({ error: 'Заполните все поля' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Некорректный email' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return res.status(400).json({ error: 'Email уже зарегистрирован' });
  const password_hash = await bcrypt.hash(password, 10);
  const free_ends = Math.floor(Date.now() / 1000) + 3 * 60 * 60;
  db.prepare('INSERT INTO users (email, password_hash, full_name, subscription_ends) VALUES (?, ?, ?, ?)').run(email, password_hash, full_name, free_ends);
  res.json({ success: true });
});

// ── Вход ──
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Неверный email или пароль' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Неверный email или пароль' });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// ── Профиль ──
app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, full_name, subscription_ends, created_at FROM users WHERE id = ?').get(req.user.id);
  const devices = db.prepare('SELECT id, name, protocol, download_token, paused, created_at FROM devices WHERE user_id = ?').all(req.user.id);
  const price = PRICES[devices.length] || PRICES[1];
  res.json({ ...user, devices, device_count: devices.length, price });
});

// ── Устройства: добавить ──
app.post('/api/devices', auth, async (req, res) => {
  const { name, protocol } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Введите название устройства' });
  if (!['amnezia', 'vless'].includes(protocol))
    return res.status(400).json({ error: 'Неверный протокол' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  if (deviceCount >= MAX_DEVICES)
    return res.status(400).json({ error: `Максимум ${MAX_DEVICES} устройства` });

  const download_token = crypto.randomBytes(32).toString('hex');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const now = Math.floor(Date.now() / 1000);
  const isActive = user.subscription_ends > now;
  const paused = isActive ? 0 : 1;

  let deviceId, deviceData;

  if (protocol === 'amnezia') {
    const client_name = 'u' + Date.now();
    try {
      execSync(`sudo ${SCRIPT} ${client_name}`, { timeout: 15000 });
    } catch(e) {
      return res.status(500).json({ error: 'Ошибка создания конфига AmneziaWG' });
    }
    const config_path = `/etc/amnezia/amneziawg/clients/${client_name}/${client_name}.conf`;
    if (!fs.existsSync(config_path))
      return res.status(500).json({ error: 'Конфиг не создан' });

    const result = db.prepare(`
      INSERT INTO devices (user_id, name, protocol, client_name, config_path, download_token, paused)
      VALUES (?, ?, 'amnezia', ?, ?, ?, ?)
    `).run(req.user.id, name.trim(), client_name, config_path, download_token, paused);

    if (isActive) addWgPeer(client_name, config_path);
    deviceId = result.lastInsertRowid;
    deviceData = { id: deviceId, name: name.trim(), protocol: 'amnezia', download_token, paused };

  } else {
    const uuid = crypto.randomUUID();
    const result = db.prepare(`
      INSERT INTO devices (user_id, name, protocol, uuid, download_token, paused)
      VALUES (?, ?, 'vless', ?, ?, ?)
    `).run(req.user.id, name.trim(), uuid, download_token, paused);

    if (isActive) xrayAddUser(uuid, user.email);
    const vless_link = buildVlessLink(uuid, name.trim());
    deviceId = result.lastInsertRowid;
    deviceData = { id: deviceId, name: name.trim(), protocol: 'vless', download_token, paused, vless_link };
  }

  const newCount = deviceCount + 1;
  res.json({ success: true, device: deviceData, device_count: newCount, price: PRICES[newCount] || 650 });
});

// ── Устройства: удалить ──
app.delete('/api/devices/:id', auth, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!device) return res.status(404).json({ error: 'Устройство не найдено' });

  deactivateDevice(device);

  if (device.protocol === 'amnezia') {
    try { execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${device.client_name}`); } catch {}
  }

  db.prepare('DELETE FROM devices WHERE id = ?').run(device.id);
  const newCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  res.json({ success: true, device_count: newCount, price: PRICES[newCount] || 200 });
});

// ── Скачать конфиг (Amnezia) ──
app.get('/download/:token', (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE download_token = ?').get(req.params.token);
  if (!device) return res.status(404).send('Not found');
  if (device.protocol !== 'amnezia') return res.status(400).send('Use /link/ for VLESS');
  if (!fs.existsSync(device.config_path)) return res.status(404).send('Config not found');
  const safeName = device.name.replace(/[^a-zA-Z0-9]/g, '_');
  res.setHeader('Content-Disposition', `attachment; filename="amaeonvpn_${safeName}.conf"`);
  res.setHeader('Content-Type', 'text/plain');
  res.sendFile(device.config_path);
});

// ── Получить VLESS-ссылку ──
app.get('/link/:token', (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE download_token = ?').get(req.params.token);
  if (!device) return res.status(404).json({ error: 'Not found' });
  if (device.protocol !== 'vless') return res.status(400).json({ error: 'Use /download/ for Amnezia' });
  const link = buildVlessLink(device.uuid, device.name);
  res.json({ link, name: device.name });
});

// ── Админ: все пользователи ──
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, email, full_name, subscription_ends, created_at FROM users ORDER BY created_at DESC').all();
  const result = users.map(u => {
    const devices = db.prepare('SELECT id, name, protocol, client_name, config_path, uuid, download_token, paused, created_at FROM devices WHERE user_id = ?').all(u.id);
    const devicesWithInfo = devices.map(d => {
      let vpn_ip = null;
      if (d.protocol === 'amnezia' && d.config_path) {
        try {
          const conf = fs.readFileSync(d.config_path, 'utf8');
          const m = conf.match(/Address\s*=\s*(10\.8\.0\.\d+)/);
          if (m) vpn_ip = m[1];
        } catch {}
      }
      return { ...d, vpn_ip };
    });
    return { ...u, devices: devicesWithInfo };
  });
  res.json(result);
});

// ── Админ: продлить подписку ──
app.post('/api/admin/extend/:id', auth, adminOnly, (req, res) => {
  const { hours } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const now = Math.floor(Date.now() / 1000);
  const wasExpired = user.subscription_ends < now;
  const base = Math.max(user.subscription_ends || now, now);
  const new_ends = base + (hours || 720) * 3600;

  db.prepare('UPDATE users SET subscription_ends = ? WHERE id = ?').run(new_ends, user.id);

  if (wasExpired) {
    db.prepare('UPDATE devices SET paused = 0 WHERE user_id = ?').run(user.id);
    const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(user.id);
    devices.forEach(d => activateDevice(d, user.email));
  }

  res.json({ success: true, subscription_ends: new_ends });
});

// ── Админ: удалить пользователя ──
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(user.id);
  devices.forEach(d => {
    deactivateDevice(d);
    if (d.protocol === 'amnezia') {
      try { execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${d.client_name}`); } catch {}
    }
  });

  db.prepare('DELETE FROM devices WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  res.json({ success: true });
});

// ── Создать платёж ──
app.post('/api/payment/create', auth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  const price = PRICES[Math.max(deviceCount, 1)] || 200;

  try {
    const payment = await yooRequest('POST', 'payments', {
      amount: { value: price.toFixed(2), currency: 'RUB' },
      confirmation: { type: 'redirect', return_url: `${SITE_URL}/cabinet` },
      capture: true,
      description: `VPN 30 дней, ${deviceCount} устр. — ${user.email}`,
      metadata: { user_id: String(user.id) }
    });
    res.json({ confirmation_url: payment.confirmation.confirmation_url });
  } catch(e) {
    res.status(500).json({ error: 'Ошибка создания платежа' });
  }
});

// ── Webhook от ЮКассы ──
app.post('/api/payment/webhook', async (req, res) => {
  const { event, object } = req.body;
  if (event === 'payment.succeeded') {
    const userId = parseInt(object.metadata?.user_id);
    if (!userId) return res.sendStatus(200);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return res.sendStatus(200);

    const now = Math.floor(Date.now() / 1000);
    const wasExpired = user.subscription_ends < now;
    const base = Math.max(user.subscription_ends || now, now);
    const new_ends = base + 30 * 24 * 3600;
    db.prepare('UPDATE users SET subscription_ends = ? WHERE id = ?').run(new_ends, userId);

    if (wasExpired) {
      db.prepare('UPDATE devices SET paused = 0 WHERE user_id = ?').run(userId);
      const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(userId);
      devices.forEach(d => activateDevice(d, user.email));
    }

    console.log(`Payment succeeded for ${user.email}`);
  }
  res.sendStatus(200);
});

// ── Статистика ──
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);

    // Xray stats
    const xrayActive = db.prepare(`
      SELECT COUNT(*) as cnt FROM devices d JOIN users u ON u.id = d.user_id
      WHERE u.subscription_ends > ? AND d.paused = 0 AND d.protocol = 'vless'
    `).get(now).cnt;

    // WG stats
    let wgPeers = {};
    try {
      const output = execSync('sudo awg show awg0 dump').toString();
      output.split('\n').slice(1).forEach(line => {
        const parts = line.split('\t');
        if (parts.length < 8) return;
        const [pubKey,,, allowedIps, latestHandshake, rxBytes, txBytes] = parts;
        wgPeers[pubKey] = {
          allowedIps,
          latestHandshake: parseInt(latestHandshake) || 0,
          rxBytes: parseInt(rxBytes) || 0,
          txBytes: parseInt(txBytes) || 0
        };
      });
    } catch {}

    res.json({ xray_active: xrayActive, wg_peers: wgPeers });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Проверка истекших подписок ──
function checkExpired() {
  const now = Math.floor(Date.now() / 1000);
  const expiredUsers = db.prepare(`
    SELECT u.id, u.email FROM users u
    WHERE u.subscription_ends < ? AND u.subscription_ends > 0
    AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id AND d.paused = 0)
  `).all(now);

  expiredUsers.forEach(u => {
    const devices = db.prepare('SELECT * FROM devices WHERE user_id = ? AND paused = 0').all(u.id);
    devices.forEach(d => {
      deactivateDevice(d);
      console.log(`Paused ${d.protocol} device ${d.id} for user ${u.email}`);
    });
    db.prepare('UPDATE devices SET paused = 1 WHERE user_id = ?').run(u.id);
  });
}

setInterval(checkExpired, 5 * 60 * 1000);
checkExpired();
rebuildWgConfig();
rebuildXrayConfig();

app.listen(3000, () => console.log('VPN API running on :3000'));