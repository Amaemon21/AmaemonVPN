const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const https = require('https');

require('dotenv').config();

const app = express();
app.use(express.json());

const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ADMIN_EMAIL = 'toitol@mail.ru';
const SUBSCRIPTION_SECONDS = 1 * 60 * 60;
const DB_PATH = '/var/www/amaemonvpn/server/vpn.db';
const SCRIPT = '/etc/amnezia/amneziawg/add_client.sh';
const SITE_URL = 'https://amaemonvpn.ru';
const MAX_DEVICES = 4;

const PRICES = { 1: 200, 2: 350, 3: 500, 4: 650 };

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT UNIQUE NOT NULL,
    password_hash     TEXT NOT NULL,
    full_name         TEXT NOT NULL,
    inn               TEXT,
    client_name       TEXT UNIQUE,
    config_path       TEXT,
    download_token    TEXT UNIQUE,
    subscription_ends INTEGER,
    created_at        INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    name           TEXT NOT NULL DEFAULT 'Устройство',
    client_name    TEXT UNIQUE NOT NULL,
    config_path    TEXT NOT NULL,
    download_token TEXT UNIQUE NOT NULL,
    created_at     INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Миграция: переносим существующие устройства из users в devices
try {
  const usersWithDevices = db.prepare(
    'SELECT id, client_name, config_path, download_token FROM users WHERE client_name IS NOT NULL'
  ).all();
  const insertDevice = db.prepare(
    'INSERT OR IGNORE INTO devices (user_id, name, client_name, config_path, download_token) VALUES (?, ?, ?, ?, ?)'
  );
  usersWithDevices.forEach(u => {
    insertDevice.run(u.id, 'Устройство 1', u.client_name, u.config_path, u.download_token);
  });
  if (usersWithDevices.length > 0) console.log(`Migrated ${usersWithDevices.length} devices`);
} catch(e) {
  console.error('Migration error:', e.message);
}

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

// ── Сохранить конфиг WireGuard ──
function saveWgConfig() {
  try {
    const stripped = execSync('sudo awg-quick strip awg0').toString();
    fs.writeFileSync('/tmp/awg0_tmp.conf', stripped);
    execSync('sudo tee /etc/amnezia/amneziawg/awg0.conf < /tmp/awg0_tmp.conf > /dev/null');
    fs.unlinkSync('/tmp/awg0_tmp.conf');
    console.log('WireGuard config saved');
  } catch(e) {
    console.error('Save config error:', e.message);
  }
}

// ── Создать VPN конфиг для устройства ──
function createVpnConfig(clientName) {
  execSync(`sudo ${SCRIPT} ${clientName}`, { timeout: 15000 });
  const configPath = `/etc/amnezia/amneziawg/clients/${clientName}/${clientName}.conf`;
  if (!fs.existsSync(configPath)) throw new Error('Конфиг не создан');
  saveWgConfig();
  return configPath;
}

// ── Удалить VPN конфиг устройства ──
function removeVpnConfig(clientName) {
  try {
    const pubKey = fs.readFileSync(
      `/etc/amnezia/amneziawg/clients/${clientName}/public.key`, 'utf8'
    ).trim();
    execSync(`sudo awg set awg0 peer ${pubKey} remove`);
  } catch(e) {}
  try {
    execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${clientName}`);
  } catch(e) {}
}

// ── Восстановить все пиры пользователя ──
function restoreUserPeers(userId) {
  const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(userId);
  devices.forEach(d => {
    try {
      const pubKey = fs.readFileSync(
        `/etc/amnezia/amneziawg/clients/${d.client_name}/public.key`, 'utf8'
      ).trim();
      const conf = fs.readFileSync(d.config_path, 'utf8');
      const ipMatch = conf.match(/Address\s*=\s*(10\.8\.0\.\d+)/);
      const ip = ipMatch ? ipMatch[1] : null;
      if (ip) {
        execSync(`sudo awg set awg0 peer ${pubKey} allowed-ips ${ip}/32`);
        console.log(`Restored peer ${d.client_name} with IP ${ip}`);
      }
    } catch(e) {
      console.error('Restore peer error:', d.client_name, e.message);
    }
  });
  saveWgConfig();
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
    return res.status(400).json({ error: 'Заполните все обязательные поля' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Некорректный email' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return res.status(400).json({ error: 'Email уже зарегистрирован' });

  const password_hash = await bcrypt.hash(password, 10);
  const subscription_ends = Math.floor(Date.now() / 1000) + SUBSCRIPTION_SECONDS;
  const client_name = 'u' + Date.now();
  const download_token = crypto.randomBytes(32).toString('hex');

  let config_path;
  try {
    config_path = createVpnConfig(client_name);
  } catch(e) {
    console.error('Script error:', e.message);
    return res.status(500).json({ error: 'Ошибка создания конфига VPN' });
  }

  const user = db.prepare(`
    INSERT INTO users (email, password_hash, full_name, client_name, config_path, download_token, subscription_ends)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(email, password_hash, full_name, client_name, config_path, download_token, subscription_ends);

  db.prepare(`
    INSERT INTO devices (user_id, name, client_name, config_path, download_token)
    VALUES (?, ?, ?, ?, ?)
  `).run(user.lastInsertRowid, 'Устройство 1', client_name, config_path, download_token);

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
  const user = db.prepare(`
    SELECT id, email, full_name, inn, subscription_ends, created_at
    FROM users WHERE id = ?
  `).get(req.user.id);
  const devices = db.prepare('SELECT id, name, download_token, created_at FROM devices WHERE user_id = ?').all(req.user.id);
  const deviceCount = devices.length;
  const price = PRICES[deviceCount] || 200;
  res.json({ ...user, devices, device_count: deviceCount, price });
});

// ── Устройства: добавить ──
app.post('/api/devices', auth, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Введите название устройства' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  if (deviceCount >= MAX_DEVICES)
    return res.status(400).json({ error: `Максимум ${MAX_DEVICES} устройства` });

  const client_name = 'u' + Date.now();
  const download_token = crypto.randomBytes(32).toString('hex');

  let config_path;
  try {
    config_path = createVpnConfig(client_name);
  } catch(e) {
    console.error('Script error:', e.message);
    return res.status(500).json({ error: 'Ошибка создания конфига VPN' });
  }

  const device = db.prepare(`
    INSERT INTO devices (user_id, name, client_name, config_path, download_token)
    VALUES (?, ?, ?, ?, ?)
  `).run(req.user.id, name, client_name, config_path, download_token);

  const newCount = deviceCount + 1;
  res.json({
    success: true,
    device: { id: device.lastInsertRowid, name, download_token },
    device_count: newCount,
    price: PRICES[newCount] || 650
  });
});

// ── Устройства: удалить ──
app.delete('/api/devices/:id', auth, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!device) return res.status(404).json({ error: 'Устройство не найдено' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  if (deviceCount <= 1) return res.status(400).json({ error: 'Нельзя удалить последнее устройство' });

  removeVpnConfig(device.client_name);
  db.prepare('DELETE FROM devices WHERE id = ?').run(device.id);
  saveWgConfig();

  const newCount = deviceCount - 1;
  res.json({ success: true, device_count: newCount, price: PRICES[newCount] || 200 });
});

// ── Скачать конфиг ──
app.get('/download/:token', (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE download_token = ?').get(req.params.token);
  if (!device) return res.status(404).send('Not found');
  if (!fs.existsSync(device.config_path)) return res.status(404).send('Config not found');
  const safeName = device.name.replace(/[^a-zA-Z0-9а-яА-Я]/g, '_');
  res.setHeader('Content-Disposition', `attachment; filename="amaemonvpn_${safeName}.conf"`);
  res.setHeader('Content-Type', 'text/plain');
  res.sendFile(device.config_path);
});

// ── Админ: все пользователи ──
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT id, email, full_name, inn, subscription_ends, created_at
    FROM users ORDER BY created_at DESC
  `).all();

  const result = users.map(u => {
    const devices = db.prepare('SELECT id, name, client_name, config_path, download_token, created_at FROM devices WHERE user_id = ?').all(u.id);
    const devicesWithIp = devices.map(d => {
      let vpn_ip = null;
      try {
        const conf = fs.readFileSync(d.config_path, 'utf8');
        const m = conf.match(/Address\s*=\s*(10\.8\.0\.\d+)/);
        if (m) vpn_ip = m[1];
      } catch {}
      return { ...d, vpn_ip };
    });
    return { ...u, devices: devicesWithIp };
  });

  res.json(result);
});

// ── Админ: продлить подписку ──
app.post('/api/admin/extend/:id', auth, adminOnly, (req, res) => {
  const { hours } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const now = Math.floor(Date.now() / 1000);
  const base = Math.max(user.subscription_ends || now, now);
  const new_ends = base + (hours || 720) * 3600;

  db.prepare('UPDATE users SET subscription_ends = ? WHERE id = ?').run(new_ends, user.id);
  if (user.subscription_ends < now) restoreUserPeers(user.id);

  res.json({ success: true, subscription_ends: new_ends });
});

// ── Админ: удалить пользователя ──
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(user.id);
  devices.forEach(d => removeVpnConfig(d.client_name));

  db.prepare('DELETE FROM devices WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  saveWgConfig();

  res.json({ success: true });
});

// ── Создать платёж ──
app.post('/api/payment/create', auth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  const price = PRICES[deviceCount] || 200;
  const priceStr = price.toFixed(2);

  try {
    const payment = await yooRequest('POST', 'payments', {
      amount: { value: priceStr, currency: 'RUB' },
      confirmation: { type: 'redirect', return_url: `${SITE_URL}/cabinet` },
      capture: true,
      description: `AmaemonVPN 30 дней, ${deviceCount} устр. — ${user.email}`,
      metadata: { user_id: String(user.id) }
    });
    res.json({ confirmation_url: payment.confirmation.confirmation_url });
  } catch(e) {
    console.error('Payment error:', e.message);
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
    const base = Math.max(user.subscription_ends || now, now);
    const new_ends = base + 30 * 24 * 3600;
    db.prepare('UPDATE users SET subscription_ends = ? WHERE id = ?').run(new_ends, userId);
    if (user.subscription_ends < now) restoreUserPeers(userId);

    console.log(`Payment succeeded for ${user.email}, ends: ${new_ends}`);
  }
  res.sendStatus(200);
});

// ── Статистика WireGuard ──
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  try {
    const output = execSync('sudo awg show awg0 dump').toString();
    const peers = {};
    output.split('\n').slice(1).forEach(line => {
      const parts = line.split('\t');
      if (parts.length < 8) return;
      const [pubKey, , endpoint, allowedIps, latestHandshake, rxBytes, txBytes] = parts;
      peers[pubKey] = {
        endpoint: endpoint === '(none)' ? null : endpoint,
        allowedIps,
        latestHandshake: parseInt(latestHandshake) || 0,
        rxBytes: parseInt(rxBytes) || 0,
        txBytes: parseInt(txBytes) || 0
      };
    });
    res.json(peers);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Проверка истекших подписок ──
function checkExpired() {
  const now = Math.floor(Date.now() / 1000);
  const expiredUsers = db.prepare(
    'SELECT id FROM users WHERE subscription_ends < ? AND subscription_ends IS NOT NULL'
  ).all(now);

  if (expiredUsers.length === 0) return;

  expiredUsers.forEach(u => {
    const devices = db.prepare('SELECT client_name FROM devices WHERE user_id = ?').all(u.id);
    devices.forEach(d => {
      try {
        const pubKey = fs.readFileSync(
          `/etc/amnezia/amneziawg/clients/${d.client_name}/public.key`, 'utf8'
        ).trim();
        execSync(`sudo awg set awg0 peer ${pubKey} remove`);
        console.log(`Removed peer ${d.client_name}`);
      } catch(e) {
        console.error('Remove peer error:', d.client_name, e.message);
      }
    });
  });

  saveWgConfig();
}

setInterval(checkExpired, 5 * 60 * 1000);
checkExpired();

app.listen(3000, () => console.log('AmaemonVPN API running on :3000'));