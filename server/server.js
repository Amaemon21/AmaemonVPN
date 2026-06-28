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

// ── Константы ──
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ADMIN_EMAIL = 'toitol@mail.ru';
const DB_PATH = '/var/www/amaemonvpn/server/vpn.db';
const SITE_URL = 'https://amaemonvpn.ru';
const MAX_DEVICES = 4;
const PRICES = { 1: 150, 2: 200, 3: 250, 4: 300 }; // RUB per month per device count
const REFERRAL_BONUS_RUB = 50; // both referrer and referred get 50 ₽

// ── Тарифы по периодам ──
const PERIODS = {
  1:  { months: 1,  discount: 0,    label: '1 месяц'    },
  3:  { months: 3,  discount: 0.05, label: '3 месяца'   },
  6:  { months: 6,  discount: 0.10, label: '6 месяцев'  },
  12: { months: 12, discount: 0.15, label: '12 месяцев' },
};

function calcPrice(deviceCount, months) {
  const baseMonthly = PRICES[Math.max(deviceCount, 1)] || PRICES[1];
  const period = PERIODS[months] || PERIODS[1];
  return Math.round(baseMonthly * period.months * (1 - period.discount));
}

function dailyRate(deviceCount) {
  return (PRICES[Math.min(Math.max(deviceCount, 1), MAX_DEVICES)] || PRICES[1]) / 30;
}

// ── AmneziaWG параметры ──
const SCRIPT = '/etc/amnezia/amneziawg/add_client.sh';
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

// ── База данных ──
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    email             TEXT UNIQUE NOT NULL,
    password_hash     TEXT NOT NULL,
    full_name         TEXT NOT NULL,
    subscription_ends INTEGER DEFAULT 0,
    balance           REAL DEFAULT 0,
    last_deducted_at  INTEGER DEFAULT 0,
    max_devices       INTEGER DEFAULT 0,
    referral_code     TEXT UNIQUE,
    referred_by       INTEGER DEFAULT NULL,
    referral_rewarded INTEGER DEFAULT 0,
    created_at        INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    name           TEXT NOT NULL,
    protocol       TEXT NOT NULL DEFAULT 'amnezia',
    client_name    TEXT UNIQUE,
    config_path    TEXT,
    download_token TEXT UNIQUE NOT NULL,
    paused         INTEGER DEFAULT 0,
    created_at     INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS processed_payments (
    payment_id   TEXT PRIMARY KEY,
    processed_at INTEGER DEFAULT (unixepoch())
  );
`);

// Schema migrations for existing installs
try { db.exec('ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN last_deducted_at INTEGER DEFAULT 0'); } catch {}

// Data migration: convert subscription_ends → balance for existing users
{
  const migNow = Math.floor(Date.now() / 1000);
  db.prepare(`
    UPDATE users
    SET balance          = ROUND((subscription_ends - ?) / 86400.0 * ? / 30.0, 2),
        last_deducted_at = ?
    WHERE subscription_ends > ? AND (balance IS NULL OR balance = 0)
  `).run(migNow, PRICES[1], migNow, migNow);
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

// ════════════════════════════════
// AMNEZIAWG (оба протокола используют один скрипт)
// ════════════════════════════════

function rebuildWgConfig() {
  try {
    const activeDevices = db.prepare(`
      SELECT d.client_name, d.config_path FROM devices d
      JOIN users u ON u.id = d.user_id
      WHERE u.balance > 0 AND d.paused = 0
    `).all();

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

function activateDevice(device) { addWgPeer(device.client_name, device.config_path); }
function deactivateDevice(device) { removeWgPeer(device.client_name); }

// ── ЮКасса ──
function yooRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const authHeader = Buffer.from(
      `${process.env.YOOKASSA_SHOP_ID}:${process.env.YOOKASSA_SECRET_KEY}`
    ).toString('base64');
    const headers = {
      'Authorization': `Basic ${authHeader}`,
      'Idempotence-Key': crypto.randomBytes(16).toString('hex'),
    };
    if (data) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    const options = { hostname: 'api.yookassa.ru', path: `/v3/${path}`, method, headers };
    const req = https.request(options, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => resolve(JSON.parse(d)));
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ── Регистрация ──
app.post('/api/register', async (req, res) => {
  const { email, password, full_name, ref } = req.body;
  if (!email || !password || !full_name)
    return res.status(400).json({ error: 'Заполните все поля' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Некорректный email' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return res.status(400).json({ error: 'Email уже зарегистрирован' });

  const password_hash = await bcrypt.hash(password, 10);
  const referral_code = crypto.randomBytes(5).toString('hex');
  const freeBalance = PRICES[1] / 30 / 24 * 3; // 3 часа бесплатно
  const now = Math.floor(Date.now() / 1000);

  let referred_by = null;
  if (ref) {
    const referrer = db.prepare('SELECT id FROM users WHERE referral_code = ?').get(ref);
    if (referrer) referred_by = referrer.id;
  }

  db.prepare(`
    INSERT INTO users (email, password_hash, full_name, balance, last_deducted_at, referral_code, referred_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(email, password_hash, full_name, freeBalance, now, referral_code, referred_by);

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
    SELECT id, email, full_name, balance, max_devices, referral_code, created_at
    FROM users WHERE id = ?
  `).get(req.user.id);
  const devices = db.prepare(
    'SELECT id, name, protocol, download_token, paused, created_at FROM devices WHERE user_id = ?'
  ).all(req.user.id);
  const effectiveCount = Math.max(devices.length, user.max_devices || 0);
  const basePrice = PRICES[effectiveCount] || PRICES[1];
  const referral_count = db.prepare(
    'SELECT COUNT(*) as cnt FROM users WHERE referred_by = ?'
  ).get(req.user.id).cnt;
  const referral_paid = db.prepare(
    'SELECT COUNT(*) as cnt FROM users WHERE referred_by = ? AND referral_rewarded = 1'
  ).get(req.user.id).cnt;

  const period_prices = {};
  Object.keys(PERIODS).forEach(m => {
    period_prices[m] = calcPrice(effectiveCount, parseInt(m));
  });

  const daily = dailyRate(effectiveCount);

  res.json({
    ...user,
    devices,
    device_count: devices.length,
    price: basePrice,
    period_prices,
    referral_count,
    referral_paid,
    daily_rate: parseFloat(daily.toFixed(2)),
    days_remaining: daily > 0 ? Math.floor(user.balance / daily) : 0,
  });
});

// ── Устройства: добавить ──
app.post('/api/devices', auth, async (req, res) => {
  const { name, protocol } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Введите название устройства' });
  if (!['amnezia', 'amnezia2'].includes(protocol))
    return res.status(400).json({ error: 'Неверный протокол' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  if (deviceCount >= MAX_DEVICES)
    return res.status(400).json({ error: `Максимум ${MAX_DEVICES} устройства` });

  const download_token = crypto.randomBytes(32).toString('hex');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const isActive = user.balance > 0;
  const paused = isActive ? 0 : 1;

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
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, name.trim(), protocol, client_name, config_path, download_token, paused);

  if (isActive) addWgPeer(client_name, config_path);

  const newCount = deviceCount + 1;
  db.prepare('UPDATE users SET max_devices = MAX(max_devices, ?) WHERE id = ?').run(newCount, req.user.id);

  res.json({
    success: true,
    device: { id: result.lastInsertRowid, name: name.trim(), protocol, download_token, paused },
    device_count: newCount,
    price: PRICES[newCount] || PRICES[MAX_DEVICES],
  });
});

// ── Устройства: удалить ──
app.delete('/api/devices/:id', auth, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!device) return res.status(404).json({ error: 'Устройство не найдено' });

  deactivateDevice(device);
  try { execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${device.client_name}`); } catch {}

  db.prepare('DELETE FROM devices WHERE id = ?').run(device.id);
  const newCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  res.json({ success: true, device_count: newCount, price: PRICES[newCount] || PRICES[1] });
});

// ── Скачать конфиг ──
app.get('/download/:token', (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE download_token = ?').get(req.params.token);
  if (!device) return res.status(404).send('Not found');
  if (!fs.existsSync(device.config_path)) return res.status(404).send('Config not found');

  const safeName = device.name.replace(/[^a-zA-Z0-9]/g, '_');

  if (device.protocol === 'amnezia2') {
    let conf = fs.readFileSync(device.config_path, 'utf8');
    conf = conf.replace(/Endpoint\s*=\s*[\d.]+:\d+/, 'Endpoint = 81.26.188.164:51820');
    res.setHeader('Content-Disposition', `attachment; filename="amaemonvpn_v2_${safeName}.conf"`);
    res.setHeader('Content-Type', 'text/plain');
    res.send(conf);
  } else {
    res.setHeader('Content-Disposition', `attachment; filename="amaemonvpn_${safeName}.conf"`);
    res.setHeader('Content-Type', 'text/plain');
    res.sendFile(device.config_path);
  }
});

// ── Создать платёж ──
app.post('/api/payment/create', auth, async (req, res) => {
  const { months } = req.body;
  const period = PERIODS[months] || PERIODS[1];

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const deviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(req.user.id).cnt;
  const price = calcPrice(deviceCount, period.months);

  try {
    const payment = await yooRequest('POST', 'payments', {
      amount: { value: price.toFixed(2), currency: 'RUB' },
      confirmation: { type: 'redirect', return_url: `${SITE_URL}/cabinet` },
      capture: true,
      description: `Amaemon ${period.label}, ${Math.max(deviceCount, 1)} устр. — ${user.email}`,
      metadata: { user_id: String(user.id) },
    });
    res.json({ confirmation_url: payment.confirmation.confirmation_url });
  } catch(e) {
    res.status(500).json({ error: 'Ошибка создания платежа' });
  }
});

// ── Webhook от ЮКассы ──
app.post('/api/payment/webhook', async (req, res) => {
  res.sendStatus(200);

  const paymentId = req.body?.object?.id;
  if (req.body?.event !== 'payment.succeeded' || !paymentId) return;

  const inserted = db.prepare(
    'INSERT OR IGNORE INTO processed_payments (payment_id) VALUES (?)'
  ).run(paymentId);
  if (inserted.changes === 0) return;

  let payment;
  try {
    payment = await yooRequest('GET', `payments/${paymentId}`, null);
  } catch(e) {
    console.error('YooKassa verify error:', e.message);
    return;
  }

  if (payment.status !== 'succeeded') return;

  const userId = parseInt(payment.metadata?.user_id);
  if (!userId) return;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return;

  const paidAmount = parseFloat(payment.amount.value);
  const wasEmpty = user.balance <= 0;

  db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(paidAmount, userId);

  const currentDeviceCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(userId).cnt;
  db.prepare('UPDATE users SET max_devices = ? WHERE id = ?').run(currentDeviceCount, userId);

  if (wasEmpty) {
    db.prepare('UPDATE devices SET paused = 0 WHERE user_id = ?').run(userId);
    const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(userId);
    devices.forEach(d => activateDevice(d));
  }

  // Реферальный бонус: +50 ₽ обоим при первой оплате приглашённого
  if (user.referred_by && !user.referral_rewarded) {
    const referrer = db.prepare('SELECT * FROM users WHERE id = ?').get(user.referred_by);
    if (referrer) {
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(REFERRAL_BONUS_RUB, referrer.id);
      db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(REFERRAL_BONUS_RUB, userId);
      db.prepare('UPDATE users SET referral_rewarded = 1 WHERE id = ?').run(userId);
      console.log(`Referral bonus +${REFERRAL_BONUS_RUB}₽ to ${referrer.email} and ${user.email}`);
    }
  }

  console.log(`Payment +${paidAmount}₽ for ${user.email}`);
});

// ── Админ: все пользователи ──
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(
    'SELECT id, email, full_name, balance, created_at FROM users ORDER BY created_at DESC'
  ).all();
  const result = users.map(u => {
    const devices = db.prepare(
      'SELECT id, name, protocol, client_name, config_path, download_token, paused, created_at FROM devices WHERE user_id = ?'
    ).all(u.id);
    const devicesWithInfo = devices.map(d => {
      let vpn_ip = null;
      if (d.config_path) {
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

// ── Админ: пополнить/списать баланс ──
app.post('/api/admin/extend/:id', auth, adminOnly, (req, res) => {
  const { rubles } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const amount = parseFloat(rubles) || 0;
  const wasEmpty = user.balance <= 0;
  const newBalance = Math.max((user.balance || 0) + amount, 0);

  db.prepare('UPDATE users SET balance = ? WHERE id = ?').run(newBalance, user.id);

  if (amount > 0 && wasEmpty) {
    db.prepare('UPDATE devices SET paused = 0 WHERE user_id = ?').run(user.id);
    const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(user.id);
    devices.forEach(d => activateDevice(d));
    const currentCount = db.prepare('SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?').get(user.id).cnt;
    db.prepare('UPDATE users SET max_devices = ? WHERE id = ?').run(currentCount, user.id);
  } else if (amount < 0 && newBalance <= 0) {
    const devices = db.prepare('SELECT * FROM devices WHERE user_id = ? AND paused = 0').all(user.id);
    devices.forEach(d => deactivateDevice(d));
    db.prepare('UPDATE devices SET paused = 1 WHERE user_id = ?').run(user.id);
  }

  res.json({ success: true, balance: newBalance });
});

// ── Админ: удалить устройство ──
app.delete('/api/admin/devices/:id', auth, adminOnly, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  deactivateDevice(device);
  try { execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${device.client_name}`); } catch {}
  db.prepare('DELETE FROM devices WHERE id = ?').run(device.id);
  res.json({ success: true });
});

// ── Админ: удалить пользователя ──
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const devices = db.prepare('SELECT * FROM devices WHERE user_id = ?').all(user.id);
  devices.forEach(d => {
    deactivateDevice(d);
    try { execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${d.client_name}`); } catch {}
  });
  db.prepare('DELETE FROM devices WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  res.json({ success: true });
});

// ── Статистика ──
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  try {
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
          txBytes: parseInt(txBytes) || 0,
        };
      });
    } catch {}
    res.json({ wg_peers: wgPeers });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Списание баланса (каждый час) ──
function checkBalances() {
  const now = Math.floor(Date.now() / 1000);

  // Списываем у пользователей с положительным балансом
  const activeUsers = db.prepare(`
    SELECT u.id, u.email, u.balance, u.last_deducted_at,
           COUNT(d.id) as device_count
    FROM users u
    LEFT JOIN devices d ON d.user_id = u.id AND d.paused = 0
    WHERE u.balance > 0
    GROUP BY u.id
  `).all();

  activeUsers.forEach(u => {
    const lastDeducted = u.last_deducted_at || (now - 3600);
    const hoursElapsed = Math.floor((now - lastDeducted) / 3600);
    if (hoursElapsed < 1) return;

    const deviceCount = Math.max(u.device_count, 1);
    const hourlyRate = (PRICES[Math.min(deviceCount, MAX_DEVICES)] || PRICES[1]) / 30 / 24;
    const deduction = hourlyRate * hoursElapsed;
    const newBalance = Math.max(u.balance - deduction, 0);
    const newLastDeducted = lastDeducted + hoursElapsed * 3600;

    db.prepare('UPDATE users SET balance = ?, last_deducted_at = ? WHERE id = ?')
      .run(newBalance, newLastDeducted, u.id);

    if (newBalance <= 0) {
      const devices = db.prepare('SELECT * FROM devices WHERE user_id = ? AND paused = 0').all(u.id);
      devices.forEach(d => {
        deactivateDevice(d);
        console.log(`Paused device ${d.id} for ${u.email} (balance depleted)`);
      });
      db.prepare('UPDATE devices SET paused = 1 WHERE user_id = ?').run(u.id);
    }
  });

  // Блокируем устройства у тех, у кого баланс уже был 0, но устройства ещё активны
  const depletedUsers = db.prepare(`
    SELECT u.id FROM users u
    WHERE u.balance <= 0
    AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id = u.id AND d.paused = 0)
  `).all();

  depletedUsers.forEach(u => {
    const devices = db.prepare('SELECT * FROM devices WHERE user_id = ? AND paused = 0').all(u.id);
    devices.forEach(d => deactivateDevice(d));
    db.prepare('UPDATE devices SET paused = 1 WHERE user_id = ?').run(u.id);
  });

  // Синхронизация с awg: пиры, помеченные paused=1 в БД, но всё ещё активные в awg — удалить
  try {
    const wgOutput = execSync('sudo awg show awg0 dump').toString();
    const activeInWg = new Set();
    wgOutput.split('\n').slice(1).forEach(line => {
      const parts = line.split('\t');
      if (parts.length >= 1 && parts[0].trim()) activeInWg.add(parts[0].trim());
    });

    const pausedDevices = db.prepare('SELECT * FROM devices WHERE paused = 1').all();
    pausedDevices.forEach(d => {
      try {
        const pubKey = fs.readFileSync(
          `/etc/amnezia/amneziawg/clients/${d.client_name}/public.key`, 'utf8'
        ).trim();
        if (activeInWg.has(pubKey)) {
          execSync(`sudo awg set awg0 peer ${pubKey} remove`);
          console.log(`Removed ghost peer ${d.client_name} from awg`);
        }
      } catch(e) {}
    });
  } catch(e) {
    console.error('Ghost peer cleanup error:', e.message);
  }
}

setInterval(checkBalances, 60 * 60 * 1000); // каждый час
checkBalances();
rebuildWgConfig();

app.listen(3000, () => console.log('VPN API running on :3000'));
