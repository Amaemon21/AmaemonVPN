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

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email               TEXT UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    full_name           TEXT NOT NULL,
    inn                 TEXT,
    client_name         TEXT UNIQUE,
    config_path         TEXT,
    download_token      TEXT UNIQUE,
    subscription_ends   INTEGER,
    created_at          INTEGER DEFAULT (unixepoch())
  )
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

// ── Восстановить peer ──
function restorePeer(user) {
  try {
    const pubKey = fs.readFileSync(
      `/etc/amnezia/amneziawg/clients/${user.client_name}/public.key`, 'utf8'
    ).trim();
    const clientConf = fs.readFileSync(
      `/etc/amnezia/amneziawg/clients/${user.client_name}/${user.client_name}.conf`, 'utf8'
    );
    const ipMatch = clientConf.match(/Address\s*=\s*(10\.8\.0\.\d+)/);
    const ip = ipMatch ? ipMatch[1] : null;
    if (ip) {
      execSync(`sudo awg set awg0 peer ${pubKey} allowed-ips ${ip}/32`);
      console.log(`Restored peer ${user.client_name} with IP ${ip}`);
    }
  } catch(e) {
    console.error('Restore peer error:', e.message);
  }
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
  const client_name = 'u' + Date.now();
  const download_token = crypto.randomBytes(32).toString('hex');
  const subscription_ends = Math.floor(Date.now() / 1000) + SUBSCRIPTION_SECONDS;

  try {
    execSync(`sudo ${SCRIPT} ${client_name}`, { timeout: 15000 });
  } catch(e) {
    console.error('Script error:', e.message);
    return res.status(500).json({ error: 'Ошибка создания конфига VPN' });
  }

  const config_path = `/etc/amnezia/amneziawg/clients/${client_name}/${client_name}.conf`;
  if (!fs.existsSync(config_path))
    return res.status(500).json({ error: 'Конфиг не создан' });

  db.prepare(`
    INSERT INTO users (email, password_hash, full_name, client_name, config_path, download_token, subscription_ends)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(email, password_hash, full_name, client_name, config_path, download_token, subscription_ends);

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
    SELECT id, email, full_name, inn, download_token, subscription_ends, created_at
    FROM users WHERE id = ?
  `).get(req.user.id);
  res.json(user);
});

// ── Скачать конфиг ──
app.get('/download/:token', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE download_token = ?').get(req.params.token);
  if (!user) return res.status(404).send('Not found');
  if (!fs.existsSync(user.config_path)) return res.status(404).send('Config not found');
  res.setHeader('Content-Disposition', 'attachment; filename="amaemonvpn.conf"');
  res.setHeader('Content-Type', 'text/plain');
  res.sendFile(user.config_path);
});

// ── Админ: все пользователи ──
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare(`
    SELECT id, email, full_name, inn, subscription_ends, created_at
    FROM users ORDER BY created_at DESC
  `).all();
  res.json(users);
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
  if (user.subscription_ends < now) restorePeer(user);

  res.json({ success: true, subscription_ends: new_ends });
});

// ── Админ: удалить пользователя ──
app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    const pubKey = fs.readFileSync(
      `/etc/amnezia/amneziawg/clients/${user.client_name}/public.key`, 'utf8'
    ).trim();
    execSync(`sudo awg set awg0 peer ${pubKey} remove`);
  } catch(e) {}

  try {
    execSync(`sudo rm -rf /etc/amnezia/amneziawg/clients/${user.client_name}`);
  } catch(e) {}

  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  res.json({ success: true });
});

// ── Создать платёж ──
app.post('/api/payment/create', auth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    const payment = await yooRequest('POST', 'payments', {
      amount: { value: '200.00', currency: 'RUB' },
      confirmation: { type: 'redirect', return_url: `${SITE_URL}/cabinet` },
      capture: true,
      description: `Подписка AmaemonVPN 30 дней — ${user.email}`,
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
    db.prepare('UPDATE users SET subscription_ends = ? WHERE id = ?').run(new_ends, user.id);
    if (user.subscription_ends < now) restorePeer(user);

    console.log(`Payment succeeded for ${user.email}, ends: ${new_ends}`);
  }
  res.sendStatus(200);
});

// ── Проверка истекших подписок ──
function checkExpired() {
  const now = Math.floor(Date.now() / 1000);
  const expired = db.prepare(
    'SELECT client_name FROM users WHERE subscription_ends < ? AND client_name IS NOT NULL'
  ).all(now);
  expired.forEach(u => {
    try {
      const pubKey = fs.readFileSync(
        `/etc/amnezia/amneziawg/clients/${u.client_name}/public.key`, 'utf8'
      ).trim();
      execSync(`sudo awg set awg0 peer ${pubKey} remove`);
      console.log(`Removed peer ${u.client_name}`);
    } catch(e) {
      console.error('Remove peer error:', u.client_name, e.message);
    }
  });
}

setInterval(checkExpired, 5 * 60 * 1000);
checkExpired();

app.listen(3000, () => console.log('AmaemonVPN API running on :3000'));