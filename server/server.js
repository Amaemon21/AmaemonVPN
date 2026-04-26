const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ADMIN_EMAIL = 'toitol@mail.ru';
const SUBSCRIPTION_SECONDS = 1 * 60 * 60; // 1 час
const DB_PATH = '/opt/amaemonvpn/vpn.db';
const SCRIPT = '/etc/amnezia/amneziawg/add_client.sh';

// ── База данных ──
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

// ── Регистрация ──
app.post('/api/register', async (req, res) => {
  const { email, password, full_name, inn } = req.body;

  if (!email || !password || !full_name)
    return res.status(400).json({ error: 'Заполните все обязательные поля' });

  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return res.status(400).json({ error: 'Email уже зарегистрирован' });

  const password_hash = await bcrypt.hash(password, 10);
  const client_name = 'u' + Date.now();
  const download_token = crypto.randomBytes(32).toString('hex');
  const subscription_ends = Math.floor(Date.now() / 1000) + SUBSCRIPTION_SECONDS;

  try {
    execSync(`sudo ${SCRIPT} ${client_name}`, { timeout: 15000 });
  } catch (e) {
    console.error('Script error:', e.message);
    return res.status(500).json({ error: 'Ошибка создания конфига VPN' });
  }

  const config_path = `/etc/amnezia/amneziawg/clients/${client_name}/${client_name}.conf`;

  if (!fs.existsSync(config_path))
    return res.status(500).json({ error: 'Конфиг не создан' });

  db.prepare(`
    INSERT INTO users (email, password_hash, full_name, inn, client_name, config_path, download_token, subscription_ends)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(email, password_hash, full_name, inn || null, client_name, config_path, download_token, subscription_ends);

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
  const base = Math.max(user.subscription_ends, now);
  const new_ends = base + (hours || 720) * 3600;

  db.prepare('UPDATE users SET subscription_ends = ? WHERE id = ?').run(new_ends, user.id);

  // Восстанавливаем peer если подписка была истекшей
  if (user.subscription_ends < now) {
    try {
      const pubKey = fs.readFileSync(
        `/etc/amnezia/amneziawg/clients/${user.client_name}/public.key`, 'utf8'
      ).trim();
      const confLine = fs.readFileSync('/etc/amnezia/amneziawg/awg0.conf', 'utf8')
        .split('\n').find(l => l.includes(user.client_name));
      const ip = confLine ? confLine.match(/10\.8\.0\.\d+/)?.[0] : null;
      if (ip) {
        execSync(`sudo awg set awg0 peer ${pubKey} allowed-ips ${ip}/32`);
      }
    } catch(e) {
      console.error('Restore peer error:', e.message);
    }
  }

  res.json({ success: true, subscription_ends: new_ends });
});


function checkExpired() {
  const now = Math.floor(Date.now() / 1000);
  const expired = db.prepare("SELECT client_name FROM users WHERE subscription_ends < ? AND client_name IS NOT NULL").all(now);
  expired.forEach(u => {
    try {
      const pubKey = fs.readFileSync(`/etc/amnezia/amneziawg/clients/${u.client_name}/public.key`, "utf8").trim();
      execSync(`sudo awg set awg0 peer ${pubKey} remove`);
    } catch(e) {
      console.error("Remove peer error:", u.client_name, e.message);
    }
  });
}
// Проверка каждые 5 минут
setInterval(checkExpired, 5 * 60 * 1000);
checkExpired(); // сразу при старте

app.listen(3000, () => console.log('AmaemonVPN API running on :3000'));
