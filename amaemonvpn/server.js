require('dotenv').config();
const express = require('express');
const path = require('path');
const cron = require('node-cron');
const db = require('./db');

const app = express();

// ─── Middleware ───────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// CORS for dev
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ─── Routes ──────────────────────────────────────────
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/payment', require('./routes/payment'));
app.use('/api/user',    require('./routes/user'));

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

// SPA fallback — serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Cron: expire subscriptions daily ────────────────
cron.schedule('0 3 * * *', () => {
  const result = db.prepare(`
    UPDATE subscriptions
    SET status = 'expired', updated_at = datetime('now')
    WHERE status = 'active' AND expires_at < datetime('now')
  `).run();

  if (result.changes > 0) {
    console.log(`[cron] Expired ${result.changes} subscriptions`);
  }
});

// ─── Start ────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AmaemonVPN backend running on port ${PORT}`);
});
