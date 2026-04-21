const express = require('express');
const QRCode = require('qrcode');
const db = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

// GET /api/user/me — profile + subscription info
router.get('/me', auth, (req, res) => {
  const userId = req.userId;

  const user = db.prepare(`SELECT id, email, created_at FROM users WHERE id = ?`).get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const sub = db.prepare(`SELECT * FROM subscriptions WHERE user_id = ?`).get(userId);
  const config = db.prepare(`SELECT peer_ip, public_key, created_at FROM vpn_configs WHERE user_id = ?`).get(userId);

  const isActive = sub?.status === 'active' && new Date(sub.expires_at) > new Date();

  res.json({
    email: user.email,
    createdAt: user.created_at,
    subscription: {
      status: isActive ? 'active' : (sub?.status || 'inactive'),
      expiresAt: sub?.expires_at || null,
    },
    hasConfig: !!config,
    config: config ? {
      peerIP: config.peer_ip,
      createdAt: config.created_at,
    } : null,
  });
});

// GET /api/user/config — download .conf file
router.get('/config', auth, (req, res) => {
  const userId = req.userId;

  // Check subscription
  const sub = db.prepare(`SELECT * FROM subscriptions WHERE user_id = ?`).get(userId);
  const isActive = sub?.status === 'active' && new Date(sub.expires_at) > new Date();

  if (!isActive) {
    return res.status(403).json({ error: 'Подписка неактивна. Оплатите доступ.' });
  }

  const config = db.prepare(`SELECT * FROM vpn_configs WHERE user_id = ?`).get(userId);
  if (!config) {
    return res.status(404).json({ error: 'Конфиг не найден. Обратитесь в поддержку.' });
  }

  const user = db.prepare(`SELECT email FROM users WHERE id = ?`).get(userId);
  const filename = `amaemonvpn_${user.email.split('@')[0]}.conf`;

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(config.config_text);
});

// GET /api/user/qr — get QR code as PNG
router.get('/qr', auth, async (req, res) => {
  const userId = req.userId;

  const sub = db.prepare(`SELECT * FROM subscriptions WHERE user_id = ?`).get(userId);
  const isActive = sub?.status === 'active' && new Date(sub.expires_at) > new Date();

  if (!isActive) {
    return res.status(403).json({ error: 'Подписка неактивна' });
  }

  const config = db.prepare(`SELECT config_text FROM vpn_configs WHERE user_id = ?`).get(userId);
  if (!config) {
    return res.status(404).json({ error: 'Конфиг не найден' });
  }

  try {
    const qrBuffer = await QRCode.toBuffer(config.config_text, {
      errorCorrectionLevel: 'L',
      width: 400,
      margin: 2,
    });

    res.setHeader('Content-Type', 'image/png');
    res.send(qrBuffer);
  } catch (e) {
    res.status(500).json({ error: 'Ошибка генерации QR' });
  }
});

module.exports = router;
