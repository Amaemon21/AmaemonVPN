const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');

const router = express.Router();

// POST /api/auth/register
router.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email и пароль обязательны' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email);
  if (existing)
    return res.status(409).json({ error: 'Email уже зарегистрирован' });

  const hashed = await bcrypt.hash(password, 10);

  const result = db.prepare(`INSERT INTO users (email, password) VALUES (?, ?)`).run(email, hashed);
  const userId = result.lastInsertRowid;

  // Create empty subscription record
  db.prepare(`INSERT INTO subscriptions (user_id) VALUES (?)`).run(userId);

  const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email });
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user)
    return res.status(401).json({ error: 'Неверный email или пароль' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.status(401).json({ error: 'Неверный email или пароль' });

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, email: user.email });
});

module.exports = router;
