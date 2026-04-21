const express = require('express');
const db = require('../db');
const auth = require('../middleware/auth');
const { createPayment, getPaymentStatus, verifyWebhook } = require('../services/yookassa');
const { generateConfigForUser } = require('../services/vpn');

const router = express.Router();

// POST /api/payment/create — create SBP payment
router.post('/create', auth, async (req, res) => {
  const userId = req.userId;
  const amount = process.env.SUBSCRIPTION_PRICE || 150;

  try {
    // Create payment record
    const paymentRecord = db.prepare(`
      INSERT INTO payments (user_id, amount, status)
      VALUES (?, ?, 'pending')
    `).run(userId, amount);

    const orderId = paymentRecord.lastInsertRowid;

    // Create YooKassa payment
    const payment = await createPayment({
      amount,
      description: `AmaemonVPN — подписка на 30 дней`,
      userId,
      orderId,
    });

    // Save YooKassa ID and URL
    db.prepare(`
      UPDATE payments SET yookassa_id = ?, payment_url = ? WHERE id = ?
    `).run(payment.id, payment.confirmationUrl, orderId);

    res.json({
      paymentUrl: payment.confirmationUrl,
      paymentId: payment.id,
    });
  } catch (e) {
    console.error('Payment create error:', e);
    res.status(500).json({ error: 'Ошибка создания платежа' });
  }
});

// GET /api/payment/status — check payment status manually
router.get('/status', auth, async (req, res) => {
  const userId = req.userId;

  const payment = db.prepare(`
    SELECT * FROM payments WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
  `).get(userId);

  if (!payment) return res.json({ status: 'none' });

  // If pending — check with YooKassa
  if (payment.status === 'pending' && payment.yookassa_id) {
    try {
      const status = await getPaymentStatus(payment.yookassa_id);

      if (status === 'succeeded') {
        await activateSubscription(userId, payment.id);
      } else if (status === 'cancelled') {
        db.prepare(`UPDATE payments SET status = 'cancelled' WHERE id = ?`).run(payment.id);
      }
    } catch (e) {
      console.error('Status check error:', e);
    }
  }

  const updated = db.prepare(`SELECT * FROM payments WHERE id = ?`).get(payment.id);
  res.json({ status: updated.status });
});

// POST /api/payment/webhook — YooKassa webhook
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  // Always respond 200 first to avoid retries
  res.sendStatus(200);

  try {
    const event = JSON.parse(req.body.toString());

    if (event.event !== 'payment.succeeded') return;

    const yookassaId = event.object?.id;
    const userId = parseInt(event.object?.metadata?.user_id);

    if (!yookassaId || !userId) return;

    const payment = db.prepare(`SELECT * FROM payments WHERE yookassa_id = ?`).get(yookassaId);
    if (!payment || payment.status === 'succeeded') return;

    await activateSubscription(userId, payment.id);
  } catch (e) {
    console.error('Webhook error:', e);
  }
});

// Activate subscription + generate config
async function activateSubscription(userId, paymentId) {
  const days = parseInt(process.env.SUBSCRIPTION_DAYS) || 30;
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + days);

  // Update payment
  db.prepare(`
    UPDATE payments SET status = 'succeeded', updated_at = datetime('now') WHERE id = ?
  `).run(paymentId);

  // Activate or extend subscription
  const sub = db.prepare(`SELECT * FROM subscriptions WHERE user_id = ?`).get(userId);

  if (sub) {
    // If already active — extend from current expiry
    const baseDate = sub.status === 'active' && new Date(sub.expires_at) > new Date()
      ? new Date(sub.expires_at)
      : new Date();

    baseDate.setDate(baseDate.getDate() + days);

    db.prepare(`
      UPDATE subscriptions
      SET status = 'active', expires_at = ?, updated_at = datetime('now')
      WHERE user_id = ?
    `).run(baseDate.toISOString(), userId);
  } else {
    db.prepare(`
      INSERT INTO subscriptions (user_id, status, expires_at)
      VALUES (?, 'active', ?)
    `).run(userId, expiresAt.toISOString());
  }

  // Generate VPN config
  generateConfigForUser(userId);

  console.log(`✓ Subscription activated for user ${userId}`);
}

module.exports = router;
