const { v4: uuidv4 } = require('uuid');

// YooKassa REST API wrapper (no SDK needed)
const YOOKASSA_URL = 'https://api.yookassa.ru/v3';

function getHeaders(idempotenceKey) {
  const auth = Buffer.from(
    `${process.env.YOOKASSA_SHOP_ID}:${process.env.YOOKASSA_SECRET_KEY}`
  ).toString('base64');

  return {
    'Authorization': `Basic ${auth}`,
    'Content-Type': 'application/json',
    'Idempotence-Key': idempotenceKey || uuidv4(),
  };
}

// Create SBP payment, returns { id, confirmationUrl }
async function createPayment({ amount, description, userId, orderId }) {
  const body = {
    amount: {
      value: String(parseFloat(amount).toFixed(2)),
      currency: 'RUB',
    },
    payment_method_data: {
      type: 'sbp',
    },
    confirmation: {
      type: 'redirect',
      return_url: `${process.env.SITE_URL}/cabinet`,
    },
    description,
    metadata: {
      user_id: String(userId),
      order_id: String(orderId),
    },
    capture: true,
  };

  const res = await fetch(`${YOOKASSA_URL}/payments`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`YooKassa error: ${err}`);
  }

  const data = await res.json();
  return {
    id: data.id,
    status: data.status,
    confirmationUrl: data.confirmation?.confirmation_url,
  };
}

// Get payment status from YooKassa
async function getPaymentStatus(paymentId) {
  const res = await fetch(`${YOOKASSA_URL}/payments/${paymentId}`, {
    headers: getHeaders(),
  });

  if (!res.ok) throw new Error('Failed to get payment status');

  const data = await res.json();
  return data.status; // pending | waiting_for_capture | succeeded | cancelled
}

// Verify webhook signature (optional but recommended)
function verifyWebhook(body, signature) {
  // YooKassa sends IP from their range — basic check
  // For production add IP whitelist: 185.71.76.0/27, 185.71.77.0/27, 77.75.153.0/25
  return true;
}

module.exports = { createPayment, getPaymentStatus, verifyWebhook };
