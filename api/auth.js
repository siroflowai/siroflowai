// /api/auth.js — Vercel serverless function
// Autentykacja email + hasło, zwraca token sesyjny (signed)

const crypto = require('crypto');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const { email, password } = req.body || {};
  if (!email || !password) {
    res.status(400).json({ error: 'Brak email lub hasła' });
    return;
  }

  // Użytkownicy z env vars
  // Format: SF_USERS = "email1:hash1:Imie1,email2:hash2:Imie2"
  // Hash = SHA-256 hasła
  const usersStr = process.env.SF_USERS || '';
  const users = usersStr.split(',').map(function(u) {
    const parts = u.split(':');
    return { email: parts[0], hash: parts[1], name: parts[2] || parts[0] };
  });

  const emailLower = String(email).trim().toLowerCase();
  const user = users.find(function(u) { return u.email.toLowerCase() === emailLower; });

  if (!user) {
    // Celowo ten sam komunikat co przy złym haśle, żeby nie ujawniać czy email istnieje
    res.status(401).json({ error: 'Nieprawidłowy email lub hasło' });
    return;
  }

  const pwHash = crypto.createHash('sha256').update(password).digest('hex');
  if (pwHash !== user.hash) {
    res.status(401).json({ error: 'Nieprawidłowy email lub hasło' });
    return;
  }

  // Generate signed token
  const secret = process.env.SF_SECRET;
  if (!secret) {
    res.status(500).json({ error: 'Serwer niepoprawnie skonfigurowany' });
    return;
  }

  const payload = {
    email: user.email,
    iat: Date.now(),
    exp: Date.now() + (12 * 60 * 60 * 1000) // 12h
  };
  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', secret).update(payloadStr).digest('hex');
  const token = payloadStr + '.' + sig;

  res.status(200).json({ token: token, name: user.name });
};
