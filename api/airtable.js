// /api/airtable.js — Vercel serverless function
// Proxy do Airtable API, weryfikuje token sesyjny
// Token Airtable pozostaje TYLKO w env vars, nigdy nie trafia do frontu

const crypto = require('crypto');

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadStr, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', secret).update(payloadStr).digest('hex');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadStr, 'base64').toString('utf8'));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

module.exports = async function handler(req, res) {
  const secret = process.env.SF_SECRET;
  const airtableToken = process.env.AIRTABLE_TOKEN;
  const baseId = process.env.AIRTABLE_BASE_ID;
  const tableId = process.env.AIRTABLE_TABLE_ID;

  if (!secret || !airtableToken || !baseId || !tableId) {
    res.status(500).json({ error: 'Serwer niepoprawnie skonfigurowany' });
    return;
  }

  // Verify session token
  const token = req.headers['x-auth-token'];
  const session = verifyToken(token, secret);
  if (!session) {
    res.status(401).json({ error: 'Sesja wygasła, zaloguj się ponownie' });
    return;
  }

  const action = req.query.action;
  const airtableUrl = 'https://api.airtable.com/v0/' + baseId + '/' + tableId;

  try {
    if (action === 'list' && req.method === 'GET') {
      // Fetch all records, sorted by creation date desc
      // Airtable max 100 per page, paginate if needed
      let allRecords = [];
      let offset = null;
      let pageCount = 0;
      const maxPages = 10; // Safety limit - max 1000 rekordów

      do {
        const url = new URL(airtableUrl);
        url.searchParams.set('pageSize', '100');
        if (offset) url.searchParams.set('offset', offset);

        const atRes = await fetch(url.toString(), {
          headers: { 'Authorization': 'Bearer ' + airtableToken }
        });
        if (!atRes.ok) {
          const errText = await atRes.text();
          res.status(502).json({ error: 'Airtable: ' + errText });
          return;
        }
        const data = await atRes.json();
        allRecords = allRecords.concat(data.records || []);
        offset = data.offset || null;
        pageCount++;
      } while (offset && pageCount < maxPages);

      res.status(200).json({ records: allRecords });
      return;
    }

    if (action === 'update' && req.method === 'POST') {
      const { id, fields } = req.body || {};
      if (!id || !fields) {
        res.status(400).json({ error: 'Brak id lub fields' });
        return;
      }
      // Whitelist pól, które można edytować z panelu
      const allowed = ['Status', 'Notatki'];
      const cleanFields = {};
      for (const k of allowed) {
        if (fields[k] !== undefined) cleanFields[k] = fields[k];
      }

      const atRes = await fetch(airtableUrl + '/' + id, {
        method: 'PATCH',
        headers: {
          'Authorization': 'Bearer ' + airtableToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ fields: cleanFields })
      });

      if (!atRes.ok) {
        const errText = await atRes.text();
        res.status(502).json({ error: 'Airtable: ' + errText });
        return;
      }
      const data = await atRes.json();
      res.status(200).json({ record: data });
      return;
    }

    res.status(400).json({ error: 'Nieprawidłowa akcja' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
