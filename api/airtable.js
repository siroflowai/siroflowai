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

// Format: "DD.MM.YYYY HH:MM"
function formatTimestamp(d) {
  const pad = n => String(n).padStart(2, '0');
  return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.' + d.getFullYear()
       + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
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

  const userName = session.name || session.email || 'Zarządca';
  const action = req.query.action;
  const airtableUrl = 'https://api.airtable.com/v0/' + baseId + '/' + tableId;

  try {
    // ====================================================================
    // LIST
    // ====================================================================
    if (action === 'list' && req.method === 'GET') {
      let allRecords = [];
      let offset = null;
      let pageCount = 0;
      const maxPages = 10;

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

    // ====================================================================
    // UPDATE — z automatycznym dopisywaniem do Historia_zmian
    // ====================================================================
    if (action === 'update' && req.method === 'POST') {
      const { id, fields, addNote } = req.body || {};
      if (!id) {
        res.status(400).json({ error: 'Brak id' });
        return;
      }

      // Whitelist pól, które można edytować z panelu
      const allowed = ['Status', 'Typ_AI', 'Priorytet_AI'];
      const cleanFields = {};
      if (fields && typeof fields === 'object') {
        for (const k of allowed) {
          if (fields[k] !== undefined) cleanFields[k] = fields[k];
        }
      }

      const hasFieldChanges = Object.keys(cleanFields).length > 0;
      const hasNewNote = typeof addNote === 'string' && addNote.trim().length > 0;

      if (!hasFieldChanges && !hasNewNote) {
        res.status(400).json({ error: 'Brak zmian do zapisania' });
        return;
      }

      // Najpierw pobierz aktualny rekord, żeby znać stare wartości i aktualną Historia_zmian
      const getRes = await fetch(airtableUrl + '/' + id, {
        headers: { 'Authorization': 'Bearer ' + airtableToken }
      });
      if (!getRes.ok) {
        const errText = await getRes.text();
        res.status(502).json({ error: 'Airtable (GET): ' + errText });
        return;
      }
      const currentData = await getRes.json();
      const currentFields = currentData.fields || {};
      const currentHistory = currentFields.Historia_zmian || '';

      // Buduj wpisy historii
      const timestamp = formatTimestamp(new Date());
      const historyEntries = [];

      if (hasFieldChanges) {
        if (cleanFields.Status !== undefined && cleanFields.Status !== currentFields.Status) {
          const from = currentFields.Status || '(brak)';
          historyEntries.push('[' + timestamp + '] Status: ' + from + ' → ' + cleanFields.Status + ' (' + userName + ')');
        }
        if (cleanFields.Typ_AI !== undefined && cleanFields.Typ_AI !== currentFields.Typ_AI) {
          const from = currentFields.Typ_AI || '(brak)';
          historyEntries.push('[' + timestamp + '] Typ: ' + from + ' → ' + cleanFields.Typ_AI + ' (' + userName + ')');
        }
        if (cleanFields.Priorytet_AI !== undefined && cleanFields.Priorytet_AI !== currentFields.Priorytet_AI) {
          const from = currentFields.Priorytet_AI || '(brak)';
          historyEntries.push('[' + timestamp + '] Priorytet: ' + from + ' → ' + cleanFields.Priorytet_AI + ' (' + userName + ')');
        }
      }

      if (hasNewNote) {
        historyEntries.push('[' + timestamp + '] Notatka: ' + addNote.trim() + ' (' + userName + ')');
      }

      // Jeśli są nowe wpisy, sklej z istniejącą historią (nowe na górze)
      if (historyEntries.length > 0) {
        const newHistoryBlock = historyEntries.join('\n');
        cleanFields.Historia_zmian = currentHistory
          ? newHistoryBlock + '\n' + currentHistory
          : newHistoryBlock;
      }

      // Zapisz do Airtable
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

    // ====================================================================
    // DELETE — twarde usunięcie z Airtable
    // ====================================================================
    if (action === 'delete' && req.method === 'POST') {
      const { id } = req.body || {};
      if (!id) {
        res.status(400).json({ error: 'Brak id' });
        return;
      }

      const atRes = await fetch(airtableUrl + '/' + id, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + airtableToken }
      });

      if (!atRes.ok) {
        const errText = await atRes.text();
        res.status(502).json({ error: 'Airtable: ' + errText });
        return;
      }
      const data = await atRes.json();
      res.status(200).json({ deleted: true, id: data.id || id });
      return;
    }

    res.status(400).json({ error: 'Nieprawidłowa akcja' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};
