// Cloudflare Worker с прямыми HTTP запросами к Google Sheets API
// Работает БЕЗ тяжелых Node.js библиотек

// CORS заголовки
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function errorResponse(message, status = 500) {
  console.error(`Error ${status}: ${message}`);
  return jsonResponse({ error: message, success: false }, status);
}

// Получить Google OAuth токен
async function getAccessToken(creds) {
  const jwt = await createJWT(creds);
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  const data = await response.json();
  return data.access_token;
}

// Создать JWT для Google
async function createJWT(creds) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: creds.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const encodedClaim = btoa(JSON.stringify(claim)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const signatureInput = `${encodedHeader}.${encodedClaim}`;

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    str2ab(creds.private_key.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '')),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(signatureInput)
  );

  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  return `${signatureInput}.${encodedSignature}`;
}

function str2ab(str) {
  const binaryString = atob(str);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Получить данные из Google Sheets
async function getSheetData(sheetId, sheetName, accessToken) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${sheetName}!A:Z`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json();
  
  if (!data.values || data.values.length === 0) {
    return [];
  }

  const headers = data.values[0];
  const rows = data.values.slice(1);

  return rows.map(row => {
    const obj = {};
    headers.forEach((header, index) => {
      obj[header] = row[index] || '';
    });
    return obj;
  });
}

// Добавить строку в Google Sheets
async function appendSheetRow(sheetId, sheetName, values, accessToken) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${sheetName}!A:Z:append?valueInputOption=RAW`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ values: [values] }),
  });
  return await response.json();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Валидация
      if (!env.CREDENTIALS_JSON || !env.SHEET_ID) {
        return errorResponse('Missing configuration', 500);
      }

      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(creds);

      // Health check
      if (path === '/api/health') {
        return jsonResponse({
          status: 'ok',
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          mode: 'production_with_google_sheets',
        });
      }

      // Get partners
      if (path === '/api/partners' && request.method === 'GET') {
        const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
        return jsonResponse(partners.map(p => ({
          title: p.title,
          url: p.url,
          category: p.category,
        })));
      }

      // Register click
      if (path === '/api/click' && request.method === 'POST') {
        const body = await request.json();
        await appendSheetRow(
          env.SHEET_ID,
          'clicks',
          [body.telegram_id, body.url, new Date().toISOString()],
          accessToken
        );
        return jsonResponse({ ok: true, success: true });
      }

      // Register user
      if (path === '/api/user' && request.method === 'POST') {
        const body = await request.json();
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const existing = users.find(u => String(u.telegram_id) === String(body.id));

        if (!existing) {
          await appendSheetRow(
            env.SHEET_ID,
            'users',
            [body.id, body.username || 'N/A', body.first_name || 'Unknown', new Date().toISOString(), 'TRUE'],
            accessToken
          );
        }
        return jsonResponse({ ok: true, success: true });
      }

      // Check admin
      if (path === '/api/me' && request.method === 'POST') {
        const body = await request.json();
        const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
        const is_admin = admins.some(a => 
          a.username && a.username.toLowerCase() === body.username?.toLowerCase()
        );
        return jsonResponse({ is_admin });
      }

      // Get subscribers
      if (path === '/api/subscribers' && request.method === 'GET') {
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        return jsonResponse(users.map(u => ({
          telegram_id: u.telegram_id,
          username: u.username,
          subscribed: String(u.subscribed).toUpperCase() === 'TRUE',
        })));
      }

      // Send push
      if (path === '/api/push' && request.method === 'POST') {
        const body = await request.json();
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const subscribedUsers = users.filter(u => String(u.subscribed).toUpperCase() === 'TRUE');

        const sendPromises = subscribedUsers.map(user =>
          fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              chat_id: user.telegram_id,
              text: `*${body.title}*\n\n${body.msg}`,
              parse_mode: 'Markdown',
              reply_markup: {
                inline_keyboard: [[{ text: 'Перейти', url: body.link }]],
              },
            }),
          }).catch(() => ({ success: false }))
        );

        const results = await Promise.allSettled(sendPromises);
        const successful = results.filter(r => r.status === 'fulfilled').length;

        return jsonResponse({
          ok: true,
          success: true,
          sent: successful,
          total: subscribedUsers.length,
        });
      }

      return errorResponse('Endpoint not found', 404);
    } catch (error) {
      console.error('Error:', error);
      return errorResponse(error.message || 'Internal server error', 500);
    }
  },
};
