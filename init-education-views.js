import crypto from 'crypto';
import { readFileSync } from 'fs';

// Manual .env loading
const envFile = readFileSync('.env', 'utf-8');
const envVars = {};
envFile.split('\n').forEach(line => {
  const match = line.match(/^([^=]+)=(.*)$/);
  if (match) {
    const key = match[1].trim();
    let value = match[2].trim();
    // Remove quotes if present
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    envVars[key] = value;
  }
});

const SHEET_ID = envVars.SHEET_ID;
const creds = JSON.parse(envVars.CREDENTIALS_JSON);

// Fix private key
creds.private_key = creds.private_key.replace(/\\n/g, '\n');

// JWT token generation
function getAccessToken(creds) {
  const now = Math.floor(Date.now() / 1000);
  const expiry = now + 3600;

  const header = {
    alg: 'RS256',
    typ: 'JWT',
  };

  const claimSet = {
    iss: creds.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: expiry,
    iat: now,
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedClaimSet = Buffer.from(JSON.stringify(claimSet)).toString('base64url');
  const signatureInput = `${encodedHeader}.${encodedClaimSet}`;

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signatureInput);
  const signature = sign.sign(creds.private_key, 'base64url');

  const jwt = `${signatureInput}.${signature}`;

  return fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  })
    .then(r => r.json())
    .then(data => data.access_token);
}

// Add sheet headers
async function initEducationViewsSheet(accessToken) {
  console.log('📋 Initializing education_views sheet...');

  const headers = [
    'telegram_id',
    'username',
    'title',
    'video_url',
    'view_date',
    'view_time'
  ];

  // First, check if sheet exists
  const sheetsUrl = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}`;
  const sheetsResponse = await fetch(sheetsUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const sheetsData = await sheetsResponse.json();
  const sheetExists = sheetsData.sheets?.some(s => s.properties.title === 'education_views');

  if (sheetExists) {
    console.log('ℹ️  Sheet "education_views" already exists');
    return;
  }

  // Create new sheet
  console.log('📝 Creating education_views sheet...');
  const createSheetUrl = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}:batchUpdate`;
  const createResponse = await fetch(createSheetUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      requests: [{
        addSheet: {
          properties: {
            title: 'education_views',
          },
        },
      }],
    }),
  });

  if (!createResponse.ok) {
    throw new Error(`Failed to create sheet: ${await createResponse.text()}`);
  }

  console.log('✅ Sheet created');

  // Add headers
  console.log('📝 Adding headers...');
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/education_views!A1:F1?valueInputOption=RAW`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      values: [headers],
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to add headers: ${await response.text()}`);
  }

  console.log('✅ Headers added to education_views sheet');
  console.log('📋 Columns:', headers.join(', '));
}

// Main
(async () => {
  try {
    console.log('🚀 Starting education_views sheet initialization...\n');

    const accessToken = await getAccessToken(creds);
    console.log('✅ Access token obtained\n');

    await initEducationViewsSheet(accessToken);

    console.log('\n✅ Done! education_views sheet is ready.');
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
})();
