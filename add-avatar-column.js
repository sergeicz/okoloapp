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

// Add avatar_url column to users sheet
async function addAvatarColumn(accessToken) {
  console.log('📋 Adding avatar_url column to users sheet...');

  // Get current data
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/users!A1:Z1000`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json();
  const rows = data.values || [];

  if (rows.length === 0) {
    console.error('❌ Users sheet is empty!');
    return;
  }

  const headers = rows[0];
  console.log('Current headers:', headers);

  // Check if avatar_url already exists
  if (headers.includes('avatar_url')) {
    console.log('ℹ️  avatar_url column already exists');
    return;
  }

  // Add avatar_url header
  headers.push('avatar_url');

  // Update header row
  const updateUrl = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/users!A1:Z1?valueInputOption=RAW`;
  const updateResponse = await fetch(updateUrl, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      values: [headers],
    }),
  });

  if (!updateResponse.ok) {
    throw new Error(`Failed to update headers: ${await updateResponse.text()}`);
  }

  console.log('✅ Added avatar_url column to users sheet');
  console.log('📋 New headers:', headers);
}

// Main
(async () => {
  try {
    console.log('🚀 Starting avatar_url column addition...\n');

    const accessToken = await getAccessToken(creds);
    console.log('✅ Access token obtained\n');

    await addAvatarColumn(accessToken);

    console.log('\n✅ Done! avatar_url column added to users sheet.');
    console.log('\n⚠️  Note: Existing users will have empty avatar_url.');
    console.log('   Avatars will be populated on next user login.');
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
})();
