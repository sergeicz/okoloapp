// Script to fix Google Sheets structure
import crypto from 'crypto';
import { readFileSync } from 'fs';

// Load .env manually
const envFile = readFileSync('.env', 'utf-8');
envFile.split('\n').forEach(line => {
  const [key, ...valueParts] = line.split('=');
  if (key && valueParts.length) {
    const value = valueParts.join('=').trim().replace(/^["']|["']$/g, '');
    process.env[key.trim()] = value;
  }
});

async function getAccessToken(creds) {
  const jwtHeader = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const jwtClaim = Buffer.from(JSON.stringify({
    iss: creds.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  })).toString('base64url');

  const signatureInput = `${jwtHeader}.${jwtClaim}`;
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signatureInput);
  const signature = sign.sign(creds.private_key, 'base64url');
  const jwt = `${signatureInput}.${signature}`;

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });

  const data = await response.json();
  return data.access_token;
}

async function updateSheetHeaders(spreadsheetId, sheetName, headers, accessToken) {
  // First, get current data to preserve it
  const getUrl = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${sheetName}`;
  const getResponse = await fetch(getUrl, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const currentData = await getResponse.json();
  const rows = currentData.values || [];

  console.log(`[${sheetName}] Current rows: ${rows.length}`);
  console.log(`[${sheetName}] Current headers:`, rows[0]);
  console.log(`[${sheetName}] New headers:`, headers);

  // Update just the first row (headers)
  const updateUrl = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values/${sheetName}!A1:${String.fromCharCode(64 + headers.length)}1?valueInputOption=RAW`;
  const updateResponse = await fetch(updateUrl, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      values: [headers]
    })
  });

  if (!updateResponse.ok) {
    const error = await updateResponse.text();
    throw new Error(`Failed to update ${sheetName}: ${error}`);
  }

  console.log(`✅ [${sheetName}] Headers updated successfully`);
  return await updateResponse.json();
}

async function main() {
  try {
    console.log('🔄 Starting Google Sheets structure fix...\n');

    const creds = JSON.parse(process.env.CREDENTIALS_JSON);
    // Fix private key - replace escaped newlines with actual newlines
    creds.private_key = creds.private_key.replace(/\\n/g, '\n');
    const accessToken = await getAccessToken(creds);
    console.log('✅ Access token obtained\n');

    // Fix users sheet - add missing columns
    const usersHeaders = [
      'telegram_id',
      'username',
      'first_name',
      'date_registered',
      'bot_started',
      'last_active',
      'total_points',
      'current_streak',
      'longest_streak',
      'last_active_date',
      'referrals_count',
      'education_views_count',
      'events_registered',
      'partners_subscribed',
      'total_donations',
      'registration_number'
    ];

    console.log('📝 Updating users sheet...');
    await updateSheetHeaders(process.env.SHEET_ID, 'users', usersHeaders, accessToken);
    console.log('');

    // Fix achievements sheet - remove duplicate rarity, add missing columns
    const achievementsHeaders = [
      'id',
      'slug',
      'title',
      'description',
      'points',
      'rarity',
      'icon_emoji',
      'condition_type',
      'condition_value',
      'is_active'
    ];

    console.log('📝 Updating achievements sheet...');
    await updateSheetHeaders(process.env.SHEET_ID, 'achievements', achievementsHeaders, accessToken);
    console.log('');

    console.log('✅ All sheets updated successfully!');
    console.log('\n📋 Summary:');
    console.log('  • users: Added 10 columns (total_points, streaks, counts, etc.)');
    console.log('  • achievements: Removed duplicate rarity, added condition_value and is_active');

  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

main();
