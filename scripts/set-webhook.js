#!/usr/bin/env node

/**
 * Script to set Telegram Bot Webhook
 * Usage: node scripts/set-webhook.js
 */

import dotenv from 'dotenv';
import https from 'https';

// Load environment variables
dotenv.config();

const BOT_TOKEN = process.env.BOT_TOKEN;
const SERVER_URL = process.env.SERVER_URL || 'https://app.okolotattooing.ru';

if (!BOT_TOKEN) {
  console.error('❌ BOT_TOKEN is not set in .env file');
  process.exit(1);
}

const webhookUrl = `${SERVER_URL}/bot${BOT_TOKEN}`;
const apiUrl = `https://api.telegram.org/bot${BOT_TOKEN}/setWebhook?url=${encodeURIComponent(webhookUrl)}`;

console.log('🔄 Setting webhook...');
console.log('Webhook URL:', webhookUrl);

https.get(apiUrl, (res) => {
  let data = '';

  res.on('data', (chunk) => {
    data += chunk;
  });

  res.on('end', () => {
    try {
      const response = JSON.parse(data);

      if (response.ok) {
        console.log('✅ Webhook set successfully!');
        console.log('Response:', JSON.stringify(response, null, 2));
      } else {
        console.error('❌ Failed to set webhook');
        console.error('Response:', JSON.stringify(response, null, 2));
        process.exit(1);
      }
    } catch (error) {
      console.error('❌ Error parsing response:', error);
      console.error('Raw response:', data);
      process.exit(1);
    }
  });
}).on('error', (error) => {
  console.error('❌ Request failed:', error.message);
  process.exit(1);
});
