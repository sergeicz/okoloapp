// Express.js Server with grammY + API + Admin Panel
// Migrated from Cloudflare Worker to Node.js/Express
// Version: 2.0.0

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import Redis from 'ioredis';
import cron from 'node-cron';
import { Bot, webhookCallback, InlineKeyboard } from 'grammy';
import crypto from 'crypto';

// Load environment variables
dotenv.config();

// ═══════════════════════════════════════════════════════════════
// REDIS SETUP
// ═══════════════════════════════════════════════════════════════

const redis = new Redis({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  retryStrategy(times) {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
});

redis.on('connect', () => {
  console.log('[Redis] ✅ Connected to Redis');
});

redis.on('error', (err) => {
  console.error('[Redis] ❌ Error:', err);
});

// ═══════════════════════════════════════════════════════════════
// ENVIRONMENT VARIABLES WRAPPER
// ═══════════════════════════════════════════════════════════════

// Create a global env object for compatibility with Worker code
const env = {
  BOT_TOKEN: process.env.BOT_TOKEN,
  SHEET_ID: process.env.SHEET_ID,
  CREDENTIALS_JSON: process.env.CREDENTIALS_JSON,
  WEBAPP_URL: process.env.WEBAPP_URL,
  BROADCAST_STATE: {
    async get(key) {
      return await redis.get(key);
    },
    async put(key, value, options = {}) {
      if (options.expirationTtl) {
        await redis.setex(key, options.expirationTtl, value);
      } else {
        await redis.set(key, value);
      }
    },
    async delete(key) {
      await redis.del(key);
    },
    async list(options = {}) {
      const prefix = options.prefix || '';
      const keys = await redis.keys(prefix + '*');
      return { keys: keys.map(name => ({ name })) };
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

function jsonResponse(data, status = 200) {
  return { data, status };
}

function errorResponse(message, status = 500) {
  console.error(`Error ${status}: ${message}`);
  return { data: { error: message, success: false }, status };
}

// ═══════════════════════════════════════════════════════════════
// GOOGLE SHEETS API
// ═══════════════════════════════════════════════════════════════

// Cached access token retrieval (cache for 55 minutes)
async function getAccessToken(env, creds) {
  const cacheKey = 'google_access_token';

  // Check cache
  const cached = await env.BROADCAST_STATE.get(cacheKey);
  if (cached) {
    const { token, expires } = JSON.parse(cached);
    // If token is still valid (with 1 minute buffer)
    if (Date.now() < expires - 60000) {
      return token;
    }
  }

  // Create new token
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

  if (!data.access_token) {
    console.error('[getAccessToken] Failed to get token:', data);
    throw new Error('Failed to get Google access token');
  }

  // Cache for 55 minutes (token lives 60 minutes)
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify({
    token: data.access_token,
    expires: Date.now() + 55 * 60 * 1000
  }), {
    expirationTtl: 3600 // Auto-delete after 1 hour
  });

  console.log('[getAccessToken] ✅ New token cached');
  return data.access_token;
}

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

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedClaim = Buffer.from(JSON.stringify(claim)).toString('base64url');
  const signatureInput = `${encodedHeader}.${encodedClaim}`;

  // Clean private key from headers and spaces
  const cleanedKey = creds.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\\n/g, '')
    .replace(/\n/g, '')
    .replace(/\s/g, '');

  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(cleanedKey, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });

  const signature = crypto.sign('sha256', Buffer.from(signatureInput), privateKey);
  const encodedSignature = signature.toString('base64url');

  return `${signatureInput}.${encodedSignature}`;
}

async function getSheetData(sheetId, sheetName, accessToken) {
  // Don't encode range - Google Sheets API accepts it as is
  const range = `${sheetName}!A:Z`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json();

  if (data.error) {
    console.error(`[getSheetData] ❌ Error reading sheet "${sheetName}":`, data.error);
    return [];
  }

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

async function appendSheetRow(sheetId, sheetName, values, accessToken) {
  // Don't encode range - just add :append to URL
  const range = `${sheetName}!A:Z`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}:append?valueInputOption=RAW`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ values: [values] }),
  });
  const result = await response.json();

  // Log for debugging
  if (result.error) {
    console.error(`[appendSheetRow] ❌ Error appending to sheet "${sheetName}":`, result.error);
  }

  return result;
}

async function updateSheetRow(sheetId, sheetName, rowIndex, values, accessToken) {
  // rowIndex is 1-based (1 = header, 2 = first data row)
  // Don't encode range
  const range = `${sheetName}!A${rowIndex}:Z${rowIndex}`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/${range}?valueInputOption=RAW`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ values: [values] }),
  });
  const result = await response.json();

  // Log for debugging
  if (result.error) {
    console.error(`[updateSheetRow] ❌ Error updating sheet "${sheetName}" row ${rowIndex}:`, result.error);
  }

  return result;
}

async function getSheetIdByName(spreadsheetId, sheetName, accessToken) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json();

  const sheet = data.sheets.find(s => s.properties.title === sheetName);
  return sheet ? sheet.properties.sheetId : 0;
}

async function getAllSheetNames(spreadsheetId, accessToken) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const data = await response.json();

  if (!data.sheets) {
    console.error('[getAllSheetNames] No sheets found in response');
    return [];
  }

  const sheetNames = data.sheets.map(s => s.properties.title);
  console.log('[getAllSheetNames] Found sheets:', sheetNames);
  return sheetNames;
}

async function deleteSheetRow(spreadsheetId, sheetName, rowIndex, accessToken) {
  // Get internal sheet ID
  const sheetId = await getSheetIdByName(spreadsheetId, sheetName, accessToken);

  const url = `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}:batchUpdate`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      requests: [{
        deleteDimension: {
          range: {
            sheetId: sheetId,
            dimension: 'ROWS',
            startIndex: rowIndex - 1, // 0-based index for API
            endIndex: rowIndex
          }
        }
      }]
    }),
  });
  return response.json();
}

async function checkUserActive(bot, userId) {
  try {
    const member = await bot.api.getChatMember(userId, userId);
    return member.status !== 'kicked';
  } catch (error) {
    // If error - user blocked bot or deleted account
    if (error.error_code === 403 || error.error_code === 400) {
      return false;
    }
    // Other errors - consider active
    return true;
  }
}

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING & SECURITY
// ═══════════════════════════════════════════════════════════════

async function checkRateLimit(env, key, limit, windowSeconds) {
  const cacheKey = `ratelimit:${key}`;
  const current = await env.BROADCAST_STATE.get(cacheKey);
  const count = current ? parseInt(current) : 0;

  if (count >= limit) {
    throw new Error('Rate limit exceeded');
  }

  await env.BROADCAST_STATE.put(cacheKey, String(count + 1), {
    expirationTtl: windowSeconds
  });

  return count + 1;
}

function validateCredentials(creds) {
  if (!creds || typeof creds !== 'object') {
    throw new Error('Invalid credentials format');
  }
  if (!creds.client_email || !creds.private_key) {
    throw new Error('Missing client_email or private_key in credentials');
  }
}

// ═══════════════════════════════════════════════════════════════
// CACHE HELPERS
// ═══════════════════════════════════════════════════════════════

// Cache admin list for 5 minutes
async function getCachedAdmins(env) {
  const cacheKey = 'cache:admins';
  const cached = await env.BROADCAST_STATE.get(cacheKey);

  if (cached) {
    return JSON.parse(cached);
  }

  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(env, creds);
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);

  // Cache for 5 minutes
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(admins), {
    expirationTtl: 300
  });

  return admins;
}

// Cache partner list for 5 minutes
async function getCachedPartners(env) {
  const cacheKey = 'cache:partners';
  const cached = await env.BROADCAST_STATE.get(cacheKey);

  if (cached) {
    return JSON.parse(cached);
  }

  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(env, creds);
  const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);

  // Cache for 5 minutes
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(partners), {
    expirationTtl: 300
  });

  return partners;
}

// Invalidate cache (call when updating data)
async function invalidateCache(env, type) {
  const cacheKey = `cache:${type}`;
  await env.BROADCAST_STATE.delete(cacheKey);
  console.log(`[Cache] Invalidated cache for: ${type}`);
}

// ═══════════════════════════════════════════════════════════════
// ADMIN CHECK HELPER
// ═══════════════════════════════════════════════════════════════

async function checkAdmin(env, user) {
  const admins = await getCachedAdmins(env);

  const isAdmin = admins.some(a => {
    const usernameMatch = a.username && user.username &&
      a.username.toLowerCase().replace('@', '') === user.username.toLowerCase().replace('@', '');
    const idMatch = a.telegram_id && String(a.telegram_id) === String(user.id);
    return usernameMatch || idMatch;
  });

  console.log(`Admin check for ${user.username} (${user.id}):`, isAdmin);
  return isAdmin;
}

// Check if user is a partner representative
async function checkRepresentative(env, user) {
  try {
    if (!user.username) {
      return null; // No username - can't be representative
    }

    const partners = await getCachedPartners(env);

    // Normalize user username (remove @ and lowercase)
    const normalizedUsername = user.username.toLowerCase().replace('@', '').trim();

    // Find partner where this user is representative
    const partnerData = partners.find(p => {
      if (!p.predstavitel) return false;

      // Normalize representative from table (remove @ and lowercase)
      const normalizedPredstavitel = p.predstavitel.toLowerCase().replace('@', '').trim();

      return normalizedPredstavitel === normalizedUsername;
    });

    console.log(`Representative check for ${user.username} (normalized: ${normalizedUsername}):`, partnerData ? partnerData.title : 'not found');
    return partnerData || null;
  } catch (error) {
    console.error('Error checking representative:', error);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// BROADCAST STATE HELPERS
// ═══════════════════════════════════════════════════════════════

async function getBroadcastState(env, chatId) {
  const stateJson = await env.BROADCAST_STATE.get(`broadcast_${chatId}`);
  return stateJson ? JSON.parse(stateJson) : null;
}

async function saveBroadcastState(env, chatId, state) {
  await env.BROADCAST_STATE.put(`broadcast_${chatId}`, JSON.stringify(state), { expirationTtl: 3600 });
}

async function deleteBroadcastState(env, chatId) {
  await env.BROADCAST_STATE.delete(`broadcast_${chatId}`);
}

// ═══════════════════════════════════════════════════════════════
// AUTOMATIC DELETION OF OLD PROMOCODES
// ═══════════════════════════════════════════════════════════════

async function deleteOldPromocodes(env) {
  console.log('[PROMO-DELETE] 🗑️ Starting old promocodes cleanup...');

  try {
    const bot = new Bot(env.BOT_TOKEN);
    let deletedCount = 0;
    let errorCount = 0;

    // Get all promocode keys from Redis
    const list = await env.BROADCAST_STATE.list({ prefix: 'promo_msg_' });
    console.log(`[PROMO-DELETE] 📊 Found ${list.keys.length} promocode messages to check`);

    const now = Date.now();

    for (const key of list.keys) {
      try {
        const dataJson = await env.BROADCAST_STATE.get(key.name);
        if (!dataJson) continue;

        const data = JSON.parse(dataJson);

        // Check if we need to delete
        if (now >= data.delete_at) {
          console.log(`[PROMO-DELETE] 🎯 Deleting message ${data.message_id} from chat ${data.chat_id} (partner: ${data.partner})`);

          try {
            await bot.api.deleteMessage(data.chat_id, data.message_id);
            deletedCount++;
            console.log(`[PROMO-DELETE] ✅ Deleted message ${data.message_id}`);
          } catch (error) {
            // Message may have been already deleted by user
            if (error.error_code === 400 && error.description?.includes('message to delete not found')) {
              console.log(`[PROMO-DELETE] ℹ️ Message ${data.message_id} already deleted`);
            } else {
              console.error(`[PROMO-DELETE] ❌ Failed to delete message ${data.message_id}:`, error.description);
              errorCount++;
            }
          }

          // Delete record from Redis
          await env.BROADCAST_STATE.delete(key.name);
        }
      } catch (error) {
        console.error(`[PROMO-DELETE] ❌ Error processing key ${key.name}:`, error);
        errorCount++;
      }
    }

    console.log(`[PROMO-DELETE] ✅ Cleanup completed! Deleted: ${deletedCount}, Errors: ${errorCount}`);

    return {
      success: true,
      deleted: deletedCount,
      errors: errorCount
    };
  } catch (error) {
    console.error('[PROMO-DELETE] ❌ Error during promocodes cleanup:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// AUTOMATIC USER CHECK (CRON)
// ═══════════════════════════════════════════════════════════════

async function checkAllUsers(env) {
  console.log('[CRON] 🕐 Starting automatic user check...');

  try {
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);

    const bot = new Bot(env.BOT_TOKEN);
    let checkedCount = 0;
    let inactiveCount = 0;
    const inactiveUsers = [];

    console.log(`[CRON] 📊 Found ${users.length} users to check`);

    // Check each user
    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      if (!user.telegram_id || String(user.telegram_id).trim() === '') {
        continue;
      }

      try {
        // Get current user info
        const chatInfo = await bot.api.getChat(user.telegram_id);
        checkedCount++;

        // Update user data in table if changed
        const currentUsername = user.username || '';
        const currentFirstName = user.first_name || '';
        const newUsername = chatInfo.username ? `@${chatInfo.username}` : '';
        const newFirstName = chatInfo.first_name || '';

        if (currentUsername !== newUsername || currentFirstName !== newFirstName) {
          console.log(`[CRON] 📝 Updating user ${user.telegram_id}: username ${currentUsername} → ${newUsername}, name ${currentFirstName} → ${newFirstName}`);

          const rowIndex = i + 2; // +2 because: +1 for header, +1 for 1-based index
          await updateSheetRow(
            env.SHEET_ID,
            'users',
            rowIndex,
            [
              user.telegram_id,
              newUsername || currentUsername,
              newFirstName || currentFirstName,
              user.date_registered || new Date().toISOString().split('T')[0],
              user.bot_started || 'бот запущен',
              user.last_active || new Date().toISOString().split('T')[0]
            ],
            accessToken
          );
        }

        // Add small delay to avoid rate limits
        if (i % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        // User blocked bot or deleted account
        if (error.error_code === 403 || (error.error_code === 400 && error.description?.includes('chat not found'))) {
          console.log(`[CRON] 🚫 User ${user.telegram_id} is inactive (blocked bot or deleted account)`);
          inactiveCount++;
          inactiveUsers.push({
            telegram_id: user.telegram_id,
            username: user.username,
            first_name: user.first_name
          });

          // Archive inactive user
          try {
            const rowIndex = i + 2;
            const currentDate = new Date().toISOString().split('T')[0];

            // Get archive sheet
            const archived = await getSheetData(env.SHEET_ID, 'archived_users', accessToken);

            // Check if already archived
            const alreadyArchived = archived.some(a => String(a.telegram_id) === String(user.telegram_id));

            if (!alreadyArchived) {
              // Add to archive
              await appendSheetRow(
                env.SHEET_ID,
                'archived_users',
                [
                  user.telegram_id,
                  user.username || '',
                  user.first_name || '',
                  user.date_registered || currentDate,
                  currentDate, // archive_date
                  'заблокировал бота или удалил аккаунт'
                ],
                accessToken
              );

              // Delete from users
              await deleteSheetRow(env.SHEET_ID, 'users', rowIndex, accessToken);
              console.log(`[CRON] ✅ User ${user.telegram_id} archived and deleted`);
            }
          } catch (archiveError) {
            console.error(`[CRON] ❌ Error archiving user ${user.telegram_id}:`, archiveError);
          }
        } else {
          console.error(`[CRON] ❌ Error checking user ${user.telegram_id}:`, error);
        }

        // Add delay after error
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    console.log(`[CRON] ✅ User check completed! Checked: ${checkedCount}, Inactive: ${inactiveCount}`);

    return {
      success: true,
      checked: checkedCount,
      inactive: inactiveCount,
      inactiveUsers: inactiveUsers
    };
  } catch (error) {
    console.error('[CRON] ❌ Error during user check:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// WEEKLY PARTNER REPORTS
// ═══════════════════════════════════════════════════════════════

async function sendWeeklyPartnerReports(env) {
  try {
    console.log('[WEEKLY_REPORT] 📊 Starting weekly partner reports...');

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);

    const bot = new Bot(env.BOT_TOKEN);
    let sentCount = 0;

    // Calculate date range for last week
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const weekAgoStr = weekAgo.toISOString().split('T')[0];

    for (const partner of partners) {
      if (!partner.telegram_id) continue;

      // Filter clicks for this partner for last week
      const partnerClicks = clicks.filter(c =>
        c.partner === partner.title &&
        c.timestamp >= weekAgoStr
      );

      // Filter broadcasts for this partner
      const partnerBroadcasts = broadcasts.filter(b =>
        b.partner === partner.title &&
        b.sent_at >= weekAgoStr
      );

      const totalClicks = partnerClicks.length;
      const totalBroadcasts = partnerBroadcasts.length;

      if (totalClicks === 0 && totalBroadcasts === 0) {
        console.log(`[WEEKLY_REPORT] ⏭️ No activity for partner ${partner.title}, skipping`);
        continue;
      }

      const message = `📊 <b>Еженедельный отчет для ${partner.title}</b>\n\n` +
        `📅 Период: последние 7 дней\n\n` +
        `📢 Рассылок: ${totalBroadcasts}\n` +
        `👆 Переходов: ${totalClicks}\n`;

      try {
        await bot.api.sendMessage(partner.telegram_id, message, { parse_mode: 'HTML' });
        sentCount++;
        console.log(`[WEEKLY_REPORT] ✅ Report sent to ${partner.title} (${partner.telegram_id})`);
      } catch (error) {
        console.error(`[WEEKLY_REPORT] ❌ Failed to send report to ${partner.title}:`, error);
      }

      // Add delay to avoid rate limits
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    console.log(`[WEEKLY_REPORT] ✅ Completed! Sent ${sentCount} reports`);
    return { success: true, sent: sentCount };
  } catch (error) {
    console.error('[WEEKLY_REPORT] ❌ Error:', error);
    return { success: false, error: error.message };
  }
}

// ═══════════════════════════════════════════════════════════════
// MONTHLY PARTNER REPORTS
// ═══════════════════════════════════════════════════════════════

async function sendMonthlyPartnerReports(env) {
  try {
    console.log('[MONTHLY_REPORT] 📊 Starting monthly partner reports...');

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);

    const bot = new Bot(env.BOT_TOKEN);
    let sentCount = 0;

    // Calculate date range for last month
    const now = new Date();
    const monthAgo = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const monthAgoStr = monthAgo.toISOString().split('T')[0];

    for (const partner of partners) {
      if (!partner.telegram_id) continue;

      // Filter clicks for this partner for last month
      const partnerClicks = clicks.filter(c =>
        c.partner === partner.title &&
        c.timestamp >= monthAgoStr
      );

      // Filter broadcasts for this partner
      const partnerBroadcasts = broadcasts.filter(b =>
        b.partner === partner.title &&
        b.sent_at >= monthAgoStr
      );

      const totalClicks = partnerClicks.length;
      const totalBroadcasts = partnerBroadcasts.length;

      if (totalClicks === 0 && totalBroadcasts === 0) {
        console.log(`[MONTHLY_REPORT] ⏭️ No activity for partner ${partner.title}, skipping`);
        continue;
      }

      const message = `📊 <b>Ежемесячный отчет для ${partner.title}</b>\n\n` +
        `📅 Период: последние 30 дней\n\n` +
        `📢 Рассылок: ${totalBroadcasts}\n` +
        `👆 Переходов: ${totalClicks}\n`;

      try {
        await bot.api.sendMessage(partner.telegram_id, message, { parse_mode: 'HTML' });
        sentCount++;
        console.log(`[MONTHLY_REPORT] ✅ Report sent to ${partner.title} (${partner.telegram_id})`);
      } catch (error) {
        console.error(`[MONTHLY_REPORT] ❌ Failed to send report to ${partner.title}:`, error);
      }

      // Add delay to avoid rate limits
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    console.log(`[MONTHLY_REPORT] ✅ Completed! Sent ${sentCount} reports`);
    return { success: true, sent: sentCount };
  } catch (error) {
    console.error('[MONTHLY_REPORT] ❌ Error:', error);
    return { success: false, error: error.message };
  }
}

// ═══════════════════════════════════════════════════════════════
// BROADCAST HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════

async function showBroadcastPreview(ctx, env, state) {
  const mediaType = state.media_type || ((state.image_url || state.image_file_id) ? 'photo' : null);
  const mediaSource = state.media_file_id || state.media_url || state.image_file_id || state.image_url;

  const keyboard = new InlineKeyboard()
    .text('✅ Отправить всем', 'broadcast_confirm').row()
    .text('❌ Отменить', 'broadcast_cancel');

  if (mediaType === 'photo') {
    let caption = '📢 *Предпросмотр рассылки*\n\n';
    if (state.title) caption += `*${state.title}*\n`;
    if (state.subtitle) caption += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) caption += `\n🔘 Кнопка: "${state.button_text}"\n`;
    caption += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;

    await ctx.replyWithPhoto(mediaSource, {
      caption: caption,
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
  } else if (mediaType === 'video') {
    let caption = '📢 *Предпросмотр рассылки*\n\n';
    if (state.title) caption += `*${state.title}*\n`;
    if (state.subtitle) caption += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) caption += `\n🔘 Кнопка: "${state.button_text}"\n`;
    caption += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;

    await ctx.replyWithVideo(mediaSource, {
      caption: caption,
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
  } else if (mediaType === 'voice' || mediaType === 'video_note') {
    let previewText = '📢 *Предпросмотр рассылки*\n\n━━━━━━━━━━━━━━━━\n';
    if (state.title) previewText += `\n*${state.title}*\n`;
    if (state.subtitle) previewText += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) previewText += `\n🔘 Кнопка: "${state.button_text}"\n`;
    previewText += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;

    await ctx.reply(previewText, {
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });

    if (mediaType === 'voice') {
      await ctx.replyWithVoice(mediaSource);
    } else {
      await ctx.replyWithVideoNote(mediaSource);
    }
  } else {
    let previewText = '📢 *Предпросмотр рассылки*\n\n━━━━━━━━━━━━━━━━\n';
    if (state.title) previewText += `\n*${state.title}*\n`;
    if (state.subtitle) previewText += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) previewText += `\n🔘 Кнопка: "${state.button_text}"\n`;
    previewText += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;

    await ctx.reply(previewText, {
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
  }

  state.step = 'confirm';
  await saveBroadcastState(env, ctx.chat.id, state);
}

// Helper функция для отправки одного сообщения рассылки
async function sendBroadcastToUser(api, user, messageText, keyboard, mediaType, mediaSource) {
  const userId = user.telegram_id;

  if (mediaType === 'photo') {
    await api.sendPhoto(userId, mediaSource, {
      caption: messageText,
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
  } else if (mediaType === 'video') {
    await api.sendVideo(userId, mediaSource, {
      caption: messageText,
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
  } else if (mediaType === 'voice') {
    if (messageText) {
      await api.sendMessage(userId, messageText, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
    }
    await api.sendVoice(userId, mediaSource);
  } else if (mediaType === 'video_note') {
    if (messageText) {
      await api.sendMessage(userId, messageText, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
    }
    await api.sendVideoNote(userId, mediaSource);
  } else {
    await api.sendMessage(userId, messageText, {
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
  }
}

async function executeBroadcast(ctx, env, state) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(env, creds);
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);

  let messageText = '';
  if (state.title) messageText += `*${state.title}*\n`;
  if (state.subtitle) messageText += `\n${state.subtitle}`;

  // Создаем промежуточную ссылку для отслеживания кликов
  let keyboard = null;
  if (state.button_text && state.button_url) {
    const encodedPartnerUrl = encodeURIComponent(state.button_url);
    const trackedUrl = `https://telegram-miniapp-api.worknotdead.workers.dev/r/${state.broadcast_id}/${encodedPartnerUrl}`;
    keyboard = new InlineKeyboard().url(state.button_text, trackedUrl);
  }

  const mediaType = state.media_type || ((state.image_url || state.image_file_id) ? 'photo' : null);
  const mediaSource = state.media_file_id || state.media_url || state.image_file_id || state.image_url;

  let successCount = 0;
  let failCount = 0;
  let inactiveCount = 0;
  const errors = [];
  const inactiveUsers = [];

  await ctx.reply('⏳ Проверяю активных подписчиков...');

  // Фильтруем только пользователей с telegram_id
  const validUsers = users.filter(u => u.telegram_id && String(u.telegram_id).trim() !== '');

  await ctx.reply(`📊 Найдено пользователей: ${validUsers.length}\n⏳ Начинаю рассылку...`);

  // ✅ ОПТИМИЗАЦИЯ: Батчинг - отправляем по 20 сообщений параллельно
  const BATCH_SIZE = 20;
  const totalUsers = validUsers.length;

  for (let i = 0; i < totalUsers; i += BATCH_SIZE) {
    const batch = validUsers.slice(i, i + BATCH_SIZE);

    // Отправляем батч параллельно
    const results = await Promise.allSettled(
      batch.map(user => sendBroadcastToUser(ctx.api, user, messageText, keyboard, mediaType, mediaSource))
    );

    // Обрабатываем результаты
    results.forEach((result, idx) => {
      const user = batch[idx];

      if (result.status === 'fulfilled') {
        successCount++;
      } else {
        failCount++;
        const error = result.reason;
        const errorCode = error.error_code;
        const errorDescription = error.description || error.message;

        console.error(`Failed to send to ${user.telegram_id}:`, errorCode, errorDescription);

        // Классифицируем ошибки
        if (errorCode === 403) {
          inactiveUsers.push({
            telegram_id: user.telegram_id,
            username: user.username,
            date_on: user.date_registered || user.first_seen || '',
            reason: 'Заблокировал бота'
          });
          inactiveCount++;
        } else if (errorCode === 400 && errorDescription?.includes('chat not found')) {
          inactiveUsers.push({
            telegram_id: user.telegram_id,
            username: user.username,
            date_on: user.date_registered || user.first_seen || '',
            reason: 'Удалил аккаунт'
          });
          inactiveCount++;
        } else if (errorCode === 400 && errorDescription?.includes('user is deactivated')) {
          inactiveUsers.push({
            telegram_id: user.telegram_id,
            username: user.username,
            date_on: user.date_registered || user.first_seen || '',
            reason: 'Деактивирован'
          });
          inactiveCount++;
        } else {
          errors.push({
            telegram_id: user.telegram_id,
            username: user.username,
            error: `${errorCode}: ${errorDescription?.substring(0, 50) || 'Unknown'}`
          });
        }
      }
    });

    // Прогресс каждые 100 пользователей
    if ((i + BATCH_SIZE) % 100 === 0 || i + BATCH_SIZE >= totalUsers) {
      const progress = Math.min(i + BATCH_SIZE, totalUsers);
      await ctx.reply(`📊 Прогресс: ${progress}/${totalUsers} (успешно: ${successCount}, ошибок: ${failCount})`);
    }

    // Небольшая задержка между батчами для Telegram API rate limits
    if (i + BATCH_SIZE < totalUsers) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  // Переносим неактивных пользователей в лист "pidarasy" и удаляем из "users"
  if (inactiveUsers.length > 0) {
    await ctx.reply(`🧹 Переношу ${inactiveUsers.length} неактивных пользователей в архив...`);

    // Получаем свежие данные из листа users
    const allUsers = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const dateOff = new Date().toISOString().split('T')[0]; // Текущая дата в формате YYYY-MM-DD

    // Переносим каждого неактивного пользователя
    for (const inactiveUser of inactiveUsers) {
      try {
        // Находим полные данные пользователя в таблице
        const fullUserData = allUsers.find(u => String(u.telegram_id) === String(inactiveUser.telegram_id));

        // Получаем дату подписки (пробуем разные варианты названий колонок)
        const dateOn = fullUserData?.date_registered
          || fullUserData?.first_seen
          || fullUserData?.created_at
          || fullUserData?.joined_date
          || inactiveUser.date_on
          || '';

        // Добавляем в лист "pidarasy"
        // Формат: username, tg_id, date on, date off
        await appendSheetRow(
          env.SHEET_ID,
          'pidarasy',
          [
            inactiveUser.username || '',
            inactiveUser.telegram_id || '',
            dateOn,
            dateOff
          ],
          accessToken
        );

        console.log(`✅ Перенесен в pidarasy: @${inactiveUser.username} (${inactiveUser.telegram_id}), подписка: ${dateOn}, отписка: ${dateOff}`);

        await new Promise(resolve => setTimeout(resolve, 50));
      } catch (error) {
        console.error(`Failed to move user ${inactiveUser.telegram_id} to pidarasy:`, error);
      }
    }

    // Теперь удаляем из листа "users"
    await ctx.reply(`🗑️ Удаляю неактивных из основной таблицы...`);

    // Находим строки для удаления (в обратном порядке чтобы индексы не сбивались)
    const rowsToDelete = [];
    for (const inactiveUser of inactiveUsers) {
      const index = allUsers.findIndex(u => String(u.telegram_id) === String(inactiveUser.telegram_id));
      if (index !== -1) {
        rowsToDelete.push(index + 2); // +2 потому что: +1 для заголовка, +1 для 1-based индекса
      }
    }

    // Удаляем строки (в обратном порядке)
    rowsToDelete.sort((a, b) => b - a);
    for (const rowIndex of rowsToDelete) {
      try {
        await deleteSheetRow(env.SHEET_ID, 'users', rowIndex, accessToken);
        await new Promise(resolve => setTimeout(resolve, 50));
      } catch (error) {
        console.error(`Failed to delete row ${rowIndex}:`, error);
      }
    }
  }

  // Сохраняем статистику рассылки в лист broadcasts
  const currentDate = new Date().toISOString().split('T')[0];
  const currentTime = new Date().toISOString().split('T')[1].split('.')[0];

  // Считаем что все успешно доставленные сообщения прочитаны
  const readCount = successCount;

  // Сохраняем статистику в таблицу broadcasts
  // Формат таблицы: broadcast_id, name, date, time, sent_count, read_count, click_count, title, subtitle, button_text, button_url, total_users, fail_count, archived_count, partner
  let saveError = null;
  try {
    const broadcastData = [
      state.broadcast_id || '',                    // broadcast_id
      state.broadcast_name || 'Без названия',      // name
      currentDate,                                  // date
      currentTime,                                  // time
      successCount,                                 // sent_count
      readCount,                                    // read_count (= sent_count)
      0,                                            // click_count (будет обновляться)
      state.title || '',                            // title
      state.subtitle || '',                         // subtitle
      state.button_text || '',                      // button_text
      state.button_url || '',                       // button_url
      validUsers.length,                            // total_users
      failCount,                                    // fail_count
      inactiveCount,                                // archived_count
      state.partner || ''                           // partner
    ];

    console.log(`[РАССЫЛКА] 📊 Сохранение данных рассылки:`, JSON.stringify(broadcastData));
    console.log(`[РАССЫЛКА] 📋 ID таблицы: ${env.SHEET_ID}, Лист: broadcasts`);

    const result = await appendSheetRow(
      env.SHEET_ID,
      'broadcasts',
      broadcastData,
      accessToken
    );

    console.log(`[РАССЫЛКА] ✅ Статистика сохранена в лист broadcasts: ${state.broadcast_id} - ${state.broadcast_name}`);
    console.log(`[РАССЫЛКА] 📝 Ответ API:`, JSON.stringify(result));
  } catch (error) {
    saveError = error.message || String(error);
    console.error(`[РАССЫЛКА] ❌ Не удалось сохранить статистику в лист broadcasts:`, error);
    console.error(`[РАССЫЛКА] ❌ Детали ошибки:`, JSON.stringify(error, null, 2));
  }

  await deleteBroadcastState(env, ctx.chat.id);

  // Формируем детальный отчет
  let reportText = `✅ *Рассылка завершена!*\n\n`;
  reportText += `📢 *Название:* ${state.broadcast_name || 'Без названия'}\n`;
  reportText += `🆔 *ID:* \`${state.broadcast_id}\`\n\n`;
  reportText += `📊 *Статистика:*\n`;
  reportText += `✉️ Отправлено: ${successCount}\n`;
  reportText += `📖 Прочитано: ${successCount}\n`;
  reportText += `👆 Кликов: 0 (отслеживается)\n`;
  reportText += `📈 Конверсия: 0.00% (обновляется)\n`;
  reportText += `❌ Ошибок: ${failCount}\n`;

  if (saveError) {
    reportText += `\n⚠️ *Внимание:* Не удалось сохранить статистику в таблицу!\n`;
    reportText += `Ошибка: ${saveError.substring(0, 100)}\n`;
    reportText += `Проверьте что лист "broadcasts" существует.\n`;
  }

  if (inactiveCount > 0) {
    reportText += `📦 Перенесено в архив: ${inactiveCount}\n\n`;
    reportText += `*Причины:*\n`;

    const reasonCounts = {};
    inactiveUsers.forEach(u => {
      reasonCounts[u.reason] = (reasonCounts[u.reason] || 0) + 1;
    });

    for (const [reason, count] of Object.entries(reasonCounts)) {
      reportText += `• ${reason}: ${count}\n`;
    }
  }

  if (errors.length > 0) {
    reportText += `\n⚠️ *Другие ошибки (${errors.length}):*\n`;
    errors.slice(0, 5).forEach(e => {
      reportText += `• @${e.username || e.telegram_id}: ${e.error}\n`;
    });
    if (errors.length > 5) {
      reportText += `• ... и еще ${errors.length - 5}\n`;
    }
  }

  const resultKeyboard = new InlineKeyboard().text('« Вернуться в админку', 'admin_panel');

  await ctx.reply(reportText, { parse_mode: 'Markdown', reply_markup: resultKeyboard });
}

// ═══════════════════════════════════════════════════════════════
// BOT SETUP WITH GRAMMY
// ═══════════════════════════════════════════════════════════════

function setupBot(env) {
  const bot = new Bot(env.BOT_TOKEN);

  // Global error handler
  bot.catch((err) => {
    const ctx = err.ctx;
    console.error(`[BOT ERROR] Update ${ctx.update.update_id}:`);
    console.error('[BOT ERROR] Error:', err.error);
    console.error('[BOT ERROR] Stack:', err.stack);

    // Try to notify user
    if (ctx.chat) {
      ctx.reply('❌ Произошла ошибка. Попробуйте позже или обратитесь к администратору.')
        .catch(e => console.error('[BOT ERROR] Failed to send error message:', e));
    }
  });

  // Middleware: Cache permission checks
  bot.use(async (ctx, next) => {
    if (ctx.from) {
      // Cache permission checks for this request
      ctx.isAdmin = await checkAdmin(env, ctx.from);
      ctx.partnerData = await checkRepresentative(env, ctx.from);
    }
    await next();
  });

  // ═══════════════════════════════════════════════════════════════
  // BOT COMMAND HANDLERS
  // ═══════════════════════════════════════════════════════════════

  bot.command('start', async (ctx) => {
    const user = ctx.from;
    const chatId = ctx.chat.id;

    // Регистрируем пользователя
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const existing = users.find(u => String(u.telegram_id) === String(chatId));

    const currentDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const username = user.username ? `@${user.username}` : '';

    if (!existing) {
      console.log(`[REGISTER] 🆕 New user: ${chatId} (@${user.username || 'no-username'})`);

      // Добавляем в таблицу users
      // Формат: telegram_id, username, first_name, date_registered, bot_started, last_active
      await appendSheetRow(
        env.SHEET_ID,
        'users',
        [
          chatId,                        // telegram_id
          username,                      // username с @
          user.first_name || 'Unknown',  // first_name
          currentDate,                   // date_registered (YYYY-MM-DD)
          'бот запущен',                 // bot_started
          currentDate                    // last_active (YYYY-MM-DD)
        ],
        accessToken
      );

      console.log(`✅ User registered: ${chatId} ${username} at ${currentDate}`);
    } else {
      console.log(`[REGISTER] ✓ Existing user: ${chatId} (@${user.username || 'no-username'})`);

      // Обновляем данные существующего пользователя
      const userIndex = users.findIndex(u => String(u.telegram_id) === String(chatId));
      if (userIndex !== -1) {
        const rowIndex = userIndex + 2; // +2 потому что: +1 для заголовка, +1 для 1-based индекса

        // Проверяем изменились ли данные
        const needsUpdate =
          existing.username !== username ||
          existing.first_name !== (user.first_name || 'Unknown') ||
          existing.bot_started !== 'бот запущен' ||
          existing.last_active !== currentDate;

        if (needsUpdate) {
          console.log(`[REGISTER] 🔄 Updating user data: ${chatId}`);

          // Обновляем строку (сохраняем date_registered из existing)
          await updateSheetRow(
            env.SHEET_ID,
            'users',
            rowIndex,
            [
              chatId,                              // telegram_id
              username,                            // username с @ (обновленный)
              user.first_name || 'Unknown',        // first_name (обновленный)
              existing.date_registered || currentDate,  // date_registered (сохраняем старую)
              'бот запущен',                       // bot_started (обновляем)
              currentDate                          // last_active (обновляем)
            ],
            accessToken
          );

          console.log(`✅ User data updated: ${chatId} ${username}`);
        } else {
          console.log(`[REGISTER] ✓ No changes for user: ${chatId}`);
        }
      }
    }

    // Проверяем админа и представителя
    const isAdmin = await checkAdmin(env, user);
    const partnerData = await checkRepresentative(env, user);

    // Клавиатура
    const keyboard = new InlineKeyboard()
      .webApp('🚀 Открыть Mini App', env.WEBAPP_URL);

    if (isAdmin) {
      keyboard.row().text('⚙️ Админ-панель', 'admin_panel');
    }

    if (partnerData) {
      keyboard.row().text('📊 Кабинет партнёра', 'representative_cabinet');
    }

    await ctx.reply(
      `👋 Привет, *${user.first_name}*!\n\n` +
      `🔗 Жми кнопку и открывай приложение.\n\n` +
      `Внутри — уникальные промокоды, акции и контент.\n` +
      `⚠️ *Бота не останавливай*❌: сюда приходят самые жирные офферы.\n\n` +
      `🖤 Поехали 👇`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  // ═══════════════════════════════════════════════════════════════
  // ОБРАБОТКА CALLBACK QUERIES
  // ═══════════════════════════════════════════════════════════════

  // Админ-панель
  bot.callbackQuery('admin_panel', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const keyboard = new InlineKeyboard()
      .text('📊 Статистика', 'admin_stats').row()
      .text('📈 Статистика рассылок', 'admin_broadcasts_stats').row()
      .text('📊 Отчеты по партнерам', 'admin_partner_reports').row()
      .text('📢 Новая рассылка', 'admin_broadcast').row()
      .text('👥 Пользователи', 'admin_users').row()
      .text('« Назад', 'back_to_start');

    await ctx.editMessageText('⚙️ *Админ-панель*\n\nВыберите действие:', {
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
    await ctx.answerCallbackQuery();
  });

  // Статистика
  bot.callbackQuery('admin_stats', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

    const text = `📊 *Статистика*\n\n👥 Всего пользователей: ${users.length}\n📈 Всего кликов: ${clicks.length}`;

    const keyboard = new InlineKeyboard().text('« Назад', 'admin_panel');

    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
    await ctx.answerCallbackQuery();
  });

  // Статистика рассылок
  bot.callbackQuery('admin_broadcasts_stats', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);

    try {
      const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);

      if (!broadcasts || broadcasts.length === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'admin_panel');
        await ctx.editMessageText(
          '📈 *Статистика рассылок*\n\n📭 Рассылок пока нет.',
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        await ctx.answerCallbackQuery();
        return;
      }

      // Сортируем по дате (последние сначала)
      broadcasts.sort((a, b) => {
        const dateA = new Date(a.date + ' ' + a.time);
        const dateB = new Date(b.date + ' ' + b.time);
        return dateB - dateA;
      });

      // Показываем последние 10 рассылок
      const recentBroadcasts = broadcasts.slice(0, 10);

      let text = `📈 *Статистика рассылок*\n\n`;
      text += `📊 Всего рассылок: ${broadcasts.length}\n\n`;
      text += `━━━━━━━━━━━━━━━━\n`;

      recentBroadcasts.forEach((broadcast, index) => {
        const convRate = broadcast.conversion_rate || '0.00%';
        text += `\n${index + 1}. *${broadcast.name || 'Без названия'}*\n`;
        text += `📅 ${broadcast.date} | 🕐 ${broadcast.time}\n`;
        text += `✉️ ${broadcast.sent_count} | 👆 ${broadcast.click_count} | 📈 ${convRate}\n`;
      });

      if (broadcasts.length > 10) {
        text += `\n_...и еще ${broadcasts.length - 10} рассылок_`;
      }

      // Создаем клавиатуру с кнопками для детальной статистики
      const keyboard = new InlineKeyboard();

      // Добавляем кнопки для первых 5 рассылок
      recentBroadcasts.slice(0, 5).forEach((broadcast, index) => {
        const shortName = broadcast.name.length > 20 ? broadcast.name.substring(0, 20) + '...' : broadcast.name;
        keyboard.text(`${index + 1}. ${shortName}`, `broadcast_detail_${broadcast.broadcast_id}`);
        if (index % 2 === 1) keyboard.row(); // По 2 кнопки в ряд
      });

      keyboard.row().text('« Назад', 'admin_panel');

      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('[BROADCASTS_STATS] Error:', error);
      await ctx.answerCallbackQuery('❌ Ошибка загрузки статистики');
    }
  });

  // Детальная статистика конкретной рассылки
  bot.callbackQuery(/^broadcast_detail_(.+)$/, async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const broadcastId = ctx.match[1];
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);

    try {
      const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
      const broadcast = broadcasts.find(b => b.broadcast_id === broadcastId);

      if (!broadcast) {
        await ctx.answerCallbackQuery('❌ Рассылка не найдена');
        return;
      }

      let text = `📊 *Детальная статистика*\n\n`;
      text += `📢 *Название:* ${broadcast.name || 'Без названия'}\n`;
      text += `🆔 *ID:* \`${broadcast.broadcast_id}\`\n\n`;

      text += `📅 *Дата:* ${broadcast.date}\n`;
      text += `🕐 *Время:* ${broadcast.time}\n\n`;

      text += `━━━━━━━━━━━━━━━━\n`;
      text += `📊 *СТАТИСТИКА:*\n\n`;

      const sentCount = parseInt(broadcast.sent_count || '0');
      const readCount = parseInt(broadcast.read_count || '0');
      const clickCount = parseInt(broadcast.click_count || '0');
      const convRate = broadcast.conversion_rate || '0.00%';

      text += `👥 Всего пользователей: ${broadcast.total_users}\n`;
      text += `✉️ Отправлено: ${sentCount}\n`;
      text += `📖 Прочитано: ${readCount}\n`;
      text += `👆 Кликнули: ${clickCount}\n`;
      text += `📈 Конверсия: *${convRate}*\n\n`;

      if (broadcast.fail_count && parseInt(broadcast.fail_count) > 0) {
        text += `❌ Ошибок: ${broadcast.fail_count}\n`;
      }

      if (broadcast.archived_count && parseInt(broadcast.archived_count) > 0) {
        text += `📦 Архивировано: ${broadcast.archived_count}\n`;
      }

      text += `\n━━━━━━━━━━━━━━━━\n`;
      text += `📝 *СОДЕРЖАНИЕ:*\n\n`;

      if (broadcast.title) {
        text += `*Заголовок:* ${broadcast.title}\n`;
      }

      if (broadcast.subtitle) {
        text += `*Текст:* ${broadcast.subtitle}\n`;
      }

      if (broadcast.button_text && broadcast.button_url) {
        text += `\n🔘 *Кнопка:* ${broadcast.button_text}\n`;
        text += `🔗 *Ссылка:* ${broadcast.button_url}`;
      }

      const keyboard = new InlineKeyboard()
        .text('« К списку рассылок', 'admin_broadcasts_stats').row()
        .text('« В админку', 'admin_panel');

      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('[BROADCAST_DETAIL] Error:', error);
      await ctx.answerCallbackQuery('❌ Ошибка загрузки детальной статистики');
    }
  });

  // Начало создания рассылки
  bot.callbackQuery('admin_broadcast', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const state = {
      step: 'broadcast_name',
      chatId: ctx.chat.id,
      broadcast_name: null,
      broadcast_id: `BR_${Date.now()}`, // Уникальный ID рассылки
      partner: null,          // Партнер для рассылки (опционально)
      title: null,
      subtitle: null,
      image_url: null,
      image_file_id: null,
      media_type: null,       // photo | video | voice | video_note
      media_url: null,
      media_file_id: null,
      button_text: null,
      button_url: null,
      started_at: new Date().toISOString()
    };

    await saveBroadcastState(env, ctx.chat.id, state);

    const keyboard = new InlineKeyboard().text('❌ Отменить', 'broadcast_cancel');

    await ctx.editMessageText(
      '📢 *Создание рассылки*\n\n*Шаг 1 из 6:* Название рассылки\n\n📝 Введите *название* рассылки для аналитики (например: "Акция Январь 2026"):',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Пропуск выбора партнера
  bot.callbackQuery('broadcast_skip_partner', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    state.partner = null;
    state.step = 'title';
    await saveBroadcastState(env, ctx.chat.id, state);

    const keyboard = new InlineKeyboard().text('❌ Отменить', 'broadcast_cancel');

    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 3 из 6:* Заголовок\n\n✅ Рассылка без привязки к партнеру\n\n📝 Введите *заголовок* рассылки (обязательно):',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Выбор партнера для рассылки
  bot.callbackQuery(/^broadcast_partner_(\d+)$/, async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    const partnerIndex = parseInt(ctx.match[1]);

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);

    if (!partners[partnerIndex]) {
      await ctx.answerCallbackQuery('❌ Партнер не найден');
      return;
    }

    const partner = partners[partnerIndex];
    state.partner = partner.title;
    state.step = 'title';
    await saveBroadcastState(env, ctx.chat.id, state);

    const keyboard = new InlineKeyboard().text('❌ Отменить', 'broadcast_cancel');

    await ctx.reply(
      `📢 *Создание рассылки*\n\n*Шаг 3 из 6:* Заголовок\n\n✅ Партнер выбран:\n🏷️ ${partner.title}\n\n📝 Введите *заголовок* рассылки (обязательно):`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Пропуск подзаголовка
  bot.callbackQuery('broadcast_skip_subtitle', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    state.step = 'media';
    await saveBroadcastState(env, ctx.chat.id, state);

    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_image').row()
      .text('❌ Отменить', 'broadcast_cancel');

    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 5 из 6:* Медиа\n\n🖼️📹🎙️ *Прикрепите медиа* (фото/видео/голосовое/видеозаметку) или отправьте ссылку на фото/видео (URL):',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Пропуск изображения
  bot.callbackQuery('broadcast_skip_image', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    state.step = 'button';
    await saveBroadcastState(env, ctx.chat.id, state);

    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_button').row()
      .text('❌ Отменить', 'broadcast_cancel');

    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 6 из 6:* Кнопка\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Пропуск кнопки
  bot.callbackQuery('broadcast_skip_button', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    await showBroadcastPreview(ctx, env, state);
    await ctx.answerCallbackQuery();
  });

  // Подтверждение рассылки
  bot.callbackQuery('broadcast_confirm', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    await executeBroadcast(ctx, env, state);
    await ctx.answerCallbackQuery();
  });

  // Отмена рассылки
  bot.callbackQuery('broadcast_cancel', async (ctx) => {
    await deleteBroadcastState(env, ctx.chat.id);

    const keyboard = new InlineKeyboard().text('« Вернуться в админку', 'admin_panel');

    await ctx.reply('❌ Создание рассылки отменено.', { reply_markup: keyboard });
    await ctx.answerCallbackQuery();
  });

  // Список пользователей
  bot.callbackQuery('admin_users', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const keyboard = new InlineKeyboard()
      .text('📊 По активности', 'admin_users_by_activity').row()
      .text('📅 По дате регистрации', 'admin_users_by_registration').row()
      .text('🔢 Общая статистика', 'admin_users_stats').row()
      .text('« Назад', 'admin_panel');

    await ctx.editMessageText(
      '👥 *Пользователи*\n\nВыберите способ отображения:',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Список пользователей по активности
  bot.callbackQuery(/^admin_users_by_activity(?:_page_(\d+))?$/, async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    await ctx.answerCallbackQuery('📊 Загружаю список...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      const page = ctx.match[1] ? parseInt(ctx.match[1]) : 1;
      const perPage = 15;

      // Фильтруем пользователей с username и добавляем статистику
      const usersWithUsername = users
        .filter(u => u.username && u.username !== '')
        .map(u => {
          const userClicks = clicks.filter(c => String(c.telegram_id) === String(u.telegram_id));
          const totalClicks = userClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);

          return {
            ...u,
            totalClicks,
            lastActiveDate: new Date(u.last_active || u.date_added || u.date_registered || '2020-01-01')
          };
        });

      // Сортируем по последней активности (самые активные сначала)
      usersWithUsername.sort((a, b) => b.lastActiveDate - a.lastActiveDate);

      const totalUsers = usersWithUsername.length;
      const totalPages = Math.ceil(totalUsers / perPage);
      const startIndex = (page - 1) * perPage;
      const endIndex = Math.min(startIndex + perPage, totalUsers);
      const pageUsers = usersWithUsername.slice(startIndex, endIndex);

      if (totalUsers === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'admin_users');
        await ctx.editMessageText(
          '👥 *Пользователи с username*\n\n📭 Пользователей с username пока нет.',
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        return;
      }

      let text = `👥 *Пользователи с username* (по активности)\n\n`;
      text += `📊 Всего: ${totalUsers} | Страница ${page}/${totalPages}\n\n`;

      pageUsers.forEach((user, index) => {
        const position = startIndex + index + 1;
        const username = user.username.startsWith('@') ? user.username : `@${user.username}`;
        const firstName = user.first_name || 'Н/Д';
        const registered = user.date_added || user.date_registered || 'Н/Д';
        const lastActive = user.last_active || 'Н/Д';
        const clicks = user.totalClicks || 0;
        const botStarted = user.bot_started === 'TRUE' ? '✅' : '❌';

        text += `${position}. ${username}\n`;
        text += `   👤 ${firstName}\n`;
        text += `   📅 Рег: ${registered} | Активен: ${lastActive}\n`;
        text += `   🖱️ Кликов: ${clicks} | Бот: ${botStarted}\n\n`;
      });

      // Пагинация
      const keyboard = new InlineKeyboard();

      if (totalPages > 1) {
        const buttons = [];
        if (page > 1) {
          buttons.push({ text: '« Пред', callback_data: `admin_users_by_activity_page_${page - 1}` });
        }
        buttons.push({ text: `${page}/${totalPages}`, callback_data: 'noop' });
        if (page < totalPages) {
          buttons.push({ text: 'След »', callback_data: `admin_users_by_activity_page_${page + 1}` });
        }

        buttons.forEach((btn, idx) => {
          keyboard.text(btn.text, btn.callback_data);
          if (idx < buttons.length - 1) keyboard.text(' ', 'noop');
        });
        keyboard.row();
      }

      keyboard.text('« Назад', 'admin_users');

      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });

    } catch (error) {
      console.error('[ADMIN_USERS_BY_ACTIVITY] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'admin_users');
      await ctx.editMessageText(
        '❌ Ошибка при загрузке списка пользователей.',
        { reply_markup: keyboard }
      );
    }
  });

  // Список пользователей по дате регистрации
  bot.callbackQuery(/^admin_users_by_registration(?:_page_(\d+))?$/, async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    await ctx.answerCallbackQuery('📊 Загружаю список...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      const page = ctx.match[1] ? parseInt(ctx.match[1]) : 1;
      const perPage = 15;

      // Фильтруем пользователей с username и добавляем статистику
      const usersWithUsername = users
        .filter(u => u.username && u.username !== '')
        .map(u => {
          const userClicks = clicks.filter(c => String(c.telegram_id) === String(u.telegram_id));
          const totalClicks = userClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);

          return {
            ...u,
            totalClicks,
            registrationDate: new Date(u.date_added || u.date_registered || '2020-01-01')
          };
        });

      // Сортируем по дате регистрации (новые сначала)
      usersWithUsername.sort((a, b) => b.registrationDate - a.registrationDate);

      const totalUsers = usersWithUsername.length;
      const totalPages = Math.ceil(totalUsers / perPage);
      const startIndex = (page - 1) * perPage;
      const endIndex = Math.min(startIndex + perPage, totalUsers);
      const pageUsers = usersWithUsername.slice(startIndex, endIndex);

      if (totalUsers === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'admin_users');
        await ctx.editMessageText(
          '👥 *Пользователи с username*\n\n📭 Пользователей с username пока нет.',
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        return;
      }

      let text = `👥 *Пользователи с username* (по дате регистрации)\n\n`;
      text += `📊 Всего: ${totalUsers} | Страница ${page}/${totalPages}\n\n`;

      pageUsers.forEach((user, index) => {
        const position = startIndex + index + 1;
        const username = user.username.startsWith('@') ? user.username : `@${user.username}`;
        const firstName = user.first_name || 'Н/Д';
        const registered = user.date_added || user.date_registered || 'Н/Д';
        const lastActive = user.last_active || 'Н/Д';
        const clicks = user.totalClicks || 0;
        const botStarted = user.bot_started === 'TRUE' ? '✅' : '❌';

        text += `${position}. ${username}\n`;
        text += `   👤 ${firstName} | Бот: ${botStarted}\n`;
        text += `   📅 Регистрация: ${registered}\n`;
        text += `   📅 Последняя активность: ${lastActive}\n`;
        text += `   🖱️ Кликов: ${clicks}\n\n`;
      });

      // Пагинация
      const keyboard = new InlineKeyboard();

      if (totalPages > 1) {
        const buttons = [];
        if (page > 1) {
          buttons.push({ text: '« Пред', callback_data: `admin_users_by_registration_page_${page - 1}` });
        }
        buttons.push({ text: `${page}/${totalPages}`, callback_data: 'noop' });
        if (page < totalPages) {
          buttons.push({ text: 'След »', callback_data: `admin_users_by_registration_page_${page + 1}` });
        }

        buttons.forEach((btn, idx) => {
          keyboard.text(btn.text, btn.callback_data);
          if (idx < buttons.length - 1) keyboard.text(' ', 'noop');
        });
        keyboard.row();
      }

      keyboard.text('« Назад', 'admin_users');

      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });

    } catch (error) {
      console.error('[ADMIN_USERS_BY_REGISTRATION] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'admin_users');
      await ctx.editMessageText(
        '❌ Ошибка при загрузке списка пользователей.',
        { reply_markup: keyboard }
      );
    }
  });

  // Общая статистика пользователей
  bot.callbackQuery('admin_users_stats', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    await ctx.answerCallbackQuery('📊 Формирую статистику...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      const totalUsers = users.length;
      const usersWithUsername = users.filter(u => u.username && u.username !== '').length;
      const usersWithoutUsername = totalUsers - usersWithUsername;
      const botStartedUsers = users.filter(u => u.bot_started === 'TRUE').length;
      const botNotStartedUsers = totalUsers - botStartedUsers;

      // Активность за последние 7 дней
      const now = new Date();
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const activeLastWeek = users.filter(u => {
        const lastActive = new Date(u.last_active || u.date_added || u.date_registered || '2020-01-01');
        return lastActive >= sevenDaysAgo;
      }).length;

      // ТОП-5 самых активных пользователей (по кликам)
      const usersWithClicks = users
        .map(u => {
          const userClicks = clicks.filter(c => String(c.telegram_id) === String(u.telegram_id));
          const totalClicks = userClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
          return { ...u, totalClicks };
        })
        .filter(u => u.totalClicks > 0)
        .sort((a, b) => b.totalClicks - a.totalClicks)
        .slice(0, 5);

      let topUsersText = '';
      if (usersWithClicks.length > 0) {
        topUsersText = '\n*🏆 ТОП-5 самых активных:*\n';
        usersWithClicks.forEach((user, index) => {
          const username = user.username ? (user.username.startsWith('@') ? user.username : `@${user.username}`) : user.first_name || 'Н/Д';
          topUsersText += `${index + 1}. ${username} - ${user.totalClicks} кликов\n`;
        });
      }

      const text = `📊 *Общая статистика пользователей*\n\n` +
        `👥 *Всего пользователей:* ${totalUsers}\n` +
        `   • С username: ${usersWithUsername}\n` +
        `   • Без username: ${usersWithoutUsername}\n\n` +
        `🤖 *Статус бота:*\n` +
        `   • Запустили: ${botStartedUsers}\n` +
        `   • Не запустили: ${botNotStartedUsers}\n\n` +
        `📈 *Активность:*\n` +
        `   • Активны за последнюю неделю: ${activeLastWeek}\n` +
        `   • Всего кликов: ${clicks.length}` +
        topUsersText;

      const keyboard = new InlineKeyboard().text('« Назад', 'admin_users');

      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });

    } catch (error) {
      console.error('[ADMIN_USERS_STATS] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'admin_users');
      await ctx.editMessageText(
        '❌ Ошибка при формировании статистики.',
        { reply_markup: keyboard }
      );
    }
  });

  // Обработчик для noop кнопок (пустая кнопка для пагинации)
  bot.callbackQuery('noop', async (ctx) => {
    await ctx.answerCallbackQuery();
  });

  // ═══════════════════════════════════════════════════════════════
  // ОТЧЕТЫ ПО ПАРТНЕРАМ (для администраторов)
  // ═══════════════════════════════════════════════════════════════

  // Список партнеров для выбора
  bot.callbackQuery('admin_partner_reports', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);

    if (!partners || partners.length === 0) {
      const keyboard = new InlineKeyboard().text('« Назад', 'admin_panel');
      await ctx.editMessageText(
        '📊 *Отчеты по партнерам*\n\n📭 Партнеров пока нет в таблице.',
        { parse_mode: 'Markdown', reply_markup: keyboard }
      );
      await ctx.answerCallbackQuery();
      return;
    }

    const keyboard = new InlineKeyboard();

    // Добавляем кнопки для каждого партнера (по 2 в ряд)
    partners.forEach((partner, index) => {
      const shortTitle = partner.title.length > 25 ? partner.title.substring(0, 25) + '...' : partner.title;
      keyboard.text(shortTitle, `admin_partner_select_${index}`);
      if (index % 2 === 1) keyboard.row();
    });

    if (partners.length % 2 === 1) keyboard.row();
    keyboard.text('« Назад', 'admin_panel');

    await ctx.editMessageText(
      '📊 *Отчеты по партнерам*\n\nВыберите партнера для отчета:',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Выбор периода отчета для партнера
  bot.callbackQuery(/^admin_partner_select_(\d+)$/, async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const partnerIndex = parseInt(ctx.match[1]);

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);

    if (!partners[partnerIndex]) {
      await ctx.answerCallbackQuery('❌ Партнер не найден');
      return;
    }

    const partner = partners[partnerIndex];

    const keyboard = new InlineKeyboard()
      .text('📅 За неделю', `admin_partner_period_${partnerIndex}_week`).row()
      .text('📊 За месяц', `admin_partner_period_${partnerIndex}_month`).row()
      .text('📈 За все время', `admin_partner_period_${partnerIndex}_all`).row()
      .text('« Назад', 'admin_partner_reports');

    await ctx.editMessageText(
      `📊 *Отчет по партнеру*\n\n` +
      `🏷️ *Партнер:* ${partner.title}\n` +
      `📁 *Категория:* ${partner.category || 'Не указана'}\n` +
      `📅 *Дата размещения:* ${partner.date_release || 'Не указана'}\n\n` +
      `Выберите период отчета:`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Генерация отчета за выбранный период
  bot.callbackQuery(/^admin_partner_period_(\d+)_(week|month|all)$/, async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }

    const partnerIndex = parseInt(ctx.match[1]);
    const period = ctx.match[2];

    await ctx.answerCallbackQuery('📊 Формирую отчет...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      if (!partners[partnerIndex]) {
        await ctx.answerCallbackQuery('❌ Партнер не найден');
        return;
      }

      const partner = partners[partnerIndex];
      const partnerClicks = clicks.filter(c => c.url === partner.url);

      if (partnerClicks.length === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', `admin_partner_select_${partnerIndex}`);
        await ctx.editMessageText(
          `📊 *Отчет по партнеру*\n\n` +
          `🏷️ *Партнер:* ${partner.title}\n\n` +
          `📭 По этой ссылке пока нет переходов.`,
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        return;
      }

      const now = new Date();
      let periodName = '';
      let filteredClicks = partnerClicks;

      // Фильтруем клики по периоду
      if (period === 'week') {
        const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        filteredClicks = partnerClicks.filter(c => {
          const clickDate = new Date(c.last_click_date || c.first_click_date);
          return clickDate >= oneWeekAgo;
        });
        periodName = 'За последнюю неделю';
      } else if (period === 'month') {
        const oneMonthAgo = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
        filteredClicks = partnerClicks.filter(c => {
          const clickDate = new Date(c.last_click_date || c.first_click_date);
          return clickDate >= oneMonthAgo;
        });
        periodName = `За последний месяц (${oneMonthAgo.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' })})`;
      } else {
        periodName = 'За все время';
      }

      // Рассчитываем статистику
      const totalClicks = filteredClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const uniqueUsers = new Set(filteredClicks.map(c => c.telegram_id)).size;
      const conversionRate = totalClicks > 0 ? ((uniqueUsers / totalClicks) * 100).toFixed(2) : '0.00';

      // Статистика по дням
      const dailyStats = {};
      filteredClicks.forEach(c => {
        const date = c.last_click_date || c.first_click_date;
        if (date) {
          dailyStats[date] = (dailyStats[date] || 0) + parseInt(c.click || 1);
        }
      });

      const topDays = Object.entries(dailyStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([date, clicks]) => `  • ${date}: ${clicks} кликов`)
        .join('\n');

      // Первый и последний клик
      const allDates = filteredClicks
        .map(c => new Date(c.first_click_date || c.last_click_date))
        .filter(d => !isNaN(d.getTime()))
        .sort((a, b) => a - b);

      const firstClick = allDates.length > 0 ? allDates[0].toLocaleDateString('ru-RU') : 'Н/Д';
      const lastClick = allDates.length > 0 ? allDates[allDates.length - 1].toLocaleDateString('ru-RU') : 'Н/Д';

      // Общая статистика за все время (для контекста)
      const allTimeTotalClicks = partnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const allTimeUniqueUsers = new Set(partnerClicks.map(c => c.telegram_id)).size;
      const allTimeConversion = allTimeTotalClicks > 0 ? ((allTimeUniqueUsers / allTimeTotalClicks) * 100).toFixed(2) : '0.00';

      let report = `📊 *Отчет по партнеру*\n` +
        `📅 *Период:* ${periodName}\n\n` +
        `🏷️ *Партнер:* ${partner.title}\n` +
        `📁 *Категория:* ${partner.category || 'Не указана'}\n` +
        `📅 *Дата размещения:* ${partner.date_release || 'Не указана'}\n` +
        `🔗 *Ссылка:* ${partner.url}\n`;

      if (partner.predstavitel) {
        report += `👤 *Представитель:* ${partner.predstavitel}\n`;
      }

      report += `\n*📈 Статистика за выбранный период:*\n` +
        `👥 Уникальных пользователей: ${uniqueUsers}\n` +
        `🖱️ Всего кликов: ${totalClicks}\n` +
        `📊 Конверсия: ${conversionRate}%\n`;

      if (totalClicks > 0) {
        report += `\n📅 *Первый клик:* ${firstClick}\n`;
        report += `📅 *Последний клик:* ${lastClick}\n`;
      }

      if (period !== 'all') {
        report += `\n*📈 Общая статистика (за все время):*\n` +
          `👥 Уникальных пользователей: ${allTimeUniqueUsers}\n` +
          `🖱️ Всего кликов: ${allTimeTotalClicks}\n` +
          `📊 Конверсия: ${allTimeConversion}%\n`;
      }

      if (topDays) {
        report += `\n*📅 Самые активные дни:*\n${topDays}\n`;
      }

      report += `\n_Отчет сформирован: ${now.toLocaleDateString('ru-RU')} ${now.toLocaleTimeString('ru-RU')}_`;

      const keyboard = new InlineKeyboard()
        .text('« К выбору периода', `admin_partner_select_${partnerIndex}`).row()
        .text('« К списку партнеров', 'admin_partner_reports').row()
        .text('« В админ-панель', 'admin_panel');

      await ctx.editMessageText(report, {
        parse_mode: 'Markdown',
        reply_markup: keyboard,
        disable_web_page_preview: true
      });

    } catch (error) {
      console.error('[ADMIN_PARTNER_REPORT] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'admin_partner_reports');
      await ctx.editMessageText(
        '❌ Ошибка при формировании отчета. Попробуйте позже.',
        { reply_markup: keyboard }
      );
    }
  });

  // Назад к старту
  bot.callbackQuery('back_to_start', async (ctx) => {
    const user = ctx.from;
    const isAdmin = await checkAdmin(env, user);
    const partnerData = await checkRepresentative(env, user);

    const keyboard = new InlineKeyboard()
      .webApp('🚀 Открыть Mini App', env.WEBAPP_URL);

    if (isAdmin) {
      keyboard.row().text('⚙️ Админ-панель', 'admin_panel');
    }

    if (partnerData) {
      keyboard.row().text('📊 Кабинет партнёра', 'representative_cabinet');
    }

    await ctx.editMessageText(
      `👋 Привет, *${user.first_name}*!\n\n` +
      `🔗 Жми кнопку и открывай приложение.\n\n` +
      `Внутри — уникальные промокоды, акции и контент.\n` +
      `⚠️ *Бота не останавливай*❌: сюда приходят самые жирные офферы.\n\n` +
      `🖤 Поехали 👇`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // ═══════════════════════════════════════════════════════════════
  // ЛИЧНЫЙ КАБИНЕТ ПРЕДСТАВИТЕЛЯ
  // ═══════════════════════════════════════════════════════════════

  // Главное меню личного кабинета
  bot.callbackQuery('representative_cabinet', async (ctx) => {
    const partnerData = await checkRepresentative(env, ctx.from);

    if (!partnerData) {
      await ctx.answerCallbackQuery('❌ Вы не являетесь представителем партнера');
      return;
    }

    const keyboard = new InlineKeyboard()
      .text('📅 Отчет за неделю', 'rep_weekly_report').row()
      .text('📊 Отчет за месяц', 'rep_monthly_report').row()
      .text('📈 Статистика рассылок', 'rep_broadcasts_stats').row()
      .text('« Назад', 'back_to_start');

    await ctx.editMessageText(
      `📊 *Кабинет партнёра*\n\n` +
      `🏷️ *Ваш партнер:* ${partnerData.title}\n` +
      `📁 *Категория:* ${partnerData.category || 'Не указана'}\n` +
      `📅 *Дата размещения:* ${partnerData.date_release || 'Не указана'}\n\n` +
      `Выберите тип отчета:`,
      {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      }
    );
    await ctx.answerCallbackQuery();
  });

  // Еженедельный отчет по запросу
  bot.callbackQuery('rep_weekly_report', async (ctx) => {
    const partnerData = await checkRepresentative(env, ctx.from);

    if (!partnerData) {
      await ctx.answerCallbackQuery('❌ Вы не являетесь представителем партнера');
      return;
    }

    await ctx.answerCallbackQuery('📊 Формирую отчет...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      // Собираем статистику ТОЛЬКО по этому партнеру
      const partnerClicks = clicks.filter(c => c.url === partnerData.url);

      if (partnerClicks.length === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
        await ctx.editMessageText(
          `📊 *Еженедельный отчет*\n\n` +
          `🏷️ *Партнер:* ${partnerData.title}\n\n` +
          `📭 По вашей ссылке пока нет переходов.`,
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        return;
      }

      const now = new Date();
      const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

      // Общая статистика
      const totalClicks = partnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const uniqueUsers = new Set(partnerClicks.map(c => c.telegram_id)).size;
      const conversionRate = totalClicks > 0 ? ((uniqueUsers / totalClicks) * 100).toFixed(2) : '0.00';

      // За неделю
      const weekClicks = partnerClicks.filter(c => {
        const clickDate = new Date(c.last_click_date || c.first_click_date);
        return clickDate >= oneWeekAgo;
      });
      const weekTotalClicks = weekClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const weekUniqueUsers = new Set(weekClicks.map(c => c.telegram_id)).size;

      const report = `📊 *Еженедельный отчет*\n\n` +
        `🏷️ *Ваш партнер:* ${partnerData.title}\n` +
        `📁 *Категория:* ${partnerData.category || 'Не указана'}\n` +
        `📅 *Дата размещения:* ${partnerData.date_release || 'Не указана'}\n` +
        `🔗 *Ссылка:* ${partnerData.url}\n\n` +
        `*📈 Общая статистика:*\n` +
        `👥 Уникальных пользователей: ${uniqueUsers}\n` +
        `🖱️ Всего кликов: ${totalClicks}\n` +
        `📊 Конверсия: ${conversionRate}%\n\n` +
        `*🗓️ За последнюю неделю:*\n` +
        `👥 Новых пользователей: ${weekUniqueUsers}\n` +
        `🖱️ Кликов: ${weekTotalClicks}\n\n` +
        `_Отчет сформирован: ${now.toLocaleDateString('ru-RU')} ${now.toLocaleTimeString('ru-RU')}_`;

      const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');

      await ctx.editMessageText(report, {
        parse_mode: 'Markdown',
        reply_markup: keyboard,
        disable_web_page_preview: true
      });

    } catch (error) {
      console.error('[REP_WEEKLY] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
      await ctx.editMessageText(
        '❌ Ошибка при формировании отчета. Попробуйте позже.',
        { reply_markup: keyboard }
      );
    }
  });

  // Ежемесячный отчет по запросу
  bot.callbackQuery('rep_monthly_report', async (ctx) => {
    const partnerData = await checkRepresentative(env, ctx.from);

    if (!partnerData) {
      await ctx.answerCallbackQuery('❌ Вы не являетесь представителем партнера');
      return;
    }

    await ctx.answerCallbackQuery('📊 Формирую отчет...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      // Собираем статистику ТОЛЬКО по этому партнеру
      const partnerClicks = clicks.filter(c => c.url === partnerData.url);

      if (partnerClicks.length === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
        await ctx.editMessageText(
          `📊 *Ежемесячный отчет*\n\n` +
          `🏷️ *Партнер:* ${partnerData.title}\n\n` +
          `📭 По вашей ссылке пока нет переходов.`,
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        return;
      }

      const now = new Date();
      const oneMonthAgo = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
      const previousMonthName = oneMonthAgo.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' });

      // Общая статистика
      const totalClicks = partnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const uniqueUsers = new Set(partnerClicks.map(c => c.telegram_id)).size;
      const conversionRate = totalClicks > 0 ? ((uniqueUsers / totalClicks) * 100).toFixed(2) : '0.00';

      // За месяц
      const monthClicks = partnerClicks.filter(c => {
        const clickDate = new Date(c.last_click_date || c.first_click_date);
        return clickDate >= oneMonthAgo;
      });
      const monthTotalClicks = monthClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const monthUniqueUsers = new Set(monthClicks.map(c => c.telegram_id)).size;
      const monthConversion = monthTotalClicks > 0 ? ((monthUniqueUsers / monthTotalClicks) * 100).toFixed(2) : '0.00';

      // ТОП-5 активных дней
      const dailyStats = {};
      monthClicks.forEach(c => {
        const date = c.last_click_date || c.first_click_date;
        if (date) {
          dailyStats[date] = (dailyStats[date] || 0) + parseInt(c.click || 1);
        }
      });
      const topDays = Object.entries(dailyStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([date, clicks]) => `  • ${date}: ${clicks} кликов`)
        .join('\n');

      const report = `📊 *Ежемесячный отчет*\n` +
        `📅 *Период:* ${previousMonthName}\n\n` +
        `🏷️ *Ваш партнер:* ${partnerData.title}\n` +
        `📁 *Категория:* ${partnerData.category || 'Не указана'}\n` +
        `📅 *Дата размещения:* ${partnerData.date_release || 'Не указана'}\n` +
        `🔗 *Ссылка:* ${partnerData.url}\n\n` +
        `*📈 Общая статистика (за все время):*\n` +
        `👥 Уникальных пользователей: ${uniqueUsers}\n` +
        `🖱️ Всего кликов: ${totalClicks}\n` +
        `📊 Конверсия: ${conversionRate}%\n\n` +
        `*🗓️ За последний месяц:*\n` +
        `👥 Новых пользователей: ${monthUniqueUsers}\n` +
        `🖱️ Кликов: ${monthTotalClicks}\n` +
        `📊 Конверсия за месяц: ${monthConversion}%\n\n` +
        (topDays ? `*📅 Самые активные дни месяца:*\n${topDays}\n\n` : '') +
        `_Отчет сформирован: ${now.toLocaleDateString('ru-RU')} ${now.toLocaleTimeString('ru-RU')}_`;

      const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');

      await ctx.editMessageText(report, {
        parse_mode: 'Markdown',
        reply_markup: keyboard,
        disable_web_page_preview: true
      });

    } catch (error) {
      console.error('[REP_MONTHLY] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
      await ctx.editMessageText(
        '❌ Ошибка при формировании отчета. Попробуйте позже.',
        { reply_markup: keyboard }
      );
    }
  });

  // Статистика рассылок для представителя
  bot.callbackQuery('rep_broadcasts_stats', async (ctx) => {
    const partnerData = await checkRepresentative(env, ctx.from);

    if (!partnerData) {
      await ctx.answerCallbackQuery('❌ Вы не являетесь представителем партнера');
      return;
    }

    await ctx.answerCallbackQuery('📊 Загружаю статистику...');

    try {
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);

      // Фильтруем рассылки только по партнеру представителя
      const partnerBroadcasts = broadcasts.filter(b => b.partner === partnerData.title);

      if (!partnerBroadcasts || partnerBroadcasts.length === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
        await ctx.editMessageText(
          `📈 *Статистика рассылок*\n\n` +
          `🏷️ *Партнер:* ${partnerData.title}\n\n` +
          `📭 По вашему партнеру пока не было рассылок.`,
          { parse_mode: 'Markdown', reply_markup: keyboard }
        );
        return;
      }

      // Сортируем по дате (новые сверху)
      partnerBroadcasts.sort((a, b) => {
        const dateA = new Date(a.date + ' ' + a.time);
        const dateB = new Date(b.date + ' ' + b.time);
        return dateB - dateA;
      });

      // Общая статистика
      const totalSent = partnerBroadcasts.reduce((sum, b) => sum + parseInt(b.sent_count || 0), 0);
      const totalClicks = partnerBroadcasts.reduce((sum, b) => sum + parseInt(b.click_count || 0), 0);
      const totalReads = partnerBroadcasts.reduce((sum, b) => sum + parseInt(b.read_count || 0), 0);
      const avgClickRate = totalReads > 0 ? ((totalClicks / totalReads) * 100).toFixed(2) : '0.00';

      let text = `📈 *Статистика рассылок*\n\n` +
        `🏷️ *Партнер:* ${partnerData.title}\n\n` +
        `*📊 Общая статистика:*\n` +
        `📧 Всего рассылок: ${partnerBroadcasts.length}\n` +
        `📬 Доставлено сообщений: ${totalSent}\n` +
        `👁️ Прочитано: ${totalReads}\n` +
        `🖱️ Кликов: ${totalClicks}\n` +
        `📊 Средний CTR: ${avgClickRate}%\n\n` +
        `*📋 Список рассылок:*\n\n`;

      // Показываем последние 5 рассылок
      const recentBroadcasts = partnerBroadcasts.slice(0, 5);
      recentBroadcasts.forEach((b, index) => {
        const clickRate = parseInt(b.read_count || 0) > 0
          ? ((parseInt(b.click_count || 0) / parseInt(b.read_count || 0)) * 100).toFixed(1)
          : '0.0';

        text += `${index + 1}. *${b.name || 'Без названия'}*\n`;
        text += `   📅 ${b.date} ${b.time}\n`;
        text += `   📬 Отправлено: ${b.sent_count || 0}\n`;
        text += `   🖱️ Кликов: ${b.click_count || 0} (${clickRate}%)\n`;
        if (b.title) text += `   📝 ${b.title.substring(0, 30)}${b.title.length > 30 ? '...' : ''}\n`;
        text += `\n`;
      });

      if (partnerBroadcasts.length > 5) {
        text += `_... и еще ${partnerBroadcasts.length - 5} рассылок_\n\n`;
      }

      text += `_Данные обновлены: ${new Date().toLocaleDateString('ru-RU')} ${new Date().toLocaleTimeString('ru-RU')}_`;

      const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');

      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });

    } catch (error) {
      console.error('[REP_BROADCASTS_STATS] Error:', error);
      const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
      await ctx.editMessageText(
        '❌ Ошибка при загрузке статистики. Попробуйте позже.',
        { reply_markup: keyboard }
      );
    }
  });

  // ═══════════════════════════════════════════════════════════════
  // ОБРАБОТКА ТЕКСТОВЫХ СООБЩЕНИЙ (для рассылки)
  // ═══════════════════════════════════════════════════════════════

  bot.on('message:text', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;

    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;

    const text = ctx.message.text;
    let keyboard;

    if (state.step === 'broadcast_name') {
      state.broadcast_name = text;
      state.step = 'partner_select';

      await saveBroadcastState(env, ctx.chat.id, state);

      // Получаем список партнеров
      const creds = JSON.parse(env.CREDENTIALS_JSON);
      const accessToken = await getAccessToken(env, creds);
      const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);

      keyboard = new InlineKeyboard();

      if (partners && partners.length > 0) {
        // Добавляем кнопки для партнеров (по 2 в ряд)
        partners.forEach((partner, index) => {
          const shortTitle = partner.title.length > 20 ? partner.title.substring(0, 20) + '...' : partner.title;
          keyboard.text(shortTitle, `broadcast_partner_${index}`);
          if (index % 2 === 1) keyboard.row();
        });
        if (partners.length % 2 === 1) keyboard.row();
      }

      keyboard.text('⏭️ Без партнера', 'broadcast_skip_partner').row()
        .text('❌ Отменить', 'broadcast_cancel');

      await ctx.reply(
        `📢 *Создание рассылки*\n\n*Шаг 2 из 6:* Выбор партнера\n\n✅ Название сохранено:\n"${text}"\n\n🏷️ Выберите партнера для этой рассылки или пропустите:`,
        { parse_mode: 'Markdown', reply_markup: keyboard }
      );

    } else if (state.step === 'title') {
      state.title = text;
      state.step = 'subtitle';
      keyboard = new InlineKeyboard()
        .text('⏭️ Пропустить', 'broadcast_skip_subtitle').row()
        .text('❌ Отменить', 'broadcast_cancel');

      await saveBroadcastState(env, ctx.chat.id, state);
      await ctx.reply(
        `📢 *Создание рассылки*\n\n*Шаг 4 из 6:* Подзаголовок\n\n✅ Заголовок сохранен:\n"${text}"\n\n📝 Введите *подзаголовок* (описание):`,
        { parse_mode: 'Markdown', reply_markup: keyboard }
      );

    } else if (state.step === 'subtitle') {
      state.subtitle = text;
      state.step = 'media';
      keyboard = new InlineKeyboard()
        .text('⏭️ Пропустить', 'broadcast_skip_image').row()
        .text('❌ Отменить', 'broadcast_cancel');

      await saveBroadcastState(env, ctx.chat.id, state);
      await ctx.reply(
        '📢 *Создание рассылки*\n\n*Шаг 5 из 6:* Медиа\n\n🖼️📹🎙️ *Прикрепите медиа* (фото/видео/голосовое/видеозаметку) или отправьте ссылку на фото/видео (URL):',
        { parse_mode: 'Markdown', reply_markup: keyboard }
      );

    } else if (state.step === 'media') {
      // Текстовый ввод воспринимаем как URL на фото/видео
      const url = text.trim();
      state.media_url = url;
      state.media_file_id = null;

      // Простая эвристика для определения типа
      const lower = url.toLowerCase();
      if (lower.endsWith('.mp4') || lower.includes('video')) {
        state.media_type = 'video';
      } else {
        state.media_type = 'photo';
      }

      state.step = 'button';
      keyboard = new InlineKeyboard()
        .text('⏭️ Пропустить', 'broadcast_skip_button').row()
        .text('❌ Отменить', 'broadcast_cancel');

      await saveBroadcastState(env, ctx.chat.id, state);
      await ctx.reply(
        '📢 *Создание рассылки*\n\n*Шаг 6 из 6:* Кнопка\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
        { parse_mode: 'Markdown', reply_markup: keyboard }
      );

    } else if (state.step === 'button') {
      const parts = text.split('|').map(p => p.trim());
      if (parts.length === 2) {
        state.button_text = parts[0];
        state.button_url = parts[1];
      }
      await showBroadcastPreview(ctx, env, state);
    }
  });

  // ═══════════════════════════════════════════════════════════════
  // ОБРАБОТКА МЕДИА (для рассылки)
  // ═══════════════════════════════════════════════════════════════

  // Фото
  bot.on('message:photo', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state || state.step !== 'media') return;

    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;

    const photos = ctx.message.photo;
    const largestPhoto = photos[photos.length - 1];
    state.media_type = 'photo';
    state.media_file_id = largestPhoto.file_id;
    state.media_url = null;
    state.step = 'button';

    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_button').row()
      .text('❌ Отменить', 'broadcast_cancel');

    await saveBroadcastState(env, ctx.chat.id, state);
    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 6 из 6:* Кнопка\n\n✅ Картинка загружена!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  // Видео
  bot.on('message:video', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state || state.step !== 'media') return;

    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;

    const video = ctx.message.video;
    state.media_type = 'video';
    state.media_file_id = video.file_id;
    state.media_url = null;
    state.step = 'button';

    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_button').row()
      .text('❌ Отменить', 'broadcast_cancel');

    await saveBroadcastState(env, ctx.chat.id, state);
    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 6 из 6:* Кнопка\n\n✅ Видео загружено!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  // Голосовое
  bot.on('message:voice', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state || state.step !== 'media') return;

    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;

    const voice = ctx.message.voice;
    state.media_type = 'voice';
    state.media_file_id = voice.file_id;
    state.media_url = null;
    state.step = 'button';

    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_button').row()
      .text('❌ Отменить', 'broadcast_cancel');

    await saveBroadcastState(env, ctx.chat.id, state);
    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 6 из 6:* Кнопка\n\n✅ Голосовое сообщение загружено!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  // Видеозаметка (круглое видео)
  bot.on('message:video_note', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state || state.step !== 'media') return;

    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;

    const videoNote = ctx.message.video_note;
    state.media_type = 'video_note';
    state.media_file_id = videoNote.file_id;
    state.media_url = null;
    state.step = 'button';

    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_button').row()
      .text('❌ Отменить', 'broadcast_cancel');

    await saveBroadcastState(env, ctx.chat.id, state);
    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 6 из 6:* Кнопка\n\n✅ Видеозаметка загружена!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  return bot;
}

// ═══════════════════════════════════════════════════════════════
// EXPRESS APP SETUP
// ═══════════════════════════════════════════════════════════════

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ═══════════════════════════════════════════════════════════════
// TELEGRAM BOT WEBHOOK
// ═══════════════════════════════════════════════════════════════

// Fixed webhook path (no token in URL for security)
app.post('/bot', async (req, res) => {
  try {
    const bot = setupBot(env);
    const handleUpdate = webhookCallback(bot, 'express');
    await handleUpdate(req, res);
  } catch (error) {
    console.error('[Webhook] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// BROADCAST CLICK TRACKING & REDIRECT
// ═══════════════════════════════════════════════════════════════

app.get('/r/:broadcastId/*', async (req, res) => {
  try {
    const { broadcastId } = req.params;
    const encodedPartnerUrl = req.params[0];
    const partnerUrl = decodeURIComponent(encodedPartnerUrl);

    console.log(`[REDIRECT] 📊 Broadcast click tracked: ${broadcastId}`);

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);

    // Update click_count in broadcasts sheet
    const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
    const broadcastIndex = broadcasts.findIndex(b => b.broadcast_id === broadcastId);

    if (broadcastIndex !== -1) {
      const broadcast = broadcasts[broadcastIndex];
      const newCount = parseInt(broadcast.click_count || 0) + 1;
      const rowIndex = broadcastIndex + 2;

      await updateSheetRow(
        env.SHEET_ID,
        'broadcasts',
        rowIndex,
        [
          broadcast.broadcast_id,
          broadcast.partner || '',
          broadcast.title || '',
          broadcast.sent_at || '',
          broadcast.user_count || '0',
          String(newCount), // click_count
          broadcast.subtitle || '',
          broadcast.image_url || '',
          broadcast.button_text || '',
          broadcast.button_url || ''
        ],
        accessToken
      );

      console.log(`[REDIRECT] ✅ Click count updated: ${newCount} for broadcast ${broadcastId}`);
    }

    // Redirect to partner URL
    res.redirect(partnerUrl);
  } catch (error) {
    console.error('[REDIRECT] Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════════
// API ENDPOINTS
// ═══════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    redis: redis.status === 'ready' ? 'connected' : 'disconnected'
  });
});

// Get partners
app.get('/api/partners', async (req, res) => {
  try {
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);

    // Filter and format partners
    const formattedPartners = partners
      .filter(p => p.title && p.url)
      .map(p => ({
        id: p.id || p.title,
        title: p.title,
        url: p.url,
        logo: p.logo || '',
        description: p.description || '',
        category: p.category || 'Другое',
        promocode: p.promocode || '',
        predstavitel: p.predstavitel || ''
      }));

    res.json({
      ok: true,
      partners: formattedPartners
    });
  } catch (error) {
    console.error('[API] Error getting partners:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Track click
app.post('/api/click', async (req, res) => {
  try {
    const { partner_id, user_id, username, partner_url } = req.body;

    if (!partner_id || !user_id) {
      return res.status(400).json({ error: 'Missing required fields', success: false });
    }

    // Rate limiting
    await checkRateLimit(env, `click:${user_id}:${partner_id}`, 10, 60);

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);

    // Get partners to find partner title
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    const partner = partners.find(p => (p.id || p.title) === partner_id);

    if (!partner) {
      return res.status(404).json({ error: 'Partner not found', success: false });
    }

    // Get clicks sheet
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

    // Check if user already clicked this partner
    const existingClickIndex = clicks.findIndex(c =>
      String(c.user_id) === String(user_id) &&
      c.partner === partner.title
    );

    const currentTimestamp = new Date().toISOString();

    if (existingClickIndex !== -1) {
      // Update existing click
      const existingClick = clicks[existingClickIndex];
      const newCount = parseInt(existingClick.click_count || 1) + 1;
      const rowIndex = existingClickIndex + 2;

      await updateSheetRow(
        env.SHEET_ID,
        'clicks',
        rowIndex,
        [
          user_id,
          username || '',
          partner.title,
          String(newCount),
          currentTimestamp,
          partner_url || partner.url
        ],
        accessToken
      );

      console.log(`[API] 🔄 Updated click for user ${user_id} on partner ${partner.title}: count=${newCount}`);
    } else {
      // Add new click record
      await appendSheetRow(
        env.SHEET_ID,
        'clicks',
        [
          user_id,
          username || '',
          partner.title,
          '1', // click_count
          currentTimestamp,
          partner_url || partner.url
        ],
        accessToken
      );

      console.log(`[API] 🆕 New click registered: user ${user_id} on partner ${partner.title}`);
    }

    // Send promocode if available
    if (partner.promocode && partner.promocode.trim() !== '') {
      try {
        const bot = new Bot(env.BOT_TOKEN);
        const message = `🎁 <b>Промокод от ${partner.title}</b>\n\n` +
          `<code>${partner.promocode}</code>\n\n` +
          `Скопируйте промокод и используйте его на сайте партнера!\n\n` +
          `<i>Это сообщение будет автоматически удалено через 24 часа</i>`;

        const sentMessage = await bot.api.sendMessage(user_id, message, { parse_mode: 'HTML' });

        // Save message info for auto-deletion
        const deleteAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        await env.BROADCAST_STATE.put(
          `promo_msg_${user_id}_${Date.now()}`,
          JSON.stringify({
            chat_id: user_id,
            message_id: sentMessage.message_id,
            partner: partner.title,
            delete_at: deleteAt
          }),
          { expirationTtl: 86400 } // 24 hours
        );

        console.log(`[PROMOCODE] ✅ Sent promocode from ${partner.title} to user ${user_id}`);
      } catch (error) {
        console.error(`[PROMOCODE] ❌ Failed to send promocode:`, {
          error_code: error.error_code,
          description: error.description,
          message: error.message
        });
      }
    }

    // Return click count
    const clickCount = existingClickIndex !== -1
      ? parseInt(clicks[existingClickIndex].click_count || 1) + 1
      : 1;

    res.json({
      ok: true,
      success: true,
      clicks: clickCount,
      promocode_sent: !!(partner.promocode && partner.promocode.trim() !== '')
    });
  } catch (error) {
    console.error('[API] Error tracking click:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Register/update user
app.post('/api/user', async (req, res) => {
  try {
    const { id, username, first_name } = req.body;

    if (!id) {
      return res.status(400).json({ error: 'Missing user id', success: false });
    }

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const existing = users.find(u => String(u.telegram_id) === String(id));
    const currentDate = new Date().toISOString().split('T')[0];

    if (!existing) {
      // Add new user
      await appendSheetRow(
        env.SHEET_ID,
        'users',
        [
          id,
          username || 'N/A',
          first_name || 'Unknown',
          currentDate,  // date_registered
          'бот запущен',  // bot_started
          currentDate   // last_active
        ],
        accessToken
      );
      console.log(`[API] 🆕 New user registered via API: ${id}`);
    } else {
      // Update existing user
      const userIndex = users.findIndex(u => String(u.telegram_id) === String(id));
      if (userIndex !== -1) {
        const rowIndex = userIndex + 2;
        await updateSheetRow(
          env.SHEET_ID,
          'users',
          rowIndex,
          [
            id,
            username || existing.username || 'N/A',
            first_name || existing.first_name || 'Unknown',
            existing.date_registered || currentDate,
            'бот запущен',  // bot_started
            currentDate  // last_active (update)
          ],
          accessToken
        );
        console.log(`[API] 🔄 User updated via API: ${id}`);
      }
    }

    res.json({ ok: true, registered: !existing });
  } catch (error) {
    console.error('[API] Error with user:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Check if user is admin
app.post('/api/me', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.json({ isAdmin: false });
    }

    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
    const isAdmin = admins.some(a => a.username && a.username.toLowerCase() === username.toLowerCase());

    res.json({ isAdmin });
  } catch (error) {
    console.error('[API] Error checking admin:', error);
    res.status(500).json({ error: error.message, isAdmin: false });
  }
});

// Get subscriber count
app.get('/api/subscribers', async (req, res) => {
  try {
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);

    res.json({
      total: users.length,
      subscribed: users.filter(u => u.subscribed === 'TRUE').length,
    });
  } catch (error) {
    console.error('[API] Error getting subscribers:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found', success: false });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('[Express] Error:', error);
  res.status(500).json({ error: error.message || 'Internal server error', success: false });
});

// ═══════════════════════════════════════════════════════════════
// CRON JOBS
// ═══════════════════════════════════════════════════════════════

// Every 5 minutes: Check users and delete old promocodes
cron.schedule('*/5 * * * *', async () => {
  console.log('[CRON] ⏰ Running 5-minute tasks at:', new Date().toISOString());

  try {
    // Check all users
    const usersResult = await checkAllUsers(env);
    console.log('[CRON] 📊 Users check result:', usersResult);

    // Delete old promocodes
    const promoResult = await deleteOldPromocodes(env);
    console.log('[CRON] 🗑️ Promocodes cleanup result:', promoResult);
  } catch (error) {
    console.error('[CRON] ❌ Error in 5-minute tasks:', error);
  }
});

// Monday 10:00 UTC: Weekly partner reports
cron.schedule('0 10 * * 1', async () => {
  console.log('[CRON] 📊 Sending weekly partner reports at:', new Date().toISOString());

  try {
    const result = await sendWeeklyPartnerReports(env);
    console.log('[CRON] 📧 Weekly reports result:', result);
  } catch (error) {
    console.error('[CRON] ❌ Error in weekly reports:', error);
  }
});

// 1st of month 12:00 UTC: Monthly partner reports
cron.schedule('0 12 1 * *', async () => {
  console.log('[CRON] 📊 Sending monthly partner reports at:', new Date().toISOString());

  try {
    const result = await sendMonthlyPartnerReports(env);
    console.log('[CRON] 📧 Monthly reports result:', result);
  } catch (error) {
    console.error('[CRON] ❌ Error in monthly reports:', error);
  }
});

// ═══════════════════════════════════════════════════════════════
// SERVER START
// ═══════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('🚀 Express Server Started');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`📡 Server listening on port ${PORT}`);
  console.log(`🤖 Bot webhook: /bot (Telegram will POST here)`);
  console.log(`🔗 API available at: http://localhost:${PORT}/api/*`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log('═══════════════════════════════════════════════════════════════');
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n[Server] Shutting down gracefully...');
  await redis.quit();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n[Server] Shutting down gracefully...');
  await redis.quit();
  process.exit(0);
});
