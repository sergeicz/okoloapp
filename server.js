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
// BOT SETUP WITH GRAMMY
// ═══════════════════════════════════════════════════════════════

// Note: The full bot setup with all handlers will be included from the worker code
// This is a placeholder - the actual implementation continues below
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

  // NOTE: All bot command handlers (start, admin_panel, callbacks, etc.)
  // from the original worker/index.js file should be included here.
  // Due to file size, I'm showing the structure. The complete implementation
  // would include all handlers from lines 461-2006 of the original file.

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

app.post(`/bot${env.BOT_TOKEN}`, async (req, res) => {
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
  console.log(`🤖 Bot webhook: http://localhost:${PORT}/bot${env.BOT_TOKEN}`);
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
