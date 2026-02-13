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

// Cached parsed credentials to avoid repeated JSON.parse on every request
const parsedCredentials = JSON.parse(env.CREDENTIALS_JSON);

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

  // Log for debugging and throw error if API returned error
  if (result.error) {
    console.error(`[appendSheetRow] ❌ Error appending to sheet "${sheetName}":`, result.error);
    throw new Error(`Google Sheets API error: ${result.error.message || JSON.stringify(result.error)}`);
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
    const member = await globalBot.api.getChatMember(userId, userId);
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

  const creds = parsedCredentials;
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

  const creds = parsedCredentials;
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

    // Admins can also be partner representatives
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const partners = await getCachedPartners(env);

    // Normalize user username (remove @ and lowercase)
    const normalizedUsername = user.username.toLowerCase().replace('@', '').trim();

    // Find partner where this user is representative
    const partnerData = partners.find(p => {
      if (!p.predstavitel) return false;

      // Split multiple representatives if they exist and normalize each
      const representatives = p.predstavitel.split(',').map(rep => rep.trim()).filter(rep => rep);
      
      // Normalize each representative from table (remove @ and lowercase)
      const normalizedRepresentatives = representatives.map(rep => rep.toLowerCase().replace('@', '').trim());

      return normalizedRepresentatives.includes(normalizedUsername);
    });

    console.log(`Representative check for ${user.username} (normalized: ${normalizedUsername}):`, partnerData ? partnerData.title : 'not found');
    return partnerData || null;
  } catch (error) {
    console.error('Error checking representative:', error);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// USER AVATAR FUNCTIONS
// ═══════════════════════════════════════════════════════════════

// Get user profile photo URL via Telegram Bot API
async function getUserAvatarUrl(userId) {
  try {
    // Create bot instance (used during startup before globalBot is initialized)
    const bot = new Bot(env.BOT_TOKEN);

    // Get user profile photos
    const photos = await bot.api.getUserProfilePhotos(userId, { limit: 1 });

    if (!photos || !photos.photos || photos.photos.length === 0) {
      console.log(`[AVATAR] No profile photo for user ${userId}`);
      return null;
    }

    // Get the largest photo (last in array)
    const photo = photos.photos[0];
    const largestPhoto = photo[photo.length - 1];

    // Get file info to get the file_path
    const file = await bot.api.getFile(largestPhoto.file_id);

    // Construct the file URL
    const fileUrl = `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${file.file_path}`;

    console.log(`[AVATAR] ✅ Got avatar URL for user ${userId}: ${fileUrl}`);
    return fileUrl;
  } catch (error) {
    console.error(`[AVATAR] ❌ Error getting avatar for user ${userId}:`, error.message);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// INITIALIZATION AND SETUP FUNCTIONS
// ═══════════════════════════════════════════════════════════════

// Initialize required sheets in Google Spreadsheet
async function initializeRequiredSheets(env) {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    
    // Get all existing sheet names
    const allSheetNames = await getAllSheetNames(env.SHEET_ID, accessToken);
    
    // Define required sheets and their headers
    const requiredSheets = [
      {
        name: 'achievements',
        headers: ['id', 'slug', 'title', 'description', 'points', 'rarity', 'icon_emoji', 'condition_type', 'condition_value', 'is_active']
      },
      {
        name: 'user_achievements',
        headers: ['telegram_id', 'achievement_id', 'progress', 'is_unlocked', 'unlocked_at', 'created_at', 'updated_at']
      },
      {
        name: 'referrals',
        headers: ['referrer_id', 'referred_id', 'points_awarded', 'is_active', 'created_at']
      },
      {
        name: 'daily_activity',
        headers: ['telegram_id', 'activity_date', 'actions_count', 'created_at']
      }
    ];
    
    // Check and create missing sheets
    for (const sheetInfo of requiredSheets) {
      if (!allSheetNames.includes(sheetInfo.name)) {
        console.log(`[INIT] Creating missing sheet: ${sheetInfo.name}`);
        
        // Add header row
        const range = `${sheetInfo.name}!A1:${String.fromCharCode(64 + sheetInfo.headers.length)}`;
        const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEET_ID}/values/${range}?valueInputOption=RAW`;
        
        await fetch(url, {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            values: [sheetInfo.headers]
          }),
        });
        
        console.log(`[INIT] ✅ Created sheet: ${sheetInfo.name} with headers: ${sheetInfo.headers.join(', ')}`);
      } else {
        console.log(`[INIT] Sheet already exists: ${sheetInfo.name}`);
      }
    }
    
    // Initialize default achievements if the achievements sheet is empty
    const achievements = await getSheetData(env.SHEET_ID, 'achievements', accessToken);
    if (!achievements || achievements.length === 0) {
      console.log('[INIT] Adding default achievements to sheet...');
      
      const defaultAchievements = [
        [
          'молодой_хомяк', 'молодой_хомяк', '🎯 Молодой хомяк', 
          'Открыл первую партнёрскую ссылку', '10', 'Обычное', '🎯', 
          'partner_click', '1', 'TRUE'
        ],
        [
          'прошаренный_хомяк', 'прошаренный_хомяк', '⭐ Прошаренный хомяк', 
          'Подписался на всех партнёров', '50', 'Редкое', '⭐', 
          'partner_subscribe_all', '', 'TRUE'
        ],
        [
          'активный_хомяк', 'активный_хомяк', '🔥 Активный хомяк', 
          '7 дней активности подряд', '30', 'Необычное', '🔥', 
          'daily_streak', '7', 'TRUE'
        ],
        [
          'проактивный_хомяк', 'проактивный_хомяк', '👑 Проактивный хомяк', 
          'Пригласили 10+ друзей', '100', 'Эпическое', '👑', 
          'referral_count', '10', 'TRUE'
        ],
        [
          'любознательный_хомяк', 'любознательный_хомяк', '📚 Любознательный хомяк', 
          'Просмотрел 5+ образовачей', '50', 'Редкое', '📚', 
          'education_view', '5', 'TRUE'
        ],
        [
          'щедрый_хомяк', 'щедрый_хомяк', '💳 Щедрый хомяк', 
          'Задонатил пацанам', '20', 'Необычное', '💳', 
          'donation', '1000', 'TRUE'
        ],
        [
          'хомяк_тусовщик', 'хомяк_тусовщик', '🎪 Хомяк-тусовщик', 
          'Посетил тату-событие', '15', 'Обычное', '🎪', 
          'event_register', '1', 'TRUE'
        ],
        [
          'легендарный_хомяк', 'легендарный_хомяк', '🚀 Легендарный хомяк', 
          'Один из первых 100 пользователей', '100', 'Легендарное', '🚀', 
          'early_user', '100', 'TRUE'
        ]
      ];
      
      // Add default achievements to the sheet
      for (const achievement of defaultAchievements) {
        await appendSheetRow(env.SHEET_ID, 'achievements', achievement, accessToken);
      }
      
      console.log('[INIT] ✅ Added default achievements to sheet');
    }
  } catch (error) {
    console.error('[INIT] Error initializing required sheets:', error);
  }
}

// ═══════════════════════════════════════════════════════════════
// ACHIEVEMENT SYSTEM FUNCTIONS
// ═══════════════════════════════════════════════════════════════

// Initialize achievements from Google Sheets
async function initializeAchievements(env) {
  const cacheKey = 'achievements:list';
  
  // Check if achievements are already cached
  const cached = await env.BROADCAST_STATE.get(cacheKey);
  if (cached) {
    return JSON.parse(cached);
  }

  try {
    // Try to fetch from Google Sheets
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const sheetAchievements = await getSheetData(env.SHEET_ID, 'achievements', accessToken);
    
    if (sheetAchievements && sheetAchievements.length > 0) {
      // Convert sheet data to our format
      const achievements = sheetAchievements.map(item => ({
        id: item.id || item.slug,
        slug: item.slug,
        title: item.title,
        description: item.description,
        points: parseInt(item.points) || 0,
        rarity: item.rarity || 'Обычное',
        icon_emoji: item.icon_emoji || '',
        condition_type: item.condition_type,
        condition_value: item.condition_value ? parseInt(item.condition_value) : null
      }));
      
      // Cache for 1 hour
      await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(achievements), { expirationTtl: 3600 });
      
      return achievements;
    }
  } catch (error) {
    console.error('Error fetching achievements from Google Sheets:', error);
  }

  // Fallback to default achievements if sheet is empty or unavailable
  const defaultAchievements = [
    {
      id: 'молодой_хомяк',
      slug: 'молодой_хомяк',
      title: '🎯 Молодой хомяк',
      description: 'Открыл первую партнёрскую ссылку',
      points: 10,
      rarity: 'Обычное',
      icon_emoji: '🎯',
      condition_type: 'partner_click',
      condition_value: 1
    },
    {
      id: 'прошаренный_хомяк',
      slug: 'прошаренный_хомяк',
      title: '⭐ Прошаренный хомяк',
      description: 'Подписался на всех партнёров',
      points: 50,
      rarity: 'Редкое',
      icon_emoji: '⭐',
      condition_type: 'partner_subscribe_all',
      condition_value: null
    },
    {
      id: 'активный_хомяк',
      slug: 'активный_хомяк',
      title: '🔥 Активный хомяк',
      description: '7 дней активности подряд',
      points: 30,
      rarity: 'Необычное',
      icon_emoji: '🔥',
      condition_type: 'daily_streak',
      condition_value: 7
    },
    {
      id: 'проактивный_хомяк',
      slug: 'проактивный_хомяк',
      title: '👑 Проактивный хомяк',
      description: 'Пригласили 10+ друзей',
      points: 100,
      rarity: 'Эпическое',
      icon_emoji: '👑',
      condition_type: 'referral_count',
      condition_value: 10
    },
    {
      id: 'любознательный_хомяк',
      slug: 'любознательный_хомяк',
      title: '📚 Любознательный хомяк',
      description: 'Просмотрел 5+ образовачей',
      points: 50,
      rarity: 'Редкое',
      icon_emoji: '📚',
      condition_type: 'education_view',
      condition_value: 5
    },
    {
      id: 'щедрый_хомяк',
      slug: 'щедрый_хомяк',
      title: '💳 Щедрый хомяк',
      description: 'Задонатил пацанам',
      points: 20,
      rarity: 'Необычное',
      icon_emoji: '💳',
      condition_type: 'donation',
      condition_value: 1000
    },
    {
      id: 'хомяк_тусовщик',
      slug: 'хомяк_тусовщик',
      title: '🎪 Хомяк-тусовщик',
      description: 'Посетил тату-событие',
      points: 15,
      rarity: 'Обычное',
      icon_emoji: '🎪',
      condition_type: 'event_register',
      condition_value: 1
    },
    {
      id: 'легендарный_хомяк',
      slug: 'легендарный_хомяк',
      title: '🚀 Легендарный хомяк',
      description: 'Один из первых 100 пользователей',
      points: 100,
      rarity: 'Легендарное',
      icon_emoji: '🚀',
      condition_type: 'early_user',
      condition_value: 100
    }
  ];

  // Cache for 1 hour
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(defaultAchievements), { expirationTtl: 3600 });
  
  return defaultAchievements;
}

// Get user's achievement progress
async function getUserAchievementProgress(env, userId, achievementId) {
  const cacheKey = `user_achievement:${userId}:${achievementId}`;
  const cached = await env.BROADCAST_STATE.get(cacheKey);
  
  if (cached) {
    return JSON.parse(cached);
  }
  
  try {
    // Try to fetch from Google Sheets
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const userAchievements = await getSheetData(env.SHEET_ID, 'user_achievements', accessToken);
    
    const userAchievement = userAchievements.find(ua => 
      String(ua.telegram_id) === String(userId) && 
      String(ua.achievement_id) === String(achievementId)
    );
    
    if (userAchievement) {
      const progress = {
        telegram_id: userId,
        achievement_id: achievementId,
        progress: parseInt(userAchievement.progress) || 0,
        is_unlocked: userAchievement.is_unlocked === 'TRUE' || userAchievement.is_unlocked === true,
        unlocked_at: userAchievement.unlocked_at || null,
        created_at: userAchievement.created_at || new Date().toISOString()
      };
      
      // Cache for 1 hour
      await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(progress), { expirationTtl: 3600 });
      
      return progress;
    }
  } catch (error) {
    console.error(`Error fetching achievement progress for user ${userId}, achievement ${achievementId}:`, error);
  }
  
  // Return default if not found in sheets
  const defaultProgress = {
    telegram_id: userId,
    achievement_id: achievementId,
    progress: 0,
    is_unlocked: false,
    unlocked_at: null,
    created_at: new Date().toISOString()
  };
  
  return defaultProgress;
}

// Update user's achievement progress
async function updateUserAchievementProgress(env, userId, achievementId, progress, isUnlocked = false) {
  const cacheKey = `user_achievement:${userId}:${achievementId}`;

  const achievementData = {
    telegram_id: userId,
    achievement_id: achievementId,
    progress: progress,
    is_unlocked: isUnlocked,
    unlocked_at: isUnlocked ? new Date().toISOString() : null,
    updated_at: new Date().toISOString()
  };

  let wasAlreadyUnlocked = false;

  try {
    // Try to update Google Sheets
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const userAchievements = await getSheetData(env.SHEET_ID, 'user_achievements', accessToken);

    const existingIndex = userAchievements.findIndex(ua =>
      String(ua.telegram_id) === String(userId) &&
      String(ua.achievement_id) === String(achievementId)
    );

    if (existingIndex !== -1) {
      // Check if it was already unlocked before this update
      const existingRecord = userAchievements[existingIndex];
      wasAlreadyUnlocked = existingRecord.is_unlocked === 'TRUE' || existingRecord.is_unlocked === true;

      // Update existing record
      const rowIndex = existingIndex + 2; // +2 because: +1 for header, +1 for 1-based index
      await updateSheetRow(
        env.SHEET_ID,
        'user_achievements',
        rowIndex,
        [
          userId,
          achievementId,
          String(progress),
          isUnlocked ? 'TRUE' : 'FALSE',
          wasAlreadyUnlocked ? existingRecord.unlocked_at : (achievementData.unlocked_at || ''),
          achievementData.updated_at
        ],
        accessToken
      );
    } else {
      // Add new record
      await appendSheetRow(
        env.SHEET_ID,
        'user_achievements',
        [
          userId,
          achievementId,
          String(progress),
          isUnlocked ? 'TRUE' : 'FALSE',
          achievementData.unlocked_at || '',
          achievementData.created_at || achievementData.updated_at
        ],
        accessToken
      );
    }
  } catch (error) {
    console.error(`Error updating achievement progress for user ${userId}, achievement ${achievementId}:`, error);
  }

  // Cache for 1 hour
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(achievementData), { expirationTtl: 3600 });

  // Award points and send notification ONLY if this is a NEW unlock (wasn't unlocked before)
  if (isUnlocked && !wasAlreadyUnlocked) {
    await awardPointsToUser(env, userId, achievementId);
    console.log(`[ACHIEVEMENT] 🆕 NEW unlock for user ${userId}, achievement ${achievementId} - awarding points`);
  } else if (isUnlocked && wasAlreadyUnlocked) {
    console.log(`[ACHIEVEMENT] ⏭️ Achievement ${achievementId} already unlocked for user ${userId} - skipping award`);
  }

  return achievementData;
}

// Award points to user when achievement is unlocked
async function awardPointsToUser(env, userId, achievementId) {
  const achievements = await initializeAchievements(env);
  const achievement = achievements.find(a => a.id === achievementId);
  
  if (!achievement || !achievement.points) {
    return 0;
  }
  
  // Check if user is an admin - if so, don't award points
  const creds = parsedCredentials;
  const accessToken = await getAccessToken(env, creds);
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
  
  const isAdmin = admins.some(a => {
    const idMatch = a.telegram_id && String(a.telegram_id) === String(userId);
    return idMatch;
  });
  
  // Don't award points to admins, but still send notification about achievement
  if (isAdmin) {
    console.log(`[ACHIEVEMENT] Admin user ${userId} achieved ${achievementId} but not receiving points`);
    
    // Still send notification about achievement without points
    try {
        const achievementTitle = achievement.title;
      const achievementDescription = achievement.description;
      
      const message = `🎉 Поздравляем! Новое достижение!\n\n${achievementTitle}\n━━━━━━━━━━━\n${achievementDescription}\n\n🏆 Редкость: ${achievement.rarity}\n⭐ (как админ, вы не получаете баллы за достижения)`;
      
      await globalBot.api.sendMessage(userId, message);
    } catch (error) {
      console.error(`Failed to send achievement notification to admin user ${userId}:`, error);
    }
    
    return 0;
  }
  
  // Update user's total points (for non-admins)
  const currentStats = await getUserStats(env, userId);
  const newTotalPoints = (currentStats.total_points || 0) + achievement.points;
  
  await updateUserStats(env, userId, { total_points: newTotalPoints });
  
  // Send notification to user
  try {
    const achievementTitle = achievement.title;
    const achievementDescription = achievement.description;
    const pointsAwarded = achievement.points;
    const totalPoints = newTotalPoints;
    
    const message = `🎉 Поздравляем! Новое достижение!\n\n${achievementTitle}\n━━━━━━━━━━━\n${achievementDescription}\n\n🏆 Редкость: ${achievement.rarity}\n⭐ Награда: +${pointsAwarded} баллов\n\nВаш новый рейтинг: ${totalPoints} баллов`;
    
    await globalBot.api.sendMessage(userId, message);
  } catch (error) {
    console.error(`Failed to send achievement notification to user ${userId}:`, error);
  }
  
  return achievement.points;
}

// Get user statistics
async function getUserStats(env, userId) {
  const cacheKey = `user_stats:${userId}`;
  const cached = await env.BROADCAST_STATE.get(cacheKey);
  
  if (cached) {
    return JSON.parse(cached);
  }
  
  // Fetch from users sheet as fallback
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    
    const user = users.find(u => String(u.telegram_id) === String(userId));
    
    if (user) {
      const stats = {
        telegram_id: userId,
        total_points: !isNaN(parseInt(user.total_points)) ? parseInt(user.total_points) : 0,
        current_streak: !isNaN(parseInt(user.current_streak)) ? parseInt(user.current_streak) : 0,
        longest_streak: !isNaN(parseInt(user.longest_streak)) ? parseInt(user.longest_streak) : 0,
        last_active_date: user.last_active_date || user.last_active || new Date().toISOString().split('T')[0],
        referrals_count: !isNaN(parseInt(user.referrals_count)) ? parseInt(user.referrals_count) : 0,
        education_views_count: !isNaN(parseInt(user.education_views_count)) ? parseInt(user.education_views_count) : 0,
        events_registered: !isNaN(parseInt(user.events_registered)) ? parseInt(user.events_registered) : 0,
        partners_subscribed: !isNaN(parseInt(user.partners_subscribed)) ? parseInt(user.partners_subscribed) : 0,
        total_donations: !isNaN(parseInt(user.total_donations)) ? parseInt(user.total_donations) : 0,
        date_registered: user.date_registered || new Date().toISOString().split('T')[0],
        updated_at: new Date().toISOString()
      };

      // Cache for 10 minutes
      try {
        await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(stats), { expirationTtl: 600 });
      } catch (cacheError) {
        console.error(`Error caching stats for ${userId}:`, cacheError);
      }

      return stats;
    }
  } catch (error) {
    console.error(`Error getting user stats for ${userId}:`, error);
  }
  
  // Return default stats if not found
  return {
    telegram_id: userId,
    total_points: 0,
    current_streak: 0,
    longest_streak: 0,
    last_active_date: new Date().toISOString().split('T')[0],
    referrals_count: 0,
    education_views_count: 0,
    events_registered: 0,
    partners_subscribed: 0,
    total_donations: 0,
    date_registered: new Date().toISOString().split('T')[0],
    updated_at: new Date().toISOString()
  };
}

// Update user statistics
async function updateUserStats(env, userId, updates) {
  // Check if user is an admin - if so, only update non-points stats
  const creds = parsedCredentials;
  const accessToken = await getAccessToken(env, creds);
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
  
  const isAdmin = admins.some(a => {
    const idMatch = a.telegram_id && String(a.telegram_id) === String(userId);
    return idMatch;
  });
  
  // If user is admin, remove points-related updates
  let filteredUpdates = { ...updates };
  if (isAdmin) {
    // Remove points-related fields from updates
    if ('total_points' in filteredUpdates) {
      delete filteredUpdates.total_points;
    }
    if ('referrals_count' in filteredUpdates) {
      delete filteredUpdates.referrals_count;
    }
    
    console.log(`[USER STATS] Partial update for admin user ${userId} (excluding points)`);
  }
  
  const currentStats = await getUserStats(env, userId);
  const newStats = { ...currentStats, ...filteredUpdates, updated_at: new Date().toISOString() };
  
  // Update cache
  const cacheKey = `user_stats:${userId}`;
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(newStats), { expirationTtl: 600 });
  
  // Update Google Sheet as well
  try {
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    
    const userIndex = users.findIndex(u => String(u.telegram_id) === String(userId));
    
    if (userIndex !== -1) {
      // Update the user row in the sheet
      const user = users[userIndex];
      const rowIndex = userIndex + 2; // +2 because: +1 for header, +1 for 1-based index
      
      await updateSheetRow(
        env.SHEET_ID,
        'users',
        rowIndex,
        [
          user.telegram_id,
          user.username || '',
          user.first_name || '',
          user.date_registered || new Date().toISOString().split('T')[0],
          user.bot_started || 'бот запущен',
          user.last_active || new Date().toISOString().split('T')[0],
          isAdmin ? user.total_points || '0' : String(newStats.total_points || 0), // Keep admin's points unchanged
          String(newStats.current_streak || 0),
          String(newStats.longest_streak || 0),
          user.last_active_date || new Date().toISOString().split('T')[0],
          isAdmin ? user.referrals_count || '0' : String(newStats.referrals_count || 0), // Keep admin's referrals unchanged
          String(newStats.education_views_count || 0),
          String(newStats.events_registered || 0),
          String(newStats.partners_subscribed || 0),
          String(newStats.total_donations || 0),
          String(newStats.registration_number || ''),
        ],
        accessToken
      );
    } else {
      // If user doesn't exist in sheet, add them
      await appendSheetRow(
        env.SHEET_ID,
        'users',
        [
          userId,
          '', // username
          '', // first_name
          new Date().toISOString().split('T')[0], // date_registered
          'бот запущен', // bot_started
          new Date().toISOString().split('T')[0], // last_active
          isAdmin ? '0' : String(newStats.total_points || 0), // Admin starts with 0 points
          String(newStats.current_streak || 0),
          String(newStats.longest_streak || 0),
          new Date().toISOString().split('T')[0], // last_active_date
          isAdmin ? '0' : String(newStats.referrals_count || 0), // Admin starts with 0 referrals
          String(newStats.education_views_count || 0),
          String(newStats.events_registered || 0),
          String(newStats.partners_subscribed || 0),
          String(newStats.total_donations || 0),
          String(newStats.registration_number || ''),
        ],
        accessToken
      );
    }
  } catch (error) {
    console.error(`Error updating user stats in sheet for ${userId}:`, error);
  }
  
  return newStats;
}

// Check and unlock achievements for user
async function checkAndUnlockAchievements(env, userId, conditionType, conditionValue = 1) {
  // Check if user is an admin - if so, process achievements but don't award points
  const creds = parsedCredentials;
  const accessToken = await getAccessToken(env, creds);
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
  
  const isAdmin = admins.some(a => {
    const idMatch = a.telegram_id && String(a.telegram_id) === String(userId);
    return idMatch;
  });
  
  const achievements = await initializeAchievements(env);
  const userStats = await getUserStats(env, userId);
  
  for (const achievement of achievements) {
    if (achievement.condition_type !== conditionType) {
      continue;
    }
    
    // Get current progress for this achievement
    const currentProgress = await getUserAchievementProgress(env, userId, achievement.id);
    
    // Calculate new progress
    let newProgress = currentProgress.progress + conditionValue;
    
    // Special cases for certain conditions
    if (conditionType === 'daily_streak') {
      newProgress = userStats.current_streak;
    } else if (conditionType === 'referral_count') {
      newProgress = userStats.referrals_count;
    } else if (conditionType === 'partner_subscribe_all') {
      // Need to check how many partners user has subscribed to
      // For now, we'll use the partners_subscribed stat
      newProgress = userStats.partners_subscribed;
    } else if (conditionType === 'early_user') {
      // Check if user is among first 100 (excluding admins with a_ prefix)
      const regNum = String(userStats.registration_number || '');
      const isRegularUser = !regNum.startsWith('a_');
      const isEarlyUser = isRegularUser && Number(regNum) <= 100;
      newProgress = isEarlyUser ? 1 : 0;
    }
    
    // Check if achievement should be unlocked
    const shouldUnlock = achievement.condition_value
      ? newProgress >= achievement.condition_value
      : newProgress > 0; // For achievements without specific threshold

    // Check if this is a NEW unlock (not already unlocked)
    const isNewUnlock = shouldUnlock && !currentProgress.is_unlocked;

    // Update progress
    await updateUserAchievementProgress(
      env,
      userId,
      achievement.id,
      newProgress,
      shouldUnlock || currentProgress.is_unlocked // Keep unlocked if already unlocked
    );

    // If achievement is NEWLY unlocked (not already unlocked before), award points and send notification
    if (isNewUnlock && !isAdmin) {
      await awardPointsToUser(env, userId, achievement.id);
      console.log(`[ACHIEVEMENT] ✅ User ${userId} unlocked NEW achievement: ${achievement.id}`);
    } else if (isNewUnlock && isAdmin) {
      // For admins, send notification without awarding points
      console.log(`[ACHIEVEMENT] Admin ${userId} unlocked NEW achievement ${achievement.id} but not receiving points`);

      try {
        const achievementTitle = achievement.title;
        const achievementDescription = achievement.description;

        const message = `🎉 Поздравляем! Новое достижение!\n\n${achievementTitle}\n━━━━━━━━━━━\n${achievementDescription}\n\n🏆 Редкость: ${achievement.rarity}\n⭐ (как админ, вы не получаете баллы за достижения)`;

        await globalBot.api.sendMessage(userId, message);
      } catch (error) {
        console.error(`Failed to send achievement notification to admin user ${userId}:`, error);
      }
    } else if (shouldUnlock && currentProgress.is_unlocked) {
      // Achievement already unlocked - skip notification
      console.log(`[ACHIEVEMENT] ⏭️ User ${userId} already has achievement ${achievement.id}, skipping notification`);
    }
  }
}

// Handle referral link processing
async function handleReferralLink(env, referrerId, newUserId) {
  try {
    // Check if referral already exists
    const existingReferral = await getReferralData(env, referrerId, newUserId);
    if (existingReferral) {
      // Referral already exists
      return false;
    }
    
    // Check if referrer is an admin - if so, process referral but don't award points
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
    
    const isAdmin = admins.some(a => {
      const idMatch = a.telegram_id && String(a.telegram_id) === String(referrerId);
      return idMatch;
    });
    
    // Create referral relationship
    const referralData = {
      referrer_id: referrerId,
      referred_id: newUserId,
      points_awarded: isAdmin ? 0 : 10, // No points for admin referrals
      is_active: true,
      created_at: new Date().toISOString()
    };
    
    // Store referral in Google Sheets
    try {
      await appendSheetRow(
        env.SHEET_ID,
        'referrals',
        [
          referrerId,
          newUserId,
          String(referralData.points_awarded),
          referralData.is_active ? 'TRUE' : 'FALSE',
          referralData.created_at
        ],
        accessToken
      );
    } catch (error) {
      console.error(`Error storing referral in sheets from ${referrerId} to ${newUserId}:`, error);
    }
    
    // Store referral in cache
    const cacheKey = `referral:${referrerId}:${newUserId}`;
    await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(referralData), { expirationTtl: 86400 }); // 24 hours
    
    // Update referrer's stats (count only, no points for admin)
    const referrerStats = await getUserStats(env, referrerId);
    const updatedReferrerStats = await updateUserStats(env, referrerId, {
      referrals_count: (referrerStats.referrals_count || 0) + 1
    });
    
    // Check if referrer achieved referral milestone (only for non-admins)
    if (!isAdmin) {
      await checkAndUnlockAchievements(env, referrerId, 'referral_count', updatedReferrerStats.referrals_count);
    }
    
    // Update referred user's stats to mark referral source
    await updateUserStats(env, newUserId, {
      referrer_id: referrerId
    });
    
    // Send notification to referrer
    try {
        const message = isAdmin 
        ? `🎉 Ваш друг присоединился! (как админ, вы не получаете баллы за рефералов)`
        : `🎉 Ваш друг присоединился! +10 баллов за реферала`;
      
      await globalBot.api.sendMessage(referrerId, message);
    } catch (error) {
      console.error(`Failed to send referral notification to user ${referrerId}:`, error);
    }
    
    return true;
  } catch (error) {
    console.error(`Error handling referral from ${referrerId} to ${newUserId}:`, error);
    return false;
  }
}

// Get referral data
async function getReferralData(env, referrerId, referredId) {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const referrals = await getSheetData(env.SHEET_ID, 'referrals', accessToken);
    
    const referral = referrals.find(r => 
      String(r.referrer_id) === String(referrerId) && 
      String(r.referred_id) === String(referredId)
    );
    
    if (referral) {
      return {
        referrer_id: referral.referrer_id,
        referred_id: referral.referred_id,
        points_awarded: parseInt(referral.points_awarded) || 0,
        is_active: referral.is_active === 'TRUE',
        created_at: referral.created_at
      };
    }
    
    return null;
  } catch (error) {
    console.error(`Error fetching referral data from ${referrerId} to ${referredId}:`, error);
    return null;
  }
}

// Calculate conversion rate for a partner
async function calculatePartnerConversion(env, partnerTitle) {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    
    // Get all clicks for this partner
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const partnerClicks = clicks.filter(c => c.title === partnerTitle);
    
    if (partnerClicks.length === 0) {
      return {
        partner_title: partnerTitle,
        total_clicks: 0,
        unique_users: 0,
        conversion_rate: '0.00%'
      };
    }
    
    // Calculate total clicks
    const totalClicks = partnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
    
    // Calculate unique users
    const uniqueUsers = new Set(partnerClicks.map(c => c.telegram_id)).size;
    
    // Calculate conversion rate
    const conversionRate = totalClicks > 0 ? ((uniqueUsers / totalClicks) * 100).toFixed(2) : 0.00;
    
    return {
      partner_title: partnerTitle,
      total_clicks: totalClicks,
      unique_users: uniqueUsers,
      conversion_rate: `${conversionRate}%`
    };
  } catch (error) {
    console.error(`Error calculating conversion for partner ${partnerTitle}:`, error);
    return {
      partner_title: partnerTitle,
      total_clicks: 0,
      unique_users: 0,
      conversion_rate: '0.00%',
      error: error.message
    };
  }
}

// Calculate conversion rate for a specific user and partner
async function calculateUserPartnerConversion(env, userId, partnerTitle) {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    
    // Get clicks for this user and partner
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const userPartnerClicks = clicks.filter(c => 
      String(c.telegram_id) === String(userId) && 
      c.title === partnerTitle
    );
    
    if (userPartnerClicks.length === 0) {
      return {
        telegram_id: userId,
        partner_title: partnerTitle,
        user_clicks: 0,
        conversion_status: 'no clicks'
      };
    }
    
    // For individual user conversion, we might track if user took action after clicking
    // This could be based on additional data like purchases, promocode usage, etc.
    const userClicks = userPartnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
    
    // Placeholder for actual conversion tracking (would need additional data)
    // In a real implementation, this might check if user used a promocode, made purchase, etc.
    const converted = false; // This would be determined by additional criteria
    
    return {
      telegram_id: userId,
      partner_title: partnerTitle,
      user_clicks: userClicks,
      converted: converted,
      conversion_status: converted ? 'converted' : 'not converted'
    };
  } catch (error) {
    console.error(`Error calculating user-partner conversion for user ${userId}, partner ${partnerTitle}:`, error);
    return {
      telegram_id: userId,
      partner_title: partnerTitle,
      user_clicks: 0,
      conversion_status: 'error',
      error: error.message
    };
  }
}

// Update conversion rate in clicks table
async function updateConversionRate(env, partnerTitle) {
  try {
    const conversionData = await calculatePartnerConversion(env, partnerTitle);
    
    if (conversionData.error) {
      console.error(`Error getting conversion data for ${partnerTitle}:`, conversionData.error);
      return null;
    }
    
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    
    // Get all clicks for this partner
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const partnerClicks = clicks.filter(c => c.title === partnerTitle);
    
    // Update conversion rate for each row of this partner
    for (const click of partnerClicks) {
      const rowIndex = clicks.findIndex(c => 
        String(c.telegram_id) === String(click.telegram_id) && 
        c.title === click.title
      ) + 2; // +2 because: +1 for header, +1 for 1-based index
      
      // Update the conversion rate in the row
      await updateSheetRow(
        env.SHEET_ID,
        'clicks',
        rowIndex,
        [
          click.telegram_id,
          click.username || '',
          click.first_name || '',
          click.title,
          click.category || '',
          click.url || '',
          click.click || '1',
          click.date_release || '',
          click.first_click_date || '',
          click.last_click_date || '',
          click.last_click_time || '',
          click.timestamp || '',
          conversionData.conversion_rate
        ],
        accessToken
      );
    }
    
    console.log(`[CONVERSION] Updated conversion rates for partner ${partnerTitle}: ${conversionData.conversion_rate}`);
    return conversionData;
  } catch (error) {
    console.error(`Error updating conversion rate for partner ${partnerTitle}:`, error);
    return null;
  }
}

// Track daily activity for streaks
async function trackDailyActivity(env, userId) {
  const today = new Date().toISOString().split('T')[0];
  const cacheKey = `daily_activity:${userId}:${today}`;
  
  // Check if already tracked today in cache
  const todayActivity = await env.BROADCAST_STATE.get(cacheKey);
  if (todayActivity) {
    // Already tracked today, just increment counter
    const activity = JSON.parse(todayActivity);
    activity.actions_count = (activity.actions_count || 0) + 1;
    await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(activity), { expirationTtl: 86400 });
    
    // Also update in Google Sheets
    try {
      const creds = parsedCredentials;
      const accessToken = await getAccessToken(env, creds);
      const dailyActivities = await getSheetData(env.SHEET_ID, 'daily_activity', accessToken);
      
      const existingIndex = dailyActivities.findIndex(da => 
        String(da.telegram_id) === String(userId) && 
        da.activity_date === today
      );
      
      if (existingIndex !== -1) {
        // Update existing record
        const rowIndex = existingIndex + 2; // +2 because: +1 for header, +1 for 1-based index
        await updateSheetRow(
          env.SHEET_ID,
          'daily_activity',
          rowIndex,
          [
            userId,
            today,
            String(activity.actions_count),
            activity.created_at
          ],
          accessToken
        );
      }
    } catch (error) {
      console.error(`Error updating daily activity in sheets for user ${userId} on ${today}:`, error);
    }
    
    return activity;
  }
  
  // New day, create activity record
  const newActivity = {
    telegram_id: userId,
    activity_date: today,
    actions_count: 1,
    created_at: new Date().toISOString()
  };
  
  await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(newActivity), { expirationTtl: 86400 });
  
  // Add to Google Sheets
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    
    await appendSheetRow(
      env.SHEET_ID,
      'daily_activity',
      [
        userId,
        today,
        String(newActivity.actions_count),
        newActivity.created_at
      ],
      accessToken
    );
  } catch (error) {
    console.error(`Error adding daily activity to sheets for user ${userId} on ${today}:`, error);
  }
  
  // Update user stats for streak
  const currentStats = await getUserStats(env, userId);
  const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
  
  let newStreak = 1;
  if (currentStats.last_active_date === yesterday) {
    // Continuing streak
    newStreak = (currentStats.current_streak || 0) + 1;
  } else if (currentStats.last_active_date === today) {
    // Already active today
    newStreak = currentStats.current_streak || 1;
  }
  
  // Update longest streak if needed
  const longestStreak = Math.max(newStreak, currentStats.longest_streak || 0);
  
  const updatedStats = await updateUserStats(env, userId, {
    current_streak: newStreak,
    longest_streak: longestStreak,
    last_active_date: today
  });
  
  // Check if user is admin - if not, check for streak achievement
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
  const isAdmin = admins.some(a => {
    const idMatch = a.telegram_id && String(a.telegram_id) === String(userId);
    return idMatch;
  });
  
  if (!isAdmin) {
    // Only check for streak achievement if user is not admin
    await checkAndUnlockAchievements(env, userId, 'daily_streak', updatedStats.current_streak);
  } else {
    console.log(`[STREAK] Admin ${userId} continued streak (${newStreak} days) but not checking for achievements`);
  }
  
  return newActivity;
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
// AUTOMATIC DELETION OF OLD MESSAGES (PROMOCODES & VIDEOS)
// ═══════════════════════════════════════════════════════════════

async function deleteOldMessages(env) {
  console.log('[AUTO-DELETE] 🗑️ Starting old messages cleanup...');

  try {
    let deletedCount = 0;
    let errorCount = 0;

    // Get all message keys from Redis (both promo_msg_* and video_msg_*)
    const promoKeys = await redis.keys('promo_msg_*');
    const videoKeys = await redis.keys('video_msg_*');
    const keys = [...promoKeys, ...videoKeys];
    console.log(`[AUTO-DELETE] 📊 Found ${keys.length} messages to check (${promoKeys.length} promocodes, ${videoKeys.length} videos)`);

    const now = Date.now();

    for (const key of keys) {
      try {
        const dataJson = await redis.get(key);
        if (!dataJson) continue;

        const data = JSON.parse(dataJson);

        // Check if we need to delete
        if (now >= data.delete_at) {
          const messageType = data.partner ? `promocode from ${data.partner}` : `video: ${data.video_title || 'unknown'}`;
          console.log(`[AUTO-DELETE] 🎯 Deleting message ${data.message_id} from chat ${data.chat_id} (${messageType})`);

          try {
            await globalBot.api.deleteMessage(data.chat_id, data.message_id);
            deletedCount++;
            console.log(`[AUTO-DELETE] ✅ Deleted message ${data.message_id}`);
          } catch (error) {
            // Message may have been already deleted by user
            if (error.error_code === 400 && error.description?.includes('message to delete not found')) {
              console.log(`[AUTO-DELETE] ℹ️ Message ${data.message_id} already deleted`);
            } else {
              console.error(`[AUTO-DELETE] ❌ Failed to delete message ${data.message_id}:`, error.description);
              errorCount++;
            }
          }

          // Delete record from Redis
          await redis.del(key);
        }
      } catch (error) {
        console.error(`[AUTO-DELETE] ❌ Error processing key ${key}:`, error);
        errorCount++;
      }
    }

    console.log(`[AUTO-DELETE] ✅ Cleanup completed! Deleted: ${deletedCount}, Errors: ${errorCount}`);

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
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);

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
        const chatInfo = await globalBot.api.getChat(user.telegram_id);
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

    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);

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
        await globalBot.api.sendMessage(partner.telegram_id, message, { parse_mode: 'HTML' });
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

    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);

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
        await globalBot.api.sendMessage(partner.telegram_id, message, { parse_mode: 'HTML' });
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
  const creds = parsedCredentials;
  const accessToken = await getAccessToken(env, creds);
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);

  let messageText = '';
  if (state.title) messageText += `*${state.title}*\n`;
  if (state.subtitle) messageText += `\n${state.subtitle}`;

  // Создаем промежуточную ссылку для отслеживания кликов
  let keyboard = null;
  if (state.button_text && state.button_url) {
    const encodedPartnerUrl = encodeURIComponent(state.button_url);
    const baseUrl = env.SERVER_URL || env.BASE_URL || 'https://app.okolotattooing.ru';
    const trackedUrl = `${baseUrl}/r/${state.broadcast_id}/${encodedPartnerUrl}`;
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
  let saveError = null;
  try {
    // Проверяем, есть ли заголовки в листе broadcasts, и если нет - добавляем их
    const broadcastHeaders = ['broadcast_id', 'name', 'date', 'time', 'sent_count', 'read_count', 'click_count', 'title', 'subtitle', 'button_text', 'button_url', 'total_users', 'fail_count', 'archived_count', 'partner'];
    
    // Сначала проверим, есть ли уже какие-то данные в листе
    const existingBroadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
    
    // Если лист пустой, добавим заголовки
    if (existingBroadcasts.length === 0) {
      await appendSheetRow(env.SHEET_ID, 'broadcasts', broadcastHeaders, accessToken);
    }
    
    const broadcastData = [
      state.broadcast_id || '',                    // broadcast_id
      state.broadcast_name || 'Без названия',      // name
      currentDate,                                  // date
      currentTime,                                  // time
      String(successCount),                         // sent_count
      String(readCount),                            // read_count (= sent_count)
      '0',                                          // click_count (будет обновляться)
      state.title || '',                            // title
      state.subtitle || '',                         // subtitle
      state.button_text || '',                      // button_text
      state.button_url || '',                       // button_url
      String(validUsers.length),                    // total_users
      String(failCount),                            // fail_count
      String(inactiveCount),                        // archived_count
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
    console.error(`[РАССЫЛКА] ❌ Stack trace:`, error.stack);

    // Send error to admin
    try {
      await ctx.reply(`⚠️ *Предупреждение:* Рассылка отправлена, но не удалось сохранить статистику в таблицу.\n\nОшибка: ${escapeMarkdown(saveError)}`, { parse_mode: 'Markdown' });
    } catch (e) {
      console.error(`[РАССЫЛКА] ❌ Не удалось отправить сообщение об ошибке:`, e);
    }
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
// HELPER FUNCTIONS FOR MARKDOWN
// ═══════════════════════════════════════════════════════════════

// Helper function to escape special Markdown characters
// This prevents Markdown parsing errors when user data contains special symbols
function escapeMarkdown(text) {
  if (!text) return text;
  return String(text).replace(/([_*\[\]()~`>#+=|{}.!-])/g, '\\$1');
}

// Helper function to escape only underscores in URLs
// URLs should not have dots, slashes, etc. escaped or they will break
function escapeMarkdownUrl(url) {
  if (!url) return url;
  return String(url).replace(/_/g, '\\_');
}

// ═══════════════════════════════════════════════════════════════
// BOT SETUP WITH GRAMMY
// ═══════════════════════════════════════════════════════════════

function setupBot(env) {
  const bot = new Bot(env.BOT_TOKEN);

  // Initialize required sheets on startup
  initializeRequiredSheets(env).catch(error => {
    console.error('Error initializing required sheets:', error);
  });

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
    const startPayload = ctx.match; // Get the payload after /start

    // Check if this is a referral link
    let referrerId = null;
    if (startPayload && startPayload.startsWith('ref_')) {
      referrerId = startPayload.replace('ref_', '');
    }

    // Регистрируем пользователя
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const existing = users.find(u => String(u.telegram_id) === String(chatId));

    const currentDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    const username = user.username ? `@${user.username}` : '';

    if (!existing) {
      console.log(`[REGISTER] 🆕 New user: ${chatId} (@${user.username || 'no-username'})`);

      // Check if user is admin
      const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
      const isAdmin = admins.some(a => {
        const idMatch = a.telegram_id && String(a.telegram_id) === String(chatId);
        return idMatch;
      });

      // Determine registration number
      let registrationNumber;
      if (isAdmin) {
        // For admins: count existing admins and assign a_N
        const adminUsers = users.filter(u => u.registration_number && String(u.registration_number).startsWith('a_'));
        registrationNumber = `a_${adminUsers.length + 1}`;
      } else {
        // For regular users: count non-admin users and assign number
        const regularUsers = users.filter(u => u.registration_number && !String(u.registration_number).startsWith('a_'));
        registrationNumber = String(regularUsers.length + 1);
      }

      // Get user avatar
      const avatarUrl = await getUserAvatarUrl(chatId);

      // Добавляем в таблицу users
      // Формат: telegram_id, username, first_name, date_registered, bot_started, last_active, total_points, current_streak, longest_streak, last_active_date, referrals_count, education_views_count, events_registered, partners_subscribed, total_donations, registration_number, avatar_url
      await appendSheetRow(
        env.SHEET_ID,
        'users',
        [
          chatId,                        // telegram_id
          username,                      // username с @
          user.first_name || 'Unknown',  // first_name
          currentDate,                   // date_registered (YYYY-MM-DD)
          'бот запущен',                 // bot_started
          currentDate,                   // last_active (YYYY-MM-DD)
          '0',                          // total_points
          '0',                          // current_streak
          '0',                          // longest_streak
          currentDate,                   // last_active_date
          '0',                          // referrals_count
          '0',                          // education_views_count
          '0',                          // events_registered
          '0',                          // partners_subscribed
          '0',                          // total_donations
          String(registrationNumber),   // registration_number
          avatarUrl || ''               // avatar_url
        ],
        accessToken
      );

      console.log(`[REGISTER] Avatar URL: ${avatarUrl || 'none'}`);


      console.log(`✅ User registered: ${chatId} ${username} at ${currentDate}, registration #${registrationNumber}`);
      
      // Process referral if applicable
      if (referrerId && referrerId !== String(chatId)) {
        await handleReferralLink(env, referrerId, chatId);
      }
      
      // Check for early user achievement (only for non-admin users with number <= 100)
      if (!isAdmin && !String(registrationNumber).startsWith('a_') && Number(registrationNumber) <= 100) {
        await checkAndUnlockAchievements(env, chatId, 'early_user', 1);
      } else if (isAdmin) {
        console.log(`[REGISTRATION] Skipping early user achievement for admin ${chatId} (${registrationNumber})`);
      }
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
              currentDate,                         // last_active (обновляем)
              existing.total_points || '0',        // total_points
              existing.current_streak || '0',      // current_streak
              existing.longest_streak || '0',      // longest_streak
              existing.last_active_date || currentDate, // last_active_date
              existing.referrals_count || '0',     // referrals_count
              existing.education_views_count || '0', // education_views_count
              existing.events_registered || '0',   // events_registered
              existing.partners_subscribed || '0', // partners_subscribed
              existing.total_donations || '0',     // total_donations
              existing.registration_number || '',  // registration_number
            ],
            accessToken
          );

          console.log(`✅ User data updated: ${chatId} ${username}`);
        } else {
          console.log(`[REGISTER] ✓ No changes for user: ${chatId}`);
        }
      }
    }

    // Check if user is admin
    const isAdmin = await checkAdmin(env, user);
    
    // Track daily activity only for non-admin users
    if (!isAdmin) {
      await trackDailyActivity(env, chatId);
    }

    // Check if user wants to donate
    if (startPayload === 'donate') {
      // Show donate menu directly
      const userStats = await getUserStats(env, chatId);

      let donateMessage = `💳 *Поддержать проект*\n\n`;
      donateMessage += `Спасибо, что пользуетесь нашим ботом! 🙏\n\n`;
      donateMessage += `Ваши донаты помогают развивать проект и добавлять новые фичи.\n\n`;
      donateMessage += `📊 *Ваша статистика:*\n`;
      donateMessage += `• Всего задонатили: ${userStats.total_donations || 0} ⭐\n\n`;
      donateMessage += `🎁 *Бонусы:*\n`;
      donateMessage += `• За каждый донат ты получаешь баллы\n`;
      donateMessage += `• Достижение "💳 Щедрый хомяк" за 1000+ ⭐\n\n`;
      donateMessage += `Выбери сумму:`;

      const donateKeyboard = new InlineKeyboard()
        .text('⭐ 50 Stars', 'donate_50').text('⭐ 100 Stars', 'donate_100').row()
        .text('⭐ 250 Stars', 'donate_250').text('⭐ 500 Stars', 'donate_500').row()
        .text('⭐ 1000 Stars', 'donate_1000');

      await ctx.reply(donateMessage, {
        parse_mode: 'Markdown',
        reply_markup: donateKeyboard
      });
      return; // Exit early, don't show start message
    }

    // Проверяем админа и представителя
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

    // Add profile and referral buttons for ALL users (including admins)
    keyboard.row().text('👤 Мой профиль', 'show_profile');
    keyboard.row().text('🐹 Фабрика хомяков', 'show_referral');
    keyboard.row().text('💌 Обратная связь', 'show_feedback');

    await ctx.reply(
      `👋 Привет, *${user.first_name}*!\n\n` +
      `🔗 Жми кнопку и открывай приложение.\n\n` +
      `Внутри — уникальные промокоды, акции и контент.\n` +
      `⚠️ *Бота не останавливай*❌: сюда приходят самые жирные офферы.\n\n` +
      `🖤 Поехали 👇`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  // /profile command - Show user profile
  bot.command('profile', async (ctx) => {
    const user = ctx.from;
    const userId = user.id;

    try {
      const userStats = await getUserStats(env, userId);
      const achievements = await initializeAchievements(env);

      // Get unlocked achievements
      const unlockedAchievements = [];
      for (const achievement of achievements) {
        const progress = await getUserAchievementProgress(env, userId, achievement.id);
        if (progress.is_unlocked) {
          unlockedAchievements.push(achievement);
        }
      }

      // Format profile message
      let profileMessage = `📊 *Ваш профиль*\n\n`;
      profileMessage += `👤 @${escapeMarkdown(user.username || 'не указан')}\n`;
      profileMessage += `🆔 Регистрация: ${userStats.date_registered || 'N/A'}\n\n`;

      profileMessage += `⭐ *Баллы:* ${userStats.total_points}\n`;
      profileMessage += `🔥 *Серия:* ${userStats.current_streak} дней (рекорд: ${userStats.longest_streak})\n`;
      profileMessage += `🐹 *Фабрика хомяков:* ${userStats.referrals_count}\n\n`;

      profileMessage += `🏆 *Достижения:* ${unlockedAchievements.length}/${achievements.length}\n`;
      profileMessage += `━━━━━━━━━━━━━━━━\n`;

      if (unlockedAchievements.length > 0) {
        for (const achievement of unlockedAchievements) {
          profileMessage += `✅ ${achievement.icon_emoji} ${escapeMarkdown(achievement.title)} (${achievement.points} баллов)\n`;
        }
      } else {
        profileMessage += `❌ Пока нет разблокированных достижений\n`;
      }

      // Add locked achievements
      const lockedAchievements = achievements.filter(a => !unlockedAchievements.some(ua => ua.id === a.id));
      if (lockedAchievements.length > 0) {
        profileMessage += `\n🔒 *Предстоящие достижения:*\n`;
        for (const achievement of lockedAchievements.slice(0, 3)) {
          let progressText = '';

          if (achievement.condition_type === 'referral_count') {
            progressText = `(${userStats.referrals_count}/${achievement.condition_value} рефералов)`;
          } else if (achievement.condition_type === 'daily_streak') {
            progressText = `(${userStats.current_streak}/${achievement.condition_value} дней)`;
          } else if (achievement.condition_type === 'partner_click') {
            progressText = `(0/${achievement.condition_value} переходов)`;
          }

          profileMessage += `🔒 ${achievement.icon_emoji} ${escapeMarkdown(achievement.title)} ${progressText}\n`;
        }
      }

      const keyboard = new InlineKeyboard()
        .text('🔄 Обновить', 'show_profile').row()
        .text('🏆 Все достижения', 'show_all_achievements').row()
        .text('🏆 Лидерборд', 'show_leaderboard');

      await ctx.reply(profileMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
    } catch (error) {
      console.error('Error showing profile:', error);
      await ctx.reply('❌ Ошибка при загрузке профиля');
    }
  });

  // /referrals command - Show referral program
  bot.command('referrals', async (ctx) => {
    const user = ctx.from;
    const userId = user.id;

    try {
      const userStats = await getUserStats(env, userId);
      // Create two versions of the link:
      // 1. Original link for button (no escaping)
      const botUsername = env.BOT_USERNAME || 'okolotattoo_bot';
      const referralLink = `https://t.me/${botUsername}?start=ref_${userId}`;
      // 2. Escaped link for display in text (with \_ for Markdown)
      const referralLinkEscaped = referralLink.replace(/_/g, '\\_');

      let referralMessage = `👥 *Реферальная программа*\n\n`;
      referralMessage += `🔗 *Ваша ссылка для копирования:*\n\`${referralLinkEscaped}\`\n\n`;
      referralMessage += `_Нажми на ссылку, чтобы скопировать_\n\n`;

      referralMessage += `📊 *Статистика:*\n`;
      referralMessage += `• Привлечено хомяков: ${userStats.referrals_count}\n`;
      referralMessage += `• Заработано баллов: ${userStats.referrals_count * 10}\n`;
      referralMessage += `• Активных рефералов: ${Math.min(userStats.referrals_count, 10)}\n\n`;

      referralMessage += `🎁 *Награды:*\n`;
      referralMessage += `• За каждого друга: +10 баллов\n`;
      referralMessage += `• Пригласи 10 друзей → 👑 Проактивный хомяк (+100 баллов)\n\n`;

      const keyboard = new InlineKeyboard()
        .switchInline('📤 Поделиться ссылкой', referralLink).row()
        .text('🐹 Мой взвод хомяков', 'show_referral_list').row()
        .text('🔄 Обновить', 'show_referral');

      await ctx.reply(referralMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
    } catch (error) {
      console.error('Error showing referral:', error);
      await ctx.reply('❌ Ошибка при загрузке реферальной программы');
    }
  });

  // /donate command - Show donation menu
  bot.command('donate', async (ctx) => {
    const user = ctx.from;
    const userId = user.id;

    try {
      const userStats = await getUserStats(env, userId);

      let donateMessage = `💳 *Поддержать проект*\n\n`;
      donateMessage += `Спасибо, что пользуетесь нашим ботом! 🙏\n\n`;
      donateMessage += `Ваши донаты помогают развивать проект и добавлять новые фичи.\n\n`;
      donateMessage += `📊 *Ваша статистика:*\n`;
      donateMessage += `• Всего задонатили: ${userStats.total_donations || 0} ⭐\n\n`;
      donateMessage += `🎁 *Бонусы:*\n`;
      donateMessage += `• За каждый донат ты получаешь баллы\n`;
      donateMessage += `• Достижение "💳 Щедрый хомяк" за 1000+ ⭐\n\n`;
      donateMessage += `Выбери сумму:`;

      const keyboard = new InlineKeyboard()
        .text('⭐ 50 Stars', 'donate_50').text('⭐ 100 Stars', 'donate_100').row()
        .text('⭐ 250 Stars', 'donate_250').text('⭐ 500 Stars', 'donate_500').row()
        .text('⭐ 1000 Stars', 'donate_1000');

      await ctx.reply(donateMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
    } catch (error) {
      console.error('Error showing donate menu:', error);
      await ctx.reply('❌ Ошибка при загрузке меню донатов');
    }
  });

  // /feedback command - Show feedback message with link
  bot.command('feedback', async (ctx) => {
    const user = ctx.from;

    try {
      let feedbackMessage = `💌 *Обратная связь*\n\n`;
      feedbackMessage += `Если у вас есть вопросы, предложения или вы столкнулись с проблемой, пожалуйста, напишите нам!\n\n`;
      feedbackMessage += `Мы ценим каждый ваш комментарий, так как он помогает нам становиться лучше.`;

      const keyboard = new InlineKeyboard()
        .url('💬 Написать в поддержку', 'https://clck.ru/3Rncqs');

      await ctx.reply(feedbackMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
    } catch (error) {
      console.error('Error showing feedback message:', error);
      await ctx.reply('❌ Ошибка при загрузке сообщения обратной связи');
    }
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

    const creds = parsedCredentials;
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

    const creds = parsedCredentials;
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
        try {
          const dateA = new Date(a.date + ' ' + a.time);
          const dateB = new Date(b.date + ' ' + b.time);
          // Check if dates are valid
          if (isNaN(dateA.getTime()) || isNaN(dateB.getTime())) {
            return 0; // Keep original order if dates are invalid
          }
          return dateB - dateA;
        } catch (error) {
          console.error('[BROADCASTS_STATS] Error sorting broadcasts:', error);
          return 0;
        }
      });

      // Показываем последние 10 рассылок
      const recentBroadcasts = broadcasts.slice(0, 10);

      let text = `📈 *Статистика рассылок*\n\n`;
      text += `📊 Всего рассылок: ${broadcasts.length}\n\n`;
      text += `━━━━━━━━━━━━━━━━\n`;

      recentBroadcasts.forEach((broadcast, index) => {
        const convRate = broadcast.conversion_rate || '0.00%';
        const broadcastName = escapeMarkdown(broadcast.name || 'Без названия');
        text += `\n${index + 1}. *${broadcastName}*\n`;
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
        const name = broadcast.name || 'Без названия';
        const shortName = name.length > 20 ? name.substring(0, 20) + '...' : name;
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
      console.error('[BROADCASTS_STATS] Error loading broadcast stats:', {
        error_message: error.message,
        error_stack: error.stack,
        user_id: ctx.from.id
      });

      try {
        await ctx.editMessageText(
          '❌ *Ошибка загрузки статистики рассылок*\n\n' +
          'Попробуйте еще раз или обратитесь к администратору.',
          {
            parse_mode: 'Markdown',
            reply_markup: new InlineKeyboard().text('« Назад', 'admin_panel')
          }
        );
      } catch (editError) {
        console.error('[BROADCASTS_STATS] Error editing message:', editError);
      }

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
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);

    try {
      const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
      const broadcast = broadcasts.find(b => b.broadcast_id === broadcastId);

      if (!broadcast) {
        await ctx.answerCallbackQuery('❌ Рассылка не найдена');
        return;
      }

      let text = `📊 *Детальная статистика*\n\n`;
      text += `📢 *Название:* ${escapeMarkdown(broadcast.name || 'Без названия')}\n`;
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
        text += `*Заголовок:* ${escapeMarkdown(broadcast.title)}\n`;
      }

      if (broadcast.subtitle) {
        text += `*Текст:* ${escapeMarkdown(broadcast.subtitle)}\n`;
      }

      if (broadcast.button_text && broadcast.button_url) {
        // Escape markdown characters in button text and URL (URL only needs underscore escaping)
        const escapedButtonText = escapeMarkdown(broadcast.button_text);
        const escapedUrl = escapeMarkdownUrl(broadcast.button_url);
        text += `\n🔘 *Кнопка:* ${escapedButtonText}\n`;
        text += `🔗 *Ссылка:* ${escapedUrl}`;
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

    const creds = parsedCredentials;
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
      const creds = parsedCredentials;
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
      const creds = parsedCredentials;
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
      const creds = parsedCredentials;
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

    const creds = parsedCredentials;
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

    const creds = parsedCredentials;
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
      const creds = parsedCredentials;
      const accessToken = await getAccessToken(env, creds);
      const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      if (!partners[partnerIndex]) {
        await ctx.answerCallbackQuery('❌ Партнер не найден');
        return;
      }

      const partner = partners[partnerIndex];
      const partnerUrl = partner.url || partner.link; // Support both field names
      const partnerClicks = clicks.filter(c => c.url === partnerUrl);

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

      // Escape underscores in the URL to prevent Markdown formatting issues
      const escapedPartnerUrl = partnerUrl.replace(/_/g, '\\_');
      
      let report = `📊 *Отчет по партнеру*\n` +
        `📅 *Период:* ${periodName}\n\n` +
        `🏷️ *Партнер:* ${partner.title}\n` +
        `📁 *Категория:* ${partner.category || 'Не указана'}\n` +
        `📅 *Дата размещения:* ${partner.date_release || 'Не указана'}\n` +
        `🔗 *Ссылка:* ${escapedPartnerUrl}\n`;

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

    // Add profile and referral buttons for all users
    keyboard.row().text('👤 Мой профиль', 'show_profile');
    keyboard.row().text('🐹 Фабрика хомяков', 'show_referral');
    keyboard.row().text('💌 Обратная связь', 'show_feedback');

    await ctx.editMessageText(
      `👋 Привет, *${escapeMarkdown(user.first_name)}*!\n\n` +
      `🔗 Жми кнопку и открывай приложение.\n\n` +
      `Внутри — уникальные промокоды, акции и контент.\n` +
      `⚠️ *Бота не останавливай*❌: сюда приходят самые жирные офферы.\n\n` +
      `🖤 Поехали 👇`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // Show user profile
  bot.callbackQuery('show_profile', async (ctx) => {
    const user = ctx.from;
    const userId = user.id;
    
    try {
      const userStats = await getUserStats(env, userId);
      const achievements = await initializeAchievements(env);
      
      // Get unlocked achievements
      const unlockedAchievements = [];
      for (const achievement of achievements) {
        const progress = await getUserAchievementProgress(env, userId, achievement.id);
        if (progress.is_unlocked) {
          unlockedAchievements.push(achievement);
        }
      }
      
      // Format profile message
      let profileMessage = `📊 *Ваш профиль*\n\n`;
      profileMessage += `👤 @${escapeMarkdown(user.username || 'не указан')}\n`;
      profileMessage += `🆔 Регистрация: ${userStats.date_registered || 'N/A'}\n\n`;

      profileMessage += `⭐ *Баллы:* ${userStats.total_points}\n`;
      profileMessage += `🔥 *Серия:* ${userStats.current_streak} дней (рекорд: ${userStats.longest_streak})\n`;
      profileMessage += `🐹 *Фабрика хомяков:* ${userStats.referrals_count}\n\n`;

      profileMessage += `🏆 *Достижения:* ${unlockedAchievements.length}/${achievements.length}\n`;
      profileMessage += `━━━━━━━━━━━━━━━━\n`;

      if (unlockedAchievements.length > 0) {
        for (const achievement of unlockedAchievements) {
          profileMessage += `✅ ${achievement.icon_emoji} ${escapeMarkdown(achievement.title)} (${achievement.points} баллов)\n`;
        }
      } else {
        profileMessage += `❌ Пока нет разблокированных достижений\n`;
      }

      // Add locked achievements
      const lockedAchievements = achievements.filter(a => !unlockedAchievements.some(ua => ua.id === a.id));
      if (lockedAchievements.length > 0) {
        profileMessage += `\n🔒 *Предстоящие достижения:*\n`;
        for (const achievement of lockedAchievements.slice(0, 3)) { // Show only first 3 locked
          let progressText = '';

          if (achievement.condition_type === 'referral_count') {
            progressText = `(${userStats.referrals_count}/${achievement.condition_value} рефералов)`;
          } else if (achievement.condition_type === 'daily_streak') {
            progressText = `(${userStats.current_streak}/${achievement.condition_value} дней)`;
          } else if (achievement.condition_type === 'partner_click') {
            // We would need to track partner clicks separately
            progressText = `(0/${achievement.condition_value} переходов)`;
          }

          profileMessage += `🔒 ${achievement.icon_emoji} ${escapeMarkdown(achievement.title)} ${progressText}\n`;
        }
      }
      
      const keyboard = new InlineKeyboard()
        .text('🔄 Обновить', 'show_profile').row()
        .text('🏆 Все достижения', 'show_all_achievements').row()
        .text('🏆 Лидерборд', 'show_leaderboard').row()
        .text('« Назад', 'back_to_start');
      
      await ctx.editMessageText(profileMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing profile:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке профиля');
    }
  });

  // Show all achievements
  bot.callbackQuery('show_all_achievements', async (ctx) => {
    const userId = ctx.from.id;
    
    try {
      const achievements = await initializeAchievements(env);
      const userStats = await getUserStats(env, userId);
      
      let achievementsMessage = `🏆 *Все достижения*\n\n`;
      
      // Group by rarity
      const groupedAchievements = {
        'Обычное': [],
        'Необычное': [],
        'Редкое': [],
        'Эпическое': [],
        'Легендарное': []
      };
      
      for (const achievement of achievements) {
        const progress = await getUserAchievementProgress(env, userId, achievement.id);
        achievement.unlocked = progress.is_unlocked;
        achievement.userProgress = progress.progress;
        
        groupedAchievements[achievement.rarity].push(achievement);
      }
      
      for (const [rarity, achs] of Object.entries(groupedAchievements)) {
        if (achs.length > 0) {
          achievementsMessage += `\n*${rarity}:*\n`;
          for (const achievement of achs) {
            const status = achievement.unlocked ? '✅' : '🔒';
            let progressText = '';
            
            if (!achievement.unlocked) {
              if (achievement.condition_type === 'referral_count') {
                progressText = ` (${achievement.userProgress || 0}/${achievement.condition_value} рефералов)`;
              } else if (achievement.condition_type === 'daily_streak') {
                progressText = ` (${achievement.userProgress || 0}/${achievement.condition_value} дней)`;
              } else if (achievement.condition_type === 'partner_click') {
                progressText = ` (${achievement.userProgress || 0}/${achievement.condition_value} переходов)`;
              } else if (achievement.condition_type === 'education_view') {
                progressText = ` (${achievement.userProgress || 0}/${achievement.condition_value} образовачей)`;
              } else if (achievement.condition_type === 'event_register') {
                progressText = ` (${achievement.userProgress || 0}/${achievement.condition_value} событий)`;
              }
            }
            
            achievementsMessage += `${status} ${achievement.icon_emoji} ${achievement.title}${progressText}\n`;
          }
        }
      }
      
      const keyboard = new InlineKeyboard()
        .text('« Назад к профилю', 'show_profile');
      
      await ctx.editMessageText(achievementsMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing all achievements:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке достижений');
    }
  });

  // Show leaderboard
  bot.callbackQuery('show_leaderboard', async (ctx) => {
    try {
      // This would normally fetch from a sorted list of users by points
      // For now, we'll show a placeholder message
      const leaderboardMessage = `🏆 *Топ пользователей*\n\n`;
      
      // In a real implementation, this would fetch from a sorted cache or database
      // For now, we'll just show a message indicating how it would work
      let message = leaderboardMessage;
      message += `Здесь будет отображаться таблица лидеров.\n\n`;
      message += `На основе количества набранных баллов пользователи будут ранжированы от лучшего к худшему.\n\n`;
      message += `Ваше текущее место: #? из ?\n`;
      message += `Ваши баллы: ?`;
      
      const keyboard = new InlineKeyboard()
        .text('« Назад к профилю', 'show_profile');
      
      await ctx.editMessageText(message, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing leaderboard:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке лидерборда');
    }
  });

  // Show referral program
  bot.callbackQuery('show_referral', async (ctx) => {
    const user = ctx.from;
    const userId = user.id;
    
    try {
      const userStats = await getUserStats(env, userId);
      // Create two versions of the link:
      // 1. Original link for button (no escaping)
      const botUsername = env.BOT_USERNAME || 'okolotattoo_bot';
      const referralLink = `https://t.me/${botUsername}?start=ref_${userId}`;
      // 2. Escaped link for display in text (with \_ for Markdown)
      const referralLinkEscaped = referralLink.replace(/_/g, '\\_');

      let referralMessage = `👥 *Реферальная программа*\n\n`;
      referralMessage += `🔗 *Ваша ссылка для копирования:*\n\`${referralLinkEscaped}\`\n\n`;
      referralMessage += `_Нажми на ссылку, чтобы скопировать_\n\n`;

      referralMessage += `📊 *Статистика:*\n`;
      referralMessage += `• Привлечено хомяков: ${userStats.referrals_count}\n`;
      referralMessage += `• Заработано баллов: ${userStats.referrals_count * 10}\n`; // 10 per referral
      referralMessage += `• Активных рефералов: ${Math.min(userStats.referrals_count, 10)}\n\n`; // Placeholder for active count

      referralMessage += `🎁 *Награды:*\n`;
      referralMessage += `• За каждого друга: +10 баллов\n`;
      referralMessage += `• Пригласи 10 друзей → 👑 Проактивный хомяк (+100 баллов)\n\n`;

      const keyboard = new InlineKeyboard()
        .switchInline('📤 Поделиться ссылкой', referralLink).row()
        .text('🐹 Мой взвод хомяков', 'show_referral_list').row()
        .text('« Назад', 'back_to_start');
      
      await ctx.editMessageText(referralMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing referral:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке реферальной программы');
    }
  });

  // Show referral list
  bot.callbackQuery('show_referral_list', async (ctx) => {
    const userId = ctx.from.id;

    try {
      // In a real implementation, this would fetch from the referrals sheet
      // For now, we'll show a placeholder
      const userStats = await getUserStats(env, userId);

      let referralListMessage = `🐹 *Мой взвод хомяков* (${userStats.referrals_count} шт.)\n\n`;

      if (userStats.referrals_count > 0) {
        // Placeholder list - in reality this would come from referrals sheet
        for (let i = 1; i <= Math.min(userStats.referrals_count, 5); i++) {
          referralListMessage += `${i}. @referral_user${i} - 2 дня назад\n`;
        }

        if (userStats.referrals_count > 5) {
          referralListMessage += `... и ещё ${userStats.referrals_count - 5}`;
        }
      } else {
        referralListMessage += `Пока никто не присоединился по вашей ссылке.\n\n`;
        referralListMessage += `Поделитесь своей ссылкой, чтобы приглашать друзей!`;
      }

      const keyboard = new InlineKeyboard()
        .text('« Назад', 'show_referral');

      await ctx.editMessageText(referralListMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing referral list:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке списка рефералов');
    }
  });

  // Show feedback message
  bot.callbackQuery('show_feedback', async (ctx) => {
    try {
      let feedbackMessage = `💌 *Обратная связь*\n\n`;
      feedbackMessage += `Если у вас есть вопросы, предложения или вы столкнулись с проблемой, пожалуйста, напишите нам!\n\n`;
      feedbackMessage += `Мы ценим каждый ваш комментарий, так как он помогает нам становиться лучше.`;

      const keyboard = new InlineKeyboard()
        .url('💬 Написать в поддержку', 'https://clck.ru/3Rncqs').row()
        .text('« Назад', 'back_to_start');

      await ctx.editMessageText(feedbackMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing feedback message:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке сообщения обратной связи');
    }
  });

  // ═══════════════════════════════════════════════════════════════
  // СИСТЕМА ДОНАТОВ ЧЕРЕЗ TELEGRAM STARS
  // ═══════════════════════════════════════════════════════════════

  // Show donation menu
  bot.callbackQuery('show_donate', async (ctx) => {
    const user = ctx.from;
    const userId = user.id;

    try {
      const userStats = await getUserStats(env, userId);

      let donateMessage = `💳 *Поддержать проект*\n\n`;
      donateMessage += `Спасибо, что пользуетесь нашим ботом! 🙏\n\n`;
      donateMessage += `Ваши донаты помогают развивать проект и добавлять новые фичи.\n\n`;
      donateMessage += `📊 *Ваша статистика:*\n`;
      donateMessage += `• Всего задонатили: ${userStats.total_donations || 0} ⭐\n\n`;
      donateMessage += `🎁 *Бонусы:*\n`;
      donateMessage += `• За каждый донат ты получаешь баллы\n`;
      donateMessage += `• Достижение "💳 Щедрый хомяк" за 1000+ ⭐\n\n`;
      donateMessage += `Выбери сумму:`;

      const keyboard = new InlineKeyboard()
        .text('⭐ 50 Stars', 'donate_50').text('⭐ 100 Stars', 'donate_100').row()
        .text('⭐ 250 Stars', 'donate_250').text('⭐ 500 Stars', 'donate_500').row()
        .text('⭐ 1000 Stars', 'donate_1000').row()
        .text('« Назад', 'back_to_start');

      await ctx.editMessageText(donateMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });
      await ctx.answerCallbackQuery();
    } catch (error) {
      console.error('Error showing donate menu:', error);
      await ctx.answerCallbackQuery('❌ Ошибка при загрузке меню донатов');
    }
  });

  // Handle donation amount selection
  const createDonationHandler = (amount) => {
    return async (ctx) => {
      const user = ctx.from;
      const userId = user.id;

      try {
        console.log(`[DONATION] User ${userId} (@${user.username}) initiated ${amount} Stars donation`);

        // Create invoice for Telegram Stars
        const title = `Поддержка проекта`;
        const description = `Донат на ${amount} Telegram Stars`;
        const payload = JSON.stringify({
          user_id: userId,
          amount: amount,
          timestamp: Date.now()
        });
        const currency = 'XTR'; // Telegram Stars currency code

        // Price in smallest units (Stars don't have subdivisions, so amount = price)
        const prices = [{ label: 'Донат', amount: amount }];

        await ctx.replyWithInvoice(
          title,
          description,
          payload,
          '', // provider_token is empty for Stars
          currency,
          prices,
          {
            reply_markup: new InlineKeyboard()
              .text('« Отменить', 'show_donate')
          }
        );

        await ctx.answerCallbackQuery();
      } catch (error) {
        console.error(`[DONATION] Error creating invoice for ${amount} Stars:`, error);
        await ctx.answerCallbackQuery('❌ Ошибка при создании счёта. Попробуйте позже.');
      }
    };
  };

  // Register handlers for different amounts
  bot.callbackQuery('donate_50', createDonationHandler(50));
  bot.callbackQuery('donate_100', createDonationHandler(100));
  bot.callbackQuery('donate_250', createDonationHandler(250));
  bot.callbackQuery('donate_500', createDonationHandler(500));
  bot.callbackQuery('donate_1000', createDonationHandler(1000));

  // Handle pre-checkout query (required by Telegram)
  bot.on('pre_checkout_query', async (ctx) => {
    try {
      const payload = JSON.parse(ctx.preCheckoutQuery.invoice_payload);
      console.log('[DONATION] Pre-checkout query:', payload);

      // Answer OK to allow payment to proceed
      await ctx.answerPreCheckoutQuery(true);
    } catch (error) {
      console.error('[DONATION] Pre-checkout error:', error);
      await ctx.answerPreCheckoutQuery(false, 'Ошибка при обработке платежа');
    }
  });

  // Handle successful payment
  bot.on('message:successful_payment', async (ctx) => {
    try {
      const payment = ctx.message.successful_payment;
      const payload = JSON.parse(payment.invoice_payload);
      const userId = payload.user_id;
      const amount = payload.amount;

      console.log(`[DONATION] ✅ Successful payment from user ${userId}: ${amount} Stars`);

      // Update total_donations
      const userStats = await getUserStats(env, userId);
      const newTotalDonations = (userStats.total_donations || 0) + amount;

      await updateUserStats(env, userId, {
        total_donations: newTotalDonations
      });

      // Award points (1 point per Star)
      const newTotalPoints = (userStats.total_points || 0) + amount;
      await updateUserStats(env, userId, {
        total_points: newTotalPoints
      });

      console.log(`[DONATION] Updated user ${userId}: total_donations=${newTotalDonations}, total_points=${newTotalPoints}`);

      // Check for achievement "Щедрый хомяк" (1000+ donations)
      await checkAndUnlockAchievements(env, userId, 'donation', newTotalDonations);

      // Send thank you message
      const thankYouMessage =
        `✨ *Спасибо за поддержку!* ✨\n\n` +
        `Вы задонатили ${amount} ⭐ Telegram Stars\n\n` +
        `🎁 *Получено:*\n` +
        `• +${amount} баллов к вашему счёту\n` +
        `• Всего задонатили: ${newTotalDonations} ⭐\n\n` +
        `Вы помогаете проекту становиться лучше! 🙏`;

      const keyboard = new InlineKeyboard()
        .text('👤 Мой профиль', 'show_profile').row()
        .text('💳 Ещё донат', 'show_donate');

      await ctx.reply(thankYouMessage, {
        parse_mode: 'Markdown',
        reply_markup: keyboard
      });

    } catch (error) {
      console.error('[DONATION] Error processing successful payment:', error);
      await ctx.reply('❌ Произошла ошибка при обработке платежа. Обратитесь в поддержку.');
    }
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
      const creds = parsedCredentials;
      const accessToken = await getAccessToken(env, creds);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      // Собираем статистику ТОЛЬКО по этому партнеру
      const partnerUrl = partnerData.url || partnerData.link; // Support both field names
      const partnerClicks = clicks.filter(c => c.url === partnerUrl);

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
        `🏷️ *Ваш партнер:* ${escapeMarkdown(partnerData.title)}\n` +
        `📁 *Категория:* ${escapeMarkdown(partnerData.category || 'Не указана')}\n` +
        `📅 *Дата размещения:* ${partnerData.date_release || 'Не указана'}\n` +
        `🔗 *Ссылка:* ${escapeMarkdownUrl(partnerUrl)}\n\n` +
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
      const creds = parsedCredentials;
      const accessToken = await getAccessToken(env, creds);
      const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

      // Собираем статистику ТОЛЬКО по этому партнеру
      const partnerUrl = partnerData.url || partnerData.link; // Support both field names
      const partnerClicks = clicks.filter(c => c.url === partnerUrl);

      if (partnerClicks.length === 0) {
        const keyboard = new InlineKeyboard().text('« Назад', 'representative_cabinet');
        await ctx.editMessageText(
          `📊 *Ежемесячный отчет*\n\n` +
          `🏷️ *Партнер:* ${escapeMarkdown(partnerData.title)}\n\n` +
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
        `🏷️ *Ваш партнер:* ${escapeMarkdown(partnerData.title)}\n` +
        `📁 *Категория:* ${escapeMarkdown(partnerData.category || 'Не указана')}\n` +
        `📅 *Дата размещения:* ${partnerData.date_release || 'Не указана'}\n` +
        `🔗 *Ссылка:* ${escapeMarkdownUrl(partnerUrl)}\n\n` +
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
      const creds = parsedCredentials;
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
      const creds = parsedCredentials;
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

  // Установка команд меню для бота
  bot.api.setMyCommands([
    { command: 'start', description: 'Начать работу с ботом' },
    { command: 'profile', description: 'Посмотреть свой профиль и достижения' },
    { command: 'referrals', description: 'Реферальная программа' },
    { command: 'donate', description: 'Поддержать проект' },
    { command: 'feedback', description: 'Связаться с поддержкой' }
  ]).catch(error => {
    console.error('Error setting bot commands:', error);
  });

  return bot;
}

// ═══════════════════════════════════════════════════════════════
// EXPRESS APP SETUP
// ═══════════════════════════════════════════════════════════════

const app = express();

// ═══════════════════════════════════════════════════════════════
// GLOBAL BOT INSTANCE (will be initialized after all setup)
// ═══════════════════════════════════════════════════════════════
let globalBot;

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
    const handleUpdate = webhookCallback(globalBot, 'express');
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

    const creds = parsedCredentials;
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
    const partners = await getCachedPartners(env);

    // Filter and format partners
    // Support both 'url'/'link' and 'logo_url'/'logo' field names
    const formattedPartners = partners
      .filter(p => !!p.title && !!(p.url || p.link))
      .map(p => ({
        id: p.id || p.title,
        title: p.title,
        url: p.url || p.link,
        logo_url: p.logo_url || p.logo || '',
        description: p.description || '',
        category: p.category || 'Другое',
        promocode: p.promocode || p.promo_code || p['Промокод'] || p['промокод'] || p.PromoCode || p.Promocode || '',
        predstavitel: p.predstavitel || ''
      }));

    res.json({
      ok: true,
      partners: formattedPartners
    });
  } catch (error) {
    console.error('[API /partners] ❌ Error:', error);
    console.error('[API /partners] Error stack:', error.stack);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Diagnostic endpoint for broadcasts sheet
app.get('/api/debug/broadcasts', async (req, res) => {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);

    // Try to read broadcasts sheet
    let broadcasts = [];
    let readError = null;
    try {
      broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
    } catch (error) {
      readError = error.message;
    }

    // Try to write a test row
    let writeError = null;
    let writeSuccess = false;
    let writeResult = null;
    try {
      const testData = [
        'TEST_' + Date.now(),
        'Test Broadcast',
        new Date().toISOString().split('T')[0],
        new Date().toISOString().split('T')[1].split('.')[0],
        '0', '0', '0', '', '', '', '', '0', '0', '0', ''
      ];
      writeResult = await appendSheetRow(env.SHEET_ID, 'broadcasts', testData, accessToken);
      writeSuccess = !writeResult.error;
      if (writeResult.error) {
        writeError = JSON.stringify(writeResult.error);
      }
    } catch (error) {
      writeError = error.message;
    }

    // Re-read to check if write worked
    let broadcastsAfterWrite = [];
    try {
      broadcastsAfterWrite = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
    } catch (error) {
      // ignore
    }

    res.json({
      ok: true,
      sheet_exists: !readError,
      read_error: readError,
      broadcasts_count_before: broadcasts.length,
      broadcasts_count_after: broadcastsAfterWrite.length,
      broadcasts_sample: broadcastsAfterWrite.slice(-3), // Last 3
      write_test: writeSuccess ? 'success' : 'failed',
      write_error: writeError,
      write_result: writeResult,
      sheet_id: env.SHEET_ID
    });
  } catch (error) {
    console.error('[DEBUG] Error checking broadcasts:', error);
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

    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);

    // Get partners to find partner title
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    const partner = partners.find(p => (p.id || p.title) === partner_id);

    if (!partner) {
      return res.status(404).json({ error: 'Partner not found', success: false });
    }

    console.log(`[API] 📋 Partner data for ${partner.title}:`, {
      title: partner.title,
      has_promocode: !!partner.promocode,
      promocode: partner.promocode,
      all_keys: Object.keys(partner)
    });

    // Get clicks sheet
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);

    // Determine the URL to use for matching
    const clickUrl = partner_url || partner.url || partner.link;

    console.log(`[API] 🔍 Searching for existing click: user=${user_id}, url=${clickUrl}`);

    // Check if user already clicked this exact URL (more specific than just title)
    const existingClickIndex = clicks.findIndex(c =>
      String(c.telegram_id) === String(user_id) &&
      c.url === clickUrl
    );

    console.log(`[API] 🔍 Found existing click at index: ${existingClickIndex}`);

    const currentTimestamp = new Date().toISOString();

    if (existingClickIndex !== -1) {
      // Update existing click
      const existingClick = clicks[existingClickIndex];
      const newCount = parseInt(existingClick.click || 1) + 1;
      const rowIndex = existingClickIndex + 2;

      // Get user's first name from users table
      const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const userRecord = users.find(u => String(u.telegram_id) === String(user_id));
      const firstName = userRecord ? userRecord.first_name || userRecord.first_name || 'Unknown' : 'Unknown';

      // Get partner's category from partners table
      const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
      const partnerRecord = partners.find(p => p.title === partner.title);
      const category = partnerRecord ? partnerRecord.category || '' : '';

      await updateSheetRow(
        env.SHEET_ID,
        'clicks',
        rowIndex,
        [
          user_id,                    // telegram_id
          username || '',             // username
          firstName,                  // first_name
          partner.title,              // title
          category,                   // category
          partner_url || partner.url || partner.link, // url - support both field names
          String(newCount),           // click
          partner.date_release || '', // date_release (from partners table)
          existingClick.first_click_date || existingClick.first_click || currentTimestamp, // first_click_date
          currentTimestamp,           // last_click_date
          new Date().toLocaleTimeString('ru-RU'), // last_click_time
          currentTimestamp,           // timestamp
          '0'                         // conversion (calculated separately)
        ],
        accessToken
      );

      console.log(`[API] 🔄 Updated click for user ${user_id} on partner ${partner.title}: count=${newCount}`);
    } else {
      // Add new click record
      // Get user's first name from users table
      const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const userRecord = users.find(u => String(u.telegram_id) === String(user_id));
      const firstName = userRecord ? userRecord.first_name || userRecord.first_name || 'Unknown' : 'Unknown';

      // Get partner's category from partners table
      const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
      const partnerRecord = partners.find(p => p.title === partner.title);
      const category = partnerRecord ? partnerRecord.category || '' : '';

      await appendSheetRow(
        env.SHEET_ID,
        'clicks',
        [
          user_id,                    // telegram_id
          username || '',             // username
          firstName,                  // first_name
          partner.title,              // title
          category,                   // category
          partner_url || partner.url || partner.link, // url - support both field names
          '1',                        // click
          partner.date_release || '', // date_release (from partners table)
          currentTimestamp,           // first_click_date
          currentTimestamp,           // last_click_date
          new Date().toLocaleTimeString('ru-RU'), // last_click_time
          currentTimestamp,           // timestamp
          '0'                         // conversion (calculated separately)
        ],
        accessToken
      );

      console.log(`[API] 🆕 New click registered: user ${user_id} on partner ${partner.title}`);
    }

    // Update conversion rate for this partner
    try {
      await updateConversionRate(env, partner.title);
    } catch (error) {
      console.error(`[CONVERSION] Error updating conversion rate for partner ${partner.title}:`, error);
    }

    // Send promocode if available
    // Check for different possible field names for promocodes
    const promocode = partner.promocode || partner.promo_code || partner['Промокод'] || partner['промокод'] || partner.PromoCode || partner.Promocode || '';

    // Check if user is admin (admins always get promocodes for testing)
    const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
    const isAdmin = admins.some(a => {
      const idMatch = a.telegram_id && String(a.telegram_id) === String(user_id);
      return idMatch;
    });

    console.log(`[PROMOCODE-DEBUG] Checking promocode for partner ${partner.title}:`, {
      has_promocode: !!promocode,
      promocode_value: promocode,
      promocode_length: promocode ? promocode.length : 0,
      is_empty_after_trim: promocode ? promocode.trim() === '' : true,
      partner_keys: Object.keys(partner),
      is_first_click: existingClickIndex === -1,
      is_admin: isAdmin
    });

    // Track if promocode was actually sent
    let promocodeSentSuccessfully = false;
    let promocodeAlreadySent = false;

    if (promocode && promocode.trim() !== '') {
      // Admins ALWAYS get promocodes (for testing), regular users only on FIRST click
      const shouldSendPromocode = isAdmin || existingClickIndex === -1;

      if (shouldSendPromocode) {
        const clickType = isAdmin ? 'admin (always send)' : 'first click';
        console.log(`[PROMOCODE] 🎯 Sending promocode "${promocode}" from ${partner.title} to user ${user_id} (${clickType})`)
        try {
          const message = `🎁 <b>Промокод от ${partner.title}</b>\n\n` +
            `<code>${promocode}</code>\n\n` +
            `Скопируйте промокод и используйте его на сайте партнера!\n\n` +
            `<i>Это сообщение будет автоматически удалено через 24 часа</i>`;

          const sentMessage = await globalBot.api.sendMessage(user_id, message, { parse_mode: 'HTML' });

          // Save message info for auto-deletion
          const deleteAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
          await redis.setex(
            `promo_msg_${user_id}_${Date.now()}`,
            86400, // 24 hours in seconds
            JSON.stringify({
              chat_id: user_id,
              message_id: sentMessage.message_id,
              partner: partner.title,
              delete_at: deleteAt
            })
          );

          promocodeSentSuccessfully = true;
          console.log(`[PROMOCODE] ✅ Sent promocode from ${partner.title} to user ${user_id}`);
        } catch (error) {
          console.error(`[PROMOCODE] ❌ Failed to send promocode:`, {
            error_code: error.error_code,
            description: error.description,
            message: error.message
          });

          // Check if user blocked the bot
          if (error.error_code === 403) {
            console.error(`[PROMOCODE] 🚫 User ${user_id} has blocked the bot`);
          }
        }
      } else {
        // Repeat click - promocode was already sent (only for non-admin users)
        promocodeAlreadySent = true;
        console.log(`[PROMOCODE] 🔁 Promocode already sent for ${partner.title} to user ${user_id} (repeat click, non-admin)`);
      }
    } else {
      console.log(`[PROMOCODE] ⏭️ No promocode to send for ${partner.title} (promocode is empty or missing)`);
    }

    // Check for "Молодой хомяк" achievement (first partner click)
    const totalClicks = clicks.filter(c => String(c.telegram_id) === String(user_id)).length;
    if (totalClicks >= 1) {
      await checkAndUnlockAchievements(env, user_id, 'partner_click', totalClicks);
    }

    // Return click count
    const clickCount = existingClickIndex !== -1
      ? parseInt(clicks[existingClickIndex].click_count || 1) + 1
      : 1;

    res.json({
      ok: true,
      success: true,
      clicks: clickCount,
      promocode_sent: promocodeSentSuccessfully,
      promocode_already_sent: promocodeAlreadySent
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

    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const existing = users.find(u => String(u.telegram_id) === String(id));
    const currentDate = new Date().toISOString().split('T')[0];

    // Get user avatar URL
    const avatarUrl = await getUserAvatarUrl(id);

    if (!existing) {
      // Check if user is admin
      const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
      const isAdmin = admins.some(a => {
        const idMatch = a.telegram_id && String(a.telegram_id) === String(id);
        return idMatch;
      });

      // Determine registration number
      let registrationNumber;
      if (isAdmin) {
        // For admins: count existing admins and assign a_N
        const adminUsers = users.filter(u => u.registration_number && String(u.registration_number).startsWith('a_'));
        registrationNumber = `a_${adminUsers.length + 1}`;
      } else {
        // For regular users: count non-admin users and assign number
        const regularUsers = users.filter(u => u.registration_number && !String(u.registration_number).startsWith('a_'));
        registrationNumber = String(regularUsers.length + 1);
      }

      await appendSheetRow(
        env.SHEET_ID,
        'users',
        [
          id,                        // telegram_id
          username || 'N/A',         // username
          first_name || 'Unknown',   // first_name
          currentDate,               // date_registered
          'бот запущен',             // bot_started
          currentDate,               // last_active
          '0',                       // total_points
          '0',                       // current_streak
          '0',                       // longest_streak
          currentDate,               // last_active_date
          '0',                       // referrals_count
          '0',                       // education_views_count
          '0',                       // events_registered
          '0',                       // partners_subscribed
          '0',                       // total_donations
          String(registrationNumber), // registration_number
          avatarUrl || ''            // avatar_url
        ],
        accessToken
      );
      console.log(`[API] 🆕 New user registered via API: ${id}, registration #${registrationNumber}, avatar: ${avatarUrl ? 'yes' : 'no'}`);
    } else {
      // Update existing user with all fields
      const userIndex = users.findIndex(u => String(u.telegram_id) === String(id));
      if (userIndex !== -1) {
        const rowIndex = userIndex + 2;
        await updateSheetRow(
          env.SHEET_ID,
          'users',
          rowIndex,
          [
            id,                                          // telegram_id
            username || existing.username || 'N/A',      // username
            first_name || existing.first_name || 'Unknown', // first_name
            existing.date_registered || currentDate,     // date_registered
            'бот запущен',                               // bot_started
            currentDate,                                 // last_active (update)
            String(existing.total_points || '0'),        // total_points
            String(existing.current_streak || '0'),      // current_streak
            String(existing.longest_streak || '0'),      // longest_streak
            existing.last_active_date || currentDate,    // last_active_date
            String(existing.referrals_count || '0'),     // referrals_count
            String(existing.education_views_count || '0'), // education_views_count
            String(existing.events_registered || '0'),   // events_registered
            String(existing.partners_subscribed || '0'), // partners_subscribed
            String(existing.total_donations || '0'),     // total_donations
            String(existing.registration_number || ''),  // registration_number
            avatarUrl || existing.avatar_url || ''       // avatar_url (update if available)
          ],
          accessToken
        );
        console.log(`[API] 🔄 User updated via API: ${id}, avatar: ${avatarUrl ? 'updated' : 'kept'}`);
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

    const creds = parsedCredentials;
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
    const creds = parsedCredentials;
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

// Get educational materials from obrazovach sheet
app.get('/api/obrazovach', async (req, res) => {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);

    console.log('[API] Attempting to fetch data from obrazovach sheet...');

    let materials = [];
    try {
      materials = await getSheetData(env.SHEET_ID, 'obrazovach', accessToken);
      console.log('[API] Raw materials from sheet:', materials);
    } catch (sheetError) {
      console.error('[API] Error reading obrazovach sheet:', sheetError);
      // Return empty array if sheet doesn't exist
      return res.json({
        ok: true,
        materials: []
      });
    }

    // Filter and format educational materials
    const formattedMaterials = materials
      .filter(m => m.url_cover && m.title && m.url_video) // Only valid entries
      .map(m => ({
        id: m.id || m.title,
        url_cover: m.url_cover,
        title: m.title,
        subtitle: m.subtitle || '',
        url_video: m.url_video,
        text_button: m.text_button || 'Смотреть видео'
      }));

    console.log('[API] Formatted materials:', formattedMaterials);

    res.json({
      ok: true,
      materials: formattedMaterials
    });
  } catch (error) {
    console.error('[API] Error getting educational materials:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Send video message to user via bot
app.post('/api/send-video', async (req, res) => {
  try {
    const { user_id, username, video_url, title, subtitle, url_cover } = req.body;

    if (!user_id || !video_url) {
      return res.status(400).json({ error: 'Missing required fields', success: false });
    }

    // Rate limiting
    await checkRateLimit(env, `send_video:${user_id}`, 5, 60);

    // Send video message to user via bot

    // Create caption with title and subtitle
    let caption = `🎥 <b>${title || 'Образовательное видео'}</b>`;
    if (subtitle) {
      caption += `\n\n${subtitle}`;
    }

    const keyboard = new InlineKeyboard().url('▶️ Открыть видео', video_url);

    // Send photo with caption and button if url_cover is provided
    let sentMessage;
    if (url_cover && url_cover.trim() !== '') {
      try {
        sentMessage = await globalBot.api.sendPhoto(user_id, url_cover, {
          caption: caption + '\n\n<i>Это сообщение будет автоматически удалено через 24 часа</i>',
          parse_mode: 'HTML',
          reply_markup: keyboard
        });
        console.log(`[API] ✅ Photo message sent to user ${user_id}: ${title}`);
      } catch (photoError) {
        console.error(`[API] ⚠️ Failed to send photo, falling back to text message:`, photoError.message);
        // Fallback to text message if photo fails
        sentMessage = await globalBot.api.sendMessage(user_id, caption + '\n\n<i>Это сообщение будет автоматически удалено через 24 часа</i>', {
          parse_mode: 'HTML',
          reply_markup: keyboard
        });
      }
    } else {
      // Send text message if no cover image
      sentMessage = await globalBot.api.sendMessage(user_id, caption + '\n\n<i>Это сообщение будет автоматически удалено через 24 часа</i>', {
        parse_mode: 'HTML',
        reply_markup: keyboard
      });
      console.log(`[API] ✅ Text message sent to user ${user_id}: ${title}`);
    }

    // Save message info for auto-deletion
    const deleteAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await redis.setex(
      `video_msg_${user_id}_${Date.now()}`,
      86400, // 24 hours in seconds
      JSON.stringify({
        chat_id: user_id,
        message_id: sentMessage.message_id,
        video_title: title,
        delete_at: deleteAt
      })
    );
    console.log(`[API] 📅 Video message scheduled for deletion in 24 hours: ${title}`);

    // Check if this video was already viewed by this user
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);

    let educationViews = [];
    try {
      educationViews = await getSheetData(env.SHEET_ID, 'education_views', accessToken);
    } catch (error) {
      console.log('[API] education_views sheet does not exist yet, will create on first view');
      educationViews = [];
    }

    // Check if user already viewed this specific video
    const alreadyViewed = educationViews.some(view =>
      String(view.telegram_id) === String(user_id) &&
      view.video_url === video_url
    );

    if (!alreadyViewed) {
      // This is a new unique video view - record it
      const currentDate = new Date().toISOString().split('T')[0];
      const currentTime = new Date().toISOString().split('T')[1].split('.')[0];

      await appendSheetRow(
        env.SHEET_ID,
        'education_views',
        [
          user_id,           // telegram_id
          username || '',    // username
          title || '',       // title
          video_url,         // video_url
          currentDate,       // view_date
          currentTime        // view_time
        ],
        accessToken
      );

      // Update user's education views count (only for unique videos)
      const userStats = await getUserStats(env, user_id);
      const updatedStats = await updateUserStats(env, user_id, {
        education_views_count: (userStats.education_views_count || 0) + 1
      });

      // Check for education view achievement
      await checkAndUnlockAchievements(env, user_id, 'education_view', updatedStats.education_views_count);

      console.log(`[API] ✅ New unique video view recorded for user ${user_id}: ${title}`);
    } else {
      console.log(`[API] ℹ️ User ${user_id} already viewed this video: ${title}`);
    }

    res.json({
      ok: true,
      success: true,
      message_sent: true
    });
  } catch (error) {
    console.error('[API] Error sending video message:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Robots.txt - disallow indexing
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *
Disallow: /
`);
});

// ═══════════════════════════════════════════════════════════════
// ACHIEVEMENT SYSTEM API ENDPOINTS
// ═══════════════════════════════════════════════════════════════

// Quick profile endpoint for profile card (name + points only)
app.get('/api/profile/quick/:tg_id', async (req, res) => {
  try {
    const { tg_id } = req.params;

    if (!tg_id) {
      return res.status(400).json({ error: 'Missing tg_id parameter', success: false });
    }

    // Get cached stats (fast)
    const userStats = await getUserStats(env, tg_id);

    // Get user name from cache or fetch minimal data
    const cacheKey = `user_profile_quick:${tg_id}`;
    let userData = await env.BROADCAST_STATE.get(cacheKey);

    if (!userData) {
      // Fetch only user data
      const creds = parsedCredentials;
      const accessToken = await getAccessToken(env, creds);
      const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const user = users.find(u => String(u.telegram_id) === String(tg_id));

      if (!user) {
        return res.status(404).json({ error: 'User not found', success: false });
      }

      userData = {
        first_name: user.first_name,
        username: user.username,
        avatar_url: user.avatar_url || null
      };

      // Cache for 5 minutes
      await env.BROADCAST_STATE.put(cacheKey, JSON.stringify(userData), {
        expirationTtl: 300
      });
    } else {
      userData = JSON.parse(userData);
    }

    res.json({
      success: true,
      user: userData,
      stats: {
        total_points: userStats.total_points || 0
      }
    });
  } catch (error) {
    console.error('[API] Error getting quick profile:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Get user profile
app.get('/api/profile/:tg_id', async (req, res) => {
  try {
    const { tg_id } = req.params;
    
    if (!tg_id) {
      return res.status(400).json({ error: 'Missing tg_id parameter', success: false });
    }

    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    
    const user = users.find(u => String(u.telegram_id) === String(tg_id));
    
    if (!user) {
      return res.status(404).json({ error: 'User not found', success: false });
    }

    // Get user stats
    const userStats = await getUserStats(env, tg_id);
    
    // Get achievements
    const achievements = await initializeAchievements(env);
    const userAchievements = [];
    
    for (const achievement of achievements) {
      const progress = await getUserAchievementProgress(env, tg_id, achievement.id);
      userAchievements.push({
        slug: achievement.slug,
        title: achievement.title,
        description: achievement.description,
        points: achievement.points,
        rarity: achievement.rarity,
        icon_emoji: achievement.icon_emoji,
        is_unlocked: progress.is_unlocked,
        progress: progress.progress,
        required: achievement.condition_value,
        unlocked_at: progress.unlocked_at
      });
    }

    // Get recent activity (placeholder)
    const recentActivity = [
      {
        type: 'achievement_unlocked',
        title: 'Новое достижение: 🔥 Активный хомяк',
        timestamp: new Date().toISOString()
      },
      {
        type: 'referral_joined',
        title: `Ваш друг @new_user присоединился!`,
        timestamp: new Date(Date.now() - 86400000).toISOString() // Yesterday
      }
    ];

    const profileData = {
      user: {
        tg_id: user.telegram_id,
        username: user.username,
        first_name: user.first_name,
        avatar_url: user.avatar_url || null,
        registration_number: user.registration_number || null,
        created_at: user.date_registered
      },
      stats: {
        total_points: userStats.total_points || 0,
        current_streak: userStats.current_streak || 0,
        longest_streak: userStats.longest_streak || 0,
        referrals_count: userStats.referrals_count || 0,
        achievements_unlocked: userAchievements.filter(a => a.is_unlocked).length,
        achievements_total: achievements.length
      },
      achievements: userAchievements,
      recent_activity: recentActivity
    };

    res.json({
      success: true,
      ...profileData
    });
  } catch (error) {
    console.error('[API] Error getting profile:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Get referral link
app.get('/api/referral/link', async (req, res) => {
  try {
    const { tg_id } = req.query;
    
    if (!tg_id) {
      return res.status(400).json({ error: 'Missing tg_id parameter', success: false });
    }

    const userStats = await getUserStats(env, tg_id);
    const link = `https://t.me/${env.BOT_USERNAME || 'okolotattoo_bot'}?start=ref_${tg_id}`;

    res.json({
      success: true,
      link: link,
      referrals_count: userStats.referrals_count || 0,
      total_earned_points: (userStats.referrals_count || 0) * 10 // 10 points per referral
    });
  } catch (error) {
    console.error('[API] Error getting referral link:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Get referral list
app.get('/api/referral/list', async (req, res) => {
  try {
    const { tg_id } = req.query;
    
    if (!tg_id) {
      return res.status(400).json({ error: 'Missing tg_id parameter', success: false });
    }

    // In a real implementation, this would fetch from the referrals sheet
    // For now, we'll return placeholder data based on user stats
    const userStats = await getUserStats(env, tg_id);
    
    // Placeholder referrals list
    const referrals = [];
    for (let i = 1; i <= Math.min(userStats.referrals_count || 0, 10); i++) {
      referrals.push({
        username: `referral_user${i}`,
        first_name: `Referral ${i}`,
        joined_at: new Date(Date.now() - (i * 86400000)).toISOString(), // Different days ago
        is_active: true
      });
    }

    res.json({
      success: true,
      referrals: referrals
    });
  } catch (error) {
    console.error('[API] Error getting referral list:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Get leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const { limit = 100 } = req.query;

    // In a real implementation, this would fetch from a sorted list of users by points
    // For now, we'll return placeholder data
    const leaderboard = [];
    for (let i = 1; i <= Math.min(parseInt(limit), 10); i++) {
      leaderboard.push({
        rank: i,
        username: `top_user${i}`,
        first_name: `Top User ${i}`,
        total_points: 1500 - (i * 100),
        achievements_count: 8 - Math.floor(i / 2)
      });
    }

    // Placeholder user rank (for demo purposes)
    const userRank = 42;
    const userPoints = 280;

    res.json({
      success: true,
      leaderboard: leaderboard,
      user_rank: userRank,
      user_points: userPoints
    });
  } catch (error) {
    console.error('[API] Error getting leaderboard:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Widget profile API (minimal data for profile card)
app.get('/api/widget/profile/:tg_id', async (req, res) => {
  try {
    const { tg_id } = req.params;
    
    if (!tg_id) {
      return res.status(400).json({ error: 'Missing tg_id parameter', success: false });
    }

    const userStats = await getUserStats(env, tg_id);
    const achievements = await initializeAchievements(env);
    
    // Get unlocked achievements for widget
    const unlockedAchievements = [];
    for (const achievement of achievements) {
      const progress = await getUserAchievementProgress(env, tg_id, achievement.id);
      if (progress.is_unlocked) {
        unlockedAchievements.push(achievement.icon_emoji);
      }
    }

    // Get next achievement for progress
    let nextAchievement = null;
    for (const achievement of achievements) {
      const progress = await getUserAchievementProgress(env, tg_id, achievement.id);
      if (!progress.is_unlocked && achievement.condition_value) {
        nextAchievement = {
          title: achievement.title,
          progress: Math.min(100, Math.round((progress.progress / achievement.condition_value) * 100)),
          progress_text: `${progress.progress}/${achievement.condition_value} ${achievement.condition_type}`
        };
        break;
      }
    }

    // Placeholder data for username and first name
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    const user = users.find(u => String(u.telegram_id) === String(tg_id));

    res.json({
      success: true,
      avatar_url: user?.avatar_url || null,
      username: user?.username?.replace('@', '') || 'unknown_user',
      first_name: user?.first_name || 'Unknown',
      total_points: userStats.total_points || 0,
      rank: userStats.registration_number || '?',
      achievements_unlocked: unlockedAchievements,
      next_achievement: nextAchievement
    });
  } catch (error) {
    console.error('[API] Error getting widget profile:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// Get spreadsheet structure
app.get('/api/spreadsheet/structure', async (req, res) => {
  try {
    const creds = parsedCredentials;
    const accessToken = await getAccessToken(env, creds);
    
    // Get all sheet names
    const sheetNames = await getAllSheetNames(env.SHEET_ID, accessToken);
    
    const structure = {};
    
    // Get headers for each sheet
    for (const sheetName of sheetNames) {
      try {
        const sampleData = await getSheetData(env.SHEET_ID, sheetName, accessToken);
        if (sampleData.length > 0) {
          // Headers are the keys of the first row object
          const headers = Object.keys(sampleData[0]);
          structure[sheetName] = {
            columns: headers,
            sample_row_count: sampleData.length
          };
        } else {
          // If no data, try to get just the headers by reading first row
          const range = `${sheetName}!A1:Z1`;
          const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEET_ID}/values/${range}`;
          const response = await fetch(url, {
            headers: { Authorization: `Bearer ${accessToken}` },
          });
          const data = await response.json();
          
          if (data.values && data.values[0]) {
            structure[sheetName] = {
              columns: data.values[0],
              sample_row_count: 0
            };
          } else {
            structure[sheetName] = {
              columns: [],
              sample_row_count: 0
            };
          }
        }
      } catch (error) {
        console.error(`Error getting structure for sheet ${sheetName}:`, error);
        structure[sheetName] = {
          columns: [],
          error: error.message
        };
      }
    }
    
    res.json({
      success: true,
      spreadsheet_id: env.SHEET_ID,
      sheets: structure,
      total_sheets: Object.keys(structure).length
    });
  } catch (error) {
    console.error('[API] Error getting spreadsheet structure:', error);
    res.status(500).json({ error: error.message, success: false });
  }
});

// ═══════════════════════════════════════════════════════════════
// 404 AND ERROR HANDLERS (must be last)
// ═══════════════════════════════════════════════════════════════

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

    // Delete old messages (promocodes and videos)
    const messagesResult = await deleteOldMessages(env);
    console.log('[CRON] 🗑️ Messages cleanup result:', messagesResult);
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
// INITIALIZE GLOBAL BOT BEFORE SERVER START
// ═══════════════════════════════════════════════════════════════
globalBot = setupBot(env);
console.log('[BOT] ✅ Global bot initialized successfully');

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
