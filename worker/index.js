// Cloudflare Worker с grammY + API + Админ-панель в боте
// Version: 1.0.1 - Auto-deploy test
import { Bot, webhookCallback, InlineKeyboard } from 'grammy';

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

// ═══════════════════════════════════════════════════════════════
// GOOGLE SHEETS API
// ═══════════════════════════════════════════════════════════════

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

  // Очищаем private key от заголовков и пробелов
  const cleanedKey = creds.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\\n/g, '')
    .replace(/\n/g, '')
    .replace(/\s/g, '');
  
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    str2ab(cleanedKey),
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
  try {
    const binaryString = atob(str);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error) {
    console.error('str2ab error:', error, 'Input length:', str?.length);
    throw error;
  }
}

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
  return response.json();
}

async function updateSheetRow(sheetId, sheetName, rowIndex, values, accessToken) {
  // rowIndex - это индекс строки (1-based, где 1 = заголовок, 2 = первая строка данных)
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
  return response.json();
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

async function deleteSheetRow(spreadsheetId, sheetName, rowIndex, accessToken) {
  // Получаем внутренний ID листа
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
            startIndex: rowIndex - 1, // 0-based индекс для API
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
    // Если получили ошибку - пользователь заблокировал бота или удалил аккаунт
    if (error.error_code === 403 || error.error_code === 400) {
      return false;
    }
    // Другие ошибки - считаем что активен
    return true;
  }
}

// ═══════════════════════════════════════════════════════════════
// ADMIN CHECK HELPER
// ═══════════════════════════════════════════════════════════════

async function checkAdmin(env, user) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
  
  const isAdmin = admins.some(a => {
    const usernameMatch = a.username && user.username && 
      a.username.toLowerCase().replace('@', '') === user.username.toLowerCase().replace('@', '');
    const idMatch = a.telegram_id && String(a.telegram_id) === String(user.id);
    return usernameMatch || idMatch;
  });
  
  console.log(`Admin check for ${user.username} (${user.id}):`, isAdmin);
  return isAdmin;
}

// Проверка, является ли пользователь представителем партнера
async function checkRepresentative(env, user) {
  try {
    if (!user.username) {
      return null; // Нет username - не может быть представителем
    }
    
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(creds);
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    
    const username = user.username.toLowerCase();
    
    // Ищем партнера, где этот пользователь является представителем
    const partnerData = partners.find(p => 
      p.predstavitel && 
      p.predstavitel.toLowerCase().replace('@', '') === username
    );
    
    console.log(`Representative check for ${user.username}:`, partnerData ? partnerData.title : 'not found');
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
// BOT SETUP WITH GRAMMY
// ═══════════════════════════════════════════════════════════════

function setupBot(env) {
  const bot = new Bot(env.BOT_TOKEN);

  // ═══════════════════════════════════════════════════════════
  // КОМАНДА /START
  // ═══════════════════════════════════════════════════════════
  
  bot.command('start', async (ctx) => {
    const user = ctx.from;
    const chatId = ctx.chat.id;
    
    // Регистрируем пользователя
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(creds);
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
          'TRUE',                        // bot_started
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
          existing.bot_started !== 'TRUE' ||
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
              'TRUE',                              // bot_started (обновляем на TRUE)
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
      keyboard.row().text('📊 Личный кабинет представителя', 'representative_cabinet');
    }
    
    await ctx.reply(
      `👋 *Привет, ${user.first_name}!*\n\nДобро пожаловать в наш Mini App!\n\n🔗 Нажми кнопку ниже чтобы открыть приложение с партнерскими ссылками.`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  // ═══════════════════════════════════════════════════════════
  // ОБРАБОТКА CALLBACK QUERIES
  // ═══════════════════════════════════════════════════════════
  
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
    const accessToken = await getAccessToken(creds);
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
    const accessToken = await getAccessToken(creds);
    
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
    const accessToken = await getAccessToken(creds);
    
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
      '📢 *Создание рассылки*\n\n*Шаг 1 из 5:* Название рассылки\n\n📝 Введите *название* рассылки для аналитики (например: "Акция Январь 2026"):',
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
      '📢 *Создание рассылки*\n\n*Шаг 3 из 4:* Медиа\n\n🖼️📹🎙️ *Прикрепите медиа* (фото/видео/голосовое/видеозаметку) или отправьте ссылку на фото/видео (URL):',
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
      '📢 *Создание рассылки*\n\n*Шаг 4 из 4:* Кнопка\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
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
      const accessToken = await getAccessToken(creds);
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
      const accessToken = await getAccessToken(creds);
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
      const accessToken = await getAccessToken(creds);
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

  // ═══════════════════════════════════════════════════════════
  // ОТЧЕТЫ ПО ПАРТНЕРАМ (для администраторов)
  // ═══════════════════════════════════════════════════════════

  // Список партнеров для выбора
  bot.callbackQuery('admin_partner_reports', async (ctx) => {
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) {
      await ctx.answerCallbackQuery('❌ У вас нет прав администратора');
      return;
    }
    
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(creds);
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
    const accessToken = await getAccessToken(creds);
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
      const accessToken = await getAccessToken(creds);
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
      keyboard.row().text('📊 Личный кабинет представителя', 'representative_cabinet');
    }
    
    await ctx.editMessageText(
      `👋 *Привет, ${user.first_name}!*\n\nДобро пожаловать в наш Mini App!\n\n🔗 Нажми кнопку ниже чтобы открыть приложение с партнерскими ссылками.`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
  });

  // ═══════════════════════════════════════════════════════════
  // ЛИЧНЫЙ КАБИНЕТ ПРЕДСТАВИТЕЛЯ
  // ═══════════════════════════════════════════════════════════

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
      .text('« Назад', 'back_to_start');
    
    await ctx.editMessageText(
      `📊 *Личный кабинет представителя*\n\n` +
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
      const accessToken = await getAccessToken(creds);
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
      const accessToken = await getAccessToken(creds);
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

  // ═══════════════════════════════════════════════════════════
  // ОБРАБОТКА ТЕКСТОВЫХ СООБЩЕНИЙ (для рассылки)
  // ═══════════════════════════════════════════════════════════
  
  bot.on('message:text', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state) return;
    
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;
    
    const text = ctx.message.text;
    let keyboard;
    
    if (state.step === 'broadcast_name') {
      state.broadcast_name = text;
      state.step = 'title';
      keyboard = new InlineKeyboard().text('❌ Отменить', 'broadcast_cancel');
      
      await saveBroadcastState(env, ctx.chat.id, state);
      await ctx.reply(
        `📢 *Создание рассылки*\n\n*Шаг 2 из 5:* Заголовок\n\n✅ Название сохранено:\n"${text}"\n\n📝 Введите *заголовок* рассылки (обязательно):`,
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
        `📢 *Создание рассылки*\n\n*Шаг 3 из 5:* Подзаголовок\n\n✅ Заголовок сохранен:\n"${text}"\n\n📝 Введите *подзаголовок* (описание):`,
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
        '📢 *Создание рассылки*\n\n*Шаг 4 из 5:* Медиа\n\n🖼️📹🎙️ *Прикрепите медиа* (фото/видео/голосовое/видеозаметку) или отправьте ссылку на фото/видео (URL):',
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
        '📢 *Создание рассылки*\n\n*Шаг 5 из 5:* Кнопка\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
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

  // ═══════════════════════════════════════════════════════════
  // ОБРАБОТКА МЕДИА (для рассылки)
  // ═══════════════════════════════════════════════════════════
  
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
      '📢 *Создание рассылки*\n\n*Шаг 5 из 5:* Кнопка\n\n✅ Картинка загружена!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
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
      '📢 *Создание рассылки*\n\n*Шаг 5 из 5:* Кнопка\n\n✅ Видео загружено!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
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
      '📢 *Создание рассылки*\n\n*Шаг 5 из 5:* Кнопка\n\n✅ Голосовое сообщение загружено!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
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
      '📢 *Создание рассылки*\n\n*Шаг 5 из 5:* Кнопка\n\n✅ Видеозаметка загружена!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com',
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  });

  return bot;
}

// ═══════════════════════════════════════════════════════════════
// BROADCAST HELPERS
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

async function executeBroadcast(ctx, env, state) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
  
  let messageText = '';
  if (state.title) messageText += `*${state.title}*\n`;
  if (state.subtitle) messageText += `\n${state.subtitle}`;
  
  // Создаем промежуточную ссылку для отслеживания кликов
  let keyboard = null;
  if (state.button_text && state.button_url) {
    // Кодируем URL партнера
    const encodedPartnerUrl = encodeURIComponent(state.button_url);
    // Создаем ссылку через наш воркер для отслеживания
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
  
  for (const user of validUsers) {
    try {
      if (mediaType === 'photo') {
        await ctx.api.sendPhoto(user.telegram_id, mediaSource, {
          caption: messageText,
          parse_mode: 'Markdown',
          reply_markup: keyboard
        });
      } else if (mediaType === 'video') {
        await ctx.api.sendVideo(user.telegram_id, mediaSource, {
          caption: messageText,
          parse_mode: 'Markdown',
          reply_markup: keyboard
        });
      } else if (mediaType === 'voice') {
        if (messageText) {
          await ctx.api.sendMessage(user.telegram_id, messageText, {
            parse_mode: 'Markdown',
            reply_markup: keyboard
          });
        }
        await ctx.api.sendVoice(user.telegram_id, mediaSource);
      } else if (mediaType === 'video_note') {
        if (messageText) {
          await ctx.api.sendMessage(user.telegram_id, messageText, {
            parse_mode: 'Markdown',
            reply_markup: keyboard
          });
        }
        await ctx.api.sendVideoNote(user.telegram_id, mediaSource);
      } else {
        await ctx.api.sendMessage(user.telegram_id, messageText, {
          parse_mode: 'Markdown',
          reply_markup: keyboard
        });
      }
      successCount++;
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      failCount++;
      
      // Анализируем ошибку
      const errorCode = error.error_code;
      const errorDescription = error.description || error.message;
      
      console.error(`Failed to send to ${user.telegram_id}:`, errorCode, errorDescription);
      
      // Классифицируем ошибки
      if (errorCode === 403) {
        // Бот заблокирован пользователем
        inactiveUsers.push({
          telegram_id: user.telegram_id,
          username: user.username,
          date_on: user.date_registered || user.first_seen || '',
          reason: 'Заблокировал бота'
        });
        inactiveCount++;
      } else if (errorCode === 400 && errorDescription?.includes('chat not found')) {
        // Пользователь удалил аккаунт
        inactiveUsers.push({
          telegram_id: user.telegram_id,
          username: user.username,
          date_on: user.date_registered || user.first_seen || '',
          reason: 'Удалил аккаунт'
        });
        inactiveCount++;
      } else if (errorCode === 400 && errorDescription?.includes('user is deactivated')) {
        // Аккаунт деактивирован
        inactiveUsers.push({
          telegram_id: user.telegram_id,
          username: user.username,
          date_on: user.date_registered || user.first_seen || '',
          reason: 'Деактивирован'
        });
        inactiveCount++;
      } else {
        // Другие ошибки
        errors.push({
          telegram_id: user.telegram_id,
          username: user.username,
          error: `${errorCode}: ${errorDescription?.substring(0, 50) || 'Unknown'}`
        });
      }
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
  
  // Начальная конверсия = 0% (пока нет кликов)
  const conversionRate = '0.00%';
  
  // Сохраняем статистику в таблицу broadcasts
  let saveError = null;
  try {
    await appendSheetRow(
      env.SHEET_ID,
      'broadcasts',
      [
        state.broadcast_id || '',                    // broadcast_id
        state.broadcast_name || 'Без названия',      // name
        currentDate,                                  // date
        currentTime,                                  // time
        successCount,                                 // sent_count
        readCount,                                    // read_count (= sent_count)
        0,                                            // click_count (будет обновляться)
        conversionRate,                               // conversion_rate
        state.title || '',                            // title
        state.subtitle || '',                         // subtitle
        state.button_text || '',                      // button_text
        state.button_url || '',                       // button_url
        validUsers.length,                            // total_users
        failCount,                                    // fail_count
        inactiveCount                                 // archived_count
      ],
      accessToken
    );
    console.log(`[BROADCAST] ✅ Statistics saved to broadcasts sheet: ${state.broadcast_id} - ${state.broadcast_name}`);
  } catch (error) {
    saveError = error.message || String(error);
    console.error(`[BROADCAST] ❌ Failed to save statistics to broadcasts sheet:`, error);
    console.error(`[BROADCAST] ❌ Error details:`, JSON.stringify(error, null, 2));
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
// АВТОМАТИЧЕСКОЕ УДАЛЕНИЕ СТАРЫХ ПРОМОКОДОВ
// ═══════════════════════════════════════════════════════════════

async function deleteOldPromocodes(env) {
  console.log('[PROMO-DELETE] 🗑️ Starting old promocodes cleanup...');
  
  try {
    const bot = new Bot(env.BOT_TOKEN);
    let deletedCount = 0;
    let errorCount = 0;
    
    // Получаем все ключи с промокодами из KV
    const list = await env.BROADCAST_STATE.list({ prefix: 'promo_msg_' });
    console.log(`[PROMO-DELETE] 📊 Found ${list.keys.length} promocode messages to check`);
    
    const now = Date.now();
    
    for (const key of list.keys) {
      try {
        const dataJson = await env.BROADCAST_STATE.get(key.name);
        if (!dataJson) continue;
        
        const data = JSON.parse(dataJson);
        
        // Проверяем нужно ли удалять
        if (now >= data.delete_at) {
          console.log(`[PROMO-DELETE] 🎯 Deleting message ${data.message_id} from chat ${data.chat_id} (partner: ${data.partner})`);
          
          try {
            await bot.api.deleteMessage(data.chat_id, data.message_id);
            deletedCount++;
            console.log(`[PROMO-DELETE] ✅ Deleted message ${data.message_id}`);
          } catch (error) {
            // Сообщение могло быть уже удалено пользователем
            if (error.error_code === 400 && error.description?.includes('message to delete not found')) {
              console.log(`[PROMO-DELETE] ℹ️ Message ${data.message_id} already deleted`);
            } else {
              console.error(`[PROMO-DELETE] ❌ Failed to delete message ${data.message_id}:`, error.description);
              errorCount++;
            }
          }
          
          // Удаляем запись из KV
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
// АВТОМАТИЧЕСКАЯ ПРОВЕРКА ПОЛЬЗОВАТЕЛЕЙ (CRON)
// ═══════════════════════════════════════════════════════════════

async function checkAllUsers(env) {
  console.log('[CRON] 🕐 Starting automatic user check...');
  
  try {
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    
    const bot = new Bot(env.BOT_TOKEN);
    let checkedCount = 0;
    let inactiveCount = 0;
    const inactiveUsers = [];
    
    console.log(`[CRON] 📊 Found ${users.length} users to check`);
    
    // Проверяем каждого пользователя
    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      if (!user.telegram_id || String(user.telegram_id).trim() === '') {
        continue;
      }
      
      try {
        // Получаем актуальную информацию о пользователе
        const chatInfo = await bot.api.getChat(user.telegram_id);
        checkedCount++;
        
        // Обновляем данные пользователя в таблице если изменились
        const currentUsername = user.username || '';
        const currentFirstName = user.first_name || '';
        const newUsername = chatInfo.username || '';
        const newFirstName = chatInfo.first_name || '';
        
        if (currentUsername !== newUsername || currentFirstName !== newFirstName) {
          const rowIndex = i + 2; // +2 потому что индекс 0-based и есть заголовок
          const updatedValues = [
            user.telegram_id,
            newUsername,
            newFirstName,
            user.date_registered || '',
            user.bot_started || '',
            new Date().toISOString().split('T')[0] + ' ' + new Date().toTimeString().split(' ')[0]
          ];
          
          await updateSheetRow(env.SHEET_ID, 'users', rowIndex, updatedValues, accessToken);
          console.log(`[CRON] 🔄 Updated user ${user.telegram_id}: @${currentUsername} → @${newUsername}`);
        }
        
        // Задержка чтобы не превысить rate limit (30 req/sec)
        await new Promise(resolve => setTimeout(resolve, 50));
      } catch (error) {
        const errorCode = error.error_code;
        const errorDescription = error.description || error.message;
        
        // Классифицируем неактивных
        if (errorCode === 403 || 
            (errorCode === 400 && (errorDescription?.includes('chat not found') || 
                                   errorDescription?.includes('user is deactivated')))) {
          
          const dateOn = user.date_registered || user.first_seen || user.created_at || user.joined_date || '';
          const reason = errorCode === 403 ? 'Заблокировал бота' : 
                        errorDescription?.includes('chat not found') ? 'Удалил аккаунт' : 'Деактивирован';
          
          inactiveUsers.push({
            telegram_id: user.telegram_id,
            username: user.username,
            date_on: dateOn,
            reason: reason
          });
          
          inactiveCount++;
          console.log(`[CRON] ❌ Inactive: ${user.telegram_id} (@${user.username || 'no-username'}) - ${reason}`);
        }
        
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
    
    // Переносим неактивных в архив
    if (inactiveUsers.length > 0) {
      console.log(`[CRON] 📦 Moving ${inactiveUsers.length} inactive users to archive...`);
      
      const allUsers = await getSheetData(env.SHEET_ID, 'users', accessToken);
      const dateOff = new Date().toISOString().split('T')[0];
      
      // Добавляем в pidarasy
      for (const inactiveUser of inactiveUsers) {
        try {
          await appendSheetRow(
            env.SHEET_ID,
            'pidarasy',
            [
              inactiveUser.username || '',
              inactiveUser.telegram_id || '',
              inactiveUser.date_on,
              dateOff
            ],
            accessToken
          );
          console.log(`[CRON] ✅ Archived: @${inactiveUser.username} (${inactiveUser.telegram_id})`);
          await new Promise(resolve => setTimeout(resolve, 50));
        } catch (error) {
          console.error(`[CRON] Failed to archive ${inactiveUser.telegram_id}:`, error);
        }
      }
      
      // Удаляем из users
      const rowsToDelete = [];
      for (const inactiveUser of inactiveUsers) {
        const index = allUsers.findIndex(u => String(u.telegram_id) === String(inactiveUser.telegram_id));
        if (index !== -1) {
          rowsToDelete.push(index + 2);
        }
      }
      
      rowsToDelete.sort((a, b) => b - a);
      for (const rowIndex of rowsToDelete) {
        try {
          await deleteSheetRow(env.SHEET_ID, 'users', rowIndex, accessToken);
          await new Promise(resolve => setTimeout(resolve, 50));
        } catch (error) {
          console.error(`[CRON] Failed to delete row ${rowIndex}:`, error);
        }
      }
    }
    
    console.log(`[CRON] ✅ Check completed!`);
    console.log(`[CRON] 📊 Stats: Checked=${checkedCount}, Inactive=${inactiveCount}, Archived=${inactiveUsers.length}`);
    
    return {
      success: true,
      checked: checkedCount,
      inactive: inactiveCount,
      archived: inactiveUsers.length
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
    const accessToken = await getAccessToken(creds);
    
    // Получаем всех партнеров
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    console.log(`[WEEKLY_REPORT] Found ${partners.length} partners`);
    
    // Получаем все клики
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    console.log(`[WEEKLY_REPORT] Found ${clicks.length} total clicks`);
    
    const bot = setupBot(env);
    let reportsSent = 0;
    let reportsFailed = 0;
    
    // Текущая дата для проверки недели
    const now = new Date();
    const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    
    // ⚠️ ВАЖНО: Каждый представитель получает отчет ТОЛЬКО по своему партнеру
    for (const partner of partners) {
      // Проверяем что есть представитель для ЭТОГО партнера
      if (!partner.predstavitel || partner.przedstawitel.trim() === '') {
        console.log(`[WEEKLY_REPORT] ⏭️ Skipping ${partner.title}: no representative`);
        continue;
      }
      
      const username = partner.predstavitel.replace('@', '').trim();
      console.log(`[WEEKLY_REPORT] 📧 Processing report for partner "${partner.title}" → representative @${username}`);
      
      // Собираем статистику ТОЛЬКО по этому партнеру (по его URL)
      const partnerClicks = clicks.filter(c => c.url === partner.url);
      console.log(`[WEEKLY_REPORT] 📊 Found ${partnerClicks.length} click records for ${partner.url}`);
      
      if (partnerClicks.length === 0) {
        console.log(`[WEEKLY_REPORT] ⏭️ Skipping ${partner.title}: no clicks yet`);
        continue;
      }
      
      // Считаем показатели
      const totalClicks = partnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const uniqueUsers = new Set(partnerClicks.map(c => c.telegram_id)).size;
      const conversionRate = totalClicks > 0 ? ((uniqueUsers / totalClicks) * 100).toFixed(2) : '0.00';
      
      // Клики за последнюю неделю
      const weekClicks = partnerClicks.filter(c => {
        const clickDate = new Date(c.last_click_date || c.first_click_date);
        return clickDate >= oneWeekAgo;
      });
      const weekTotalClicks = weekClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const weekUniqueUsers = new Set(weekClicks.map(c => c.telegram_id)).size;
      
      // Формируем отчет ТОЛЬКО по этому партнеру
      const report = `📊 *Еженедельный отчет по партнерству*\n\n` +
                    `🏷️ *Ваш партнер:* ${partner.title}\n` +
                    `📁 *Категория:* ${partner.category || 'Не указана'}\n` +
                    `📅 *Дата размещения:* ${partner.date_release || 'Не указана'}\n` +
                    `🔗 *Ссылка:* ${partner.url}\n\n` +
                    `*📈 Общая статистика:*\n` +
                    `👥 Уникальных пользователей: ${uniqueUsers}\n` +
                    `🖱️ Всего кликов: ${totalClicks}\n` +
                    `📊 Конверсия: ${conversionRate}%\n\n` +
                    `*🗓️ За последнюю неделю:*\n` +
                    `👥 Новых пользователей: ${weekUniqueUsers}\n` +
                    `🖱️ Кликов: ${weekTotalClicks}\n\n` +
                    `_Отчет отправлен: ${now.toLocaleDateString('ru-RU')} ${now.toLocaleTimeString('ru-RU')}_`;
      
      try {
        // Находим представителя ЭТОГО партнера в базе пользователей
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const user = users.find(u => 
          u.username && u.username.toLowerCase() === username.toLowerCase()
        );
        
        if (!user) {
          console.log(`[WEEKLY_REPORT] ⚠️ Representative @${username} for "${partner.title}" not found in database`);
          reportsFailed++;
          continue;
        }
        
        if (!user.telegram_id) {
          console.log(`[WEEKLY_REPORT] ⚠️ Representative @${username} has no telegram_id`);
          reportsFailed++;
          continue;
        }
        
        // Отправляем отчет представителю ТОЛЬКО по его партнеру
        await bot.api.sendMessage(user.telegram_id, report, {
          parse_mode: 'Markdown',
          disable_web_page_preview: true
        });
        
        console.log(`[WEEKLY_REPORT] ✅ Report for "${partner.title}" sent to representative @${username} (${user.telegram_id})`);
        reportsSent++;
        
      } catch (error) {
        if (error.error_code === 403) {
          console.log(`[WEEKLY_REPORT] ⚠️ Bot not started by @${username}`);
        } else {
          console.error(`[WEEKLY_REPORT] ❌ Failed to send to @${username}:`, error.message);
        }
        reportsFailed++;
      }
    }
    
    console.log(`[WEEKLY_REPORT] 📊 Completed: ${reportsSent} sent, ${reportsFailed} failed`);
    return { success: true, sent: reportsSent, failed: reportsFailed };
    
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
    const accessToken = await getAccessToken(creds);
    
    // Получаем всех партнеров
    const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
    console.log(`[MONTHLY_REPORT] Found ${partners.length} partners`);
    
    // Получаем все клики
    const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
    console.log(`[MONTHLY_REPORT] Found ${clicks.length} total clicks`);
    
    const bot = setupBot(env);
    let reportsSent = 0;
    let reportsFailed = 0;
    
    // Текущая дата для проверки месяца
    const now = new Date();
    const oneMonthAgo = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
    const previousMonthName = oneMonthAgo.toLocaleDateString('ru-RU', { month: 'long', year: 'numeric' });
    
    // ⚠️ ВАЖНО: Каждый представитель получает отчет ТОЛЬКО по своему партнеру
    for (const partner of partners) {
      // Проверяем что есть представитель для ЭТОГО партнера
      if (!partner.predstavitel || partner.predstavitel.trim() === '') {
        console.log(`[MONTHLY_REPORT] ⏭️ Skipping ${partner.title}: no representative`);
        continue;
      }
      
      const username = partner.predstavitel.replace('@', '').trim();
      console.log(`[MONTHLY_REPORT] 📧 Processing report for partner "${partner.title}" → representative @${username}`);
      
      // Собираем статистику ТОЛЬКО по этому партнеру (по его URL)
      const partnerClicks = clicks.filter(c => c.url === partner.url);
      console.log(`[MONTHLY_REPORT] 📊 Found ${partnerClicks.length} click records for ${partner.url}`);
      
      if (partnerClicks.length === 0) {
        console.log(`[MONTHLY_REPORT] ⏭️ Skipping ${partner.title}: no clicks yet`);
        continue;
      }
      
      // Считаем показатели за все время
      const totalClicks = partnerClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const uniqueUsers = new Set(partnerClicks.map(c => c.telegram_id)).size;
      const conversionRate = totalClicks > 0 ? ((uniqueUsers / totalClicks) * 100).toFixed(2) : '0.00';
      
      // Клики за последний месяц
      const monthClicks = partnerClicks.filter(c => {
        const clickDate = new Date(c.last_click_date || c.first_click_date);
        return clickDate >= oneMonthAgo;
      });
      const monthTotalClicks = monthClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
      const monthUniqueUsers = new Set(monthClicks.map(c => c.telegram_id)).size;
      const monthConversion = monthTotalClicks > 0 ? ((monthUniqueUsers / monthTotalClicks) * 100).toFixed(2) : '0.00';
      
      // Динамика по дням (топ-5 дней по активности)
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
      
      // Формируем отчет ТОЛЬКО по этому партнеру
      const report = `📊 *Ежемесячный отчет по партнерству*\n` +
                    `📅 *Период:* ${previousMonthName}\n\n` +
                    `🏷️ *Ваш партнер:* ${partner.title}\n` +
                    `📁 *Категория:* ${partner.category || 'Не указана'}\n` +
                    `📅 *Дата размещения:* ${partner.date_release || 'Не указана'}\n` +
                    `🔗 *Ссылка:* ${partner.url}\n\n` +
                    `*📈 Общая статистика (за все время):*\n` +
                    `👥 Уникальных пользователей: ${uniqueUsers}\n` +
                    `🖱️ Всего кликов: ${totalClicks}\n` +
                    `📊 Конверсия: ${conversionRate}%\n\n` +
                    `*🗓️ За последний месяц:*\n` +
                    `👥 Новых пользователей: ${monthUniqueUsers}\n` +
                    `🖱️ Кликов: ${monthTotalClicks}\n` +
                    `📊 Конверсия за месяц: ${monthConversion}%\n\n` +
                    (topDays ? `*📅 Самые активные дни месяца:*\n${topDays}\n\n` : '') +
                    `_Отчет отправлен: ${now.toLocaleDateString('ru-RU')} ${now.toLocaleTimeString('ru-RU')}_`;
      
      try {
        // Находим представителя ЭТОГО партнера в базе пользователей
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const user = users.find(u => 
          u.username && u.username.toLowerCase() === username.toLowerCase()
        );
        
        if (!user) {
          console.log(`[MONTHLY_REPORT] ⚠️ Representative @${username} for "${partner.title}" not found in database`);
          reportsFailed++;
          continue;
        }
        
        if (!user.telegram_id) {
          console.log(`[MONTHLY_REPORT] ⚠️ Representative @${username} has no telegram_id`);
          reportsFailed++;
          continue;
        }
        
        // Отправляем отчет представителю ТОЛЬКО по его партнеру
        await bot.api.sendMessage(user.telegram_id, report, {
          parse_mode: 'Markdown',
          disable_web_page_preview: true
        });
        
        console.log(`[MONTHLY_REPORT] ✅ Report for "${partner.title}" sent to representative @${username} (${user.telegram_id})`);
        reportsSent++;
        
      } catch (error) {
        if (error.error_code === 403) {
          console.log(`[MONTHLY_REPORT] ⚠️ Bot not started by @${username}`);
        } else {
          console.error(`[MONTHLY_REPORT] ❌ Failed to send to @${username}:`, error.message);
        }
        reportsFailed++;
      }
    }
    
    console.log(`[MONTHLY_REPORT] 📊 Completed: ${reportsSent} sent, ${reportsFailed} failed`);
    return { success: true, sent: reportsSent, failed: reportsFailed };
    
  } catch (error) {
    console.error('[MONTHLY_REPORT] ❌ Error:', error);
    return { success: false, error: error.message };
  }
}

// ═══════════════════════════════════════════════════════════════
// MAIN HANDLER
// ═══════════════════════════════════════════════════════════════

export default {
  // Scheduled handler для Cron Triggers
  async scheduled(event, env, ctx) {
    console.log('[CRON] ⏰ Triggered at:', new Date().toISOString());
    
    // Определяем день недели и число месяца
    const now = new Date();
    const dayOfWeek = now.getDay();
    const dayOfMonth = now.getDate();
    const hour = now.getHours();
    
    // Проверка и архивация неактивных пользователей (каждые 5 минут)
    const usersResult = await checkAllUsers(env);
    console.log('[CRON] 📊 Users check result:', usersResult);
    
    // Удаление старых сообщений с промокодами (каждые 5 минут)
    const promoResult = await deleteOldPromocodes(env);
    console.log('[CRON] 🗑️ Promocodes cleanup result:', promoResult);
    
    // Еженедельные отчеты партнерам (каждый понедельник в 10:00 UTC)
    if (dayOfWeek === 1 && hour === 10) {
      console.log('[CRON] 📊 Sending weekly partner reports...');
      const weeklyReportsResult = await sendWeeklyPartnerReports(env);
      console.log('[CRON] 📧 Weekly reports result:', weeklyReportsResult);
    }
    
    // Ежемесячные отчеты партнерам (1-го числа каждого месяца в 12:00 UTC)
    if (dayOfMonth === 1 && hour === 12) {
      console.log('[CRON] 📊 Sending monthly partner reports...');
      const monthlyReportsResult = await sendMonthlyPartnerReports(env);
      console.log('[CRON] 📧 Monthly reports result:', monthlyReportsResult);
    }
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
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

      // ═══════════════════════════════════════════════════════════
      // TELEGRAM BOT WEBHOOK (с grammY)
      // ═══════════════════════════════════════════════════════════
      
      if (path === `/bot${env.BOT_TOKEN}` && request.method === 'POST') {
        const bot = setupBot(env);
        const handleUpdate = webhookCallback(bot, 'cloudflare-mod');
        return await handleUpdate(request);
      }

      // ═══════════════════════════════════════════════════════════
      // BROADCAST CLICK TRACKING & REDIRECT
      // ═══════════════════════════════════════════════════════════
      
      if (path.startsWith('/r/')) {
        // Формат: /r/{broadcast_id}/{encoded_partner_url}
        const pathParts = path.split('/').filter(p => p);
        if (pathParts.length >= 3 && pathParts[0] === 'r') {
          const broadcastId = pathParts[1];
          const encodedPartnerUrl = pathParts.slice(2).join('/');
          const partnerUrl = decodeURIComponent(encodedPartnerUrl);
          
          console.log(`[REDIRECT] 📊 Broadcast click tracked: ${broadcastId}`);
          
          // Обновляем click_count в листе broadcasts
          try {
            const broadcasts = await getSheetData(env.SHEET_ID, 'broadcasts', accessToken);
            const broadcastIndex = broadcasts.findIndex(b => b.broadcast_id === broadcastId);
            
            if (broadcastIndex !== -1) {
              const broadcast = broadcasts[broadcastIndex];
              const currentClicks = parseInt(broadcast.click_count || '0') || 0;
              const newClicks = currentClicks + 1;
              const rowIndex = broadcastIndex + 2;
              
              // Пересчитываем конверсию
              const sentCount = parseInt(broadcast.sent_count || '0') || 0;
              let conversionRate = '0.00%';
              if (sentCount > 0) {
                const rate = (newClicks / sentCount) * 100;
                conversionRate = rate.toFixed(2) + '%';
              }
              
              // Обновляем click_count и conversion_rate
              await updateSheetRow(
                env.SHEET_ID,
                'broadcasts',
                rowIndex,
                [
                  broadcast.broadcast_id || '',
                  broadcast.name || '',
                  broadcast.date || '',
                  broadcast.time || '',
                  broadcast.sent_count || '0',
                  broadcast.read_count || '0',
                  String(newClicks),                         // click_count - обновляем
                  conversionRate,                            // conversion_rate - пересчитываем
                  broadcast.title || '',
                  broadcast.subtitle || '',
                  broadcast.button_text || '',
                  broadcast.button_url || '',
                  broadcast.total_users || '0',
                  broadcast.fail_count || '0',
                  broadcast.archived_count || '0'
                ],
                accessToken
              );
              
              console.log(`[REDIRECT] ✅ Updated broadcast ${broadcastId}: clicks ${currentClicks} → ${newClicks}, conversion: ${conversionRate}`);
            }
          } catch (error) {
            console.error(`[REDIRECT] ❌ Failed to update broadcast clicks:`, error);
          }
          
          // Редиректим на финальный URL
          return Response.redirect(partnerUrl, 302);
        }
      }
      
      // ═══════════════════════════════════════════════════════════
      // API ENDPOINTS (для Mini App)
      // ═══════════════════════════════════════════════════════════

      if (path === '/api/health') {
        return jsonResponse({
          status: 'ok',
          timestamp: new Date().toISOString(),
          version: '3.0.0-grammy',
          mode: 'production_with_grammy',
        });
      }

      if (path === '/api/partners' && request.method === 'GET') {
        const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
        console.log(`[API/PARTNERS] Loaded ${partners.length} partners from sheet`);
        
        // Логируем промокоды для отладки
        partners.forEach(p => {
          if (p.promocode && p.promocode.trim() !== '') {
            console.log(`[API/PARTNERS] ${p.title}: promocode="${p.promocode}"`);
          }
        });
        
        const result = partners.map(p => ({
          title: p.title,
          logo_url: p.logo_url || '',
          url: p.url,
          category: p.category,
          promocode: p.promocode || '', // Добавляем промокод
        }));
        
        console.log(`[API/PARTNERS] Returning ${result.length} partners to frontend`);
        return jsonResponse(result);
      }

      if (path === '/api/click' && request.method === 'POST') {
        const body = await request.json();
        console.log(`[CLICK] Request received:`, JSON.stringify(body));
        
        // Получаем данные пользователя
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const user = users.find(u => String(u.telegram_id) === String(body.telegram_id));
        console.log(`[CLICK] User found:`, user ? `${user.username} (${user.telegram_id})` : 'NOT FOUND');
        
        // Получаем данные партнера
        const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
        console.log(`[CLICK] Total partners in sheet:`, partners.length);
        const partner = partners.find(p => p.url === body.url);
        console.log(`[CLICK] Partner found:`, partner ? `${partner.title} | Promocode: "${partner.promocode}"` : 'NOT FOUND');
        
        // Получаем все клики
        const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
        
        // Ищем существующую запись для этого пользователя и URL
        const existingClickIndex = clicks.findIndex(c => 
          String(c.telegram_id) === String(body.telegram_id) && 
          c.url === body.url
        );
        
        const now = new Date();
        const currentDate = now.toISOString().split('T')[0]; // YYYY-MM-DD
        const currentTime = now.toISOString().split('T')[1].split('.')[0]; // HH:MM:SS
        const timestamp = now.toISOString();
        
        let newCount = 1; // По умолчанию для нового клика
        
        // Рассчитываем конверсию для данного URL
        const urlClicks = clicks.filter(c => c.url === body.url);
        const uniqueUsers = new Set(urlClicks.map(c => c.telegram_id)).size;
        const totalClicks = urlClicks.reduce((sum, c) => sum + parseInt(c.click || 1), 0);
        
        // Конверсия = уникальные пользователи / общее количество кликов * 100%
        // После добавления нового клика учитываем это в расчете
        const willBeUniqueUsers = existingClickIndex === -1 ? uniqueUsers + 1 : uniqueUsers;
        const willBeTotalClicks = existingClickIndex === -1 ? totalClicks + 1 : totalClicks + 1;
        const conversionRate = willBeTotalClicks > 0 
          ? ((willBeUniqueUsers / willBeTotalClicks) * 100).toFixed(2) 
          : '0.00';
        
        if (existingClickIndex !== -1) {
          // Обновляем существующую запись - увеличиваем счетчик
          const existingClick = clicks[existingClickIndex];
          const currentCount = parseInt(existingClick.click || '1') || 1;
          newCount = currentCount + 1;
          
          const rowIndex = existingClickIndex + 2; // +2 для заголовка и 1-based индекса
          
          // Формат: telegram_id, username, first_name, partner_title, category, url, click, date_release, first_click_date, last_click_date, last_click_time, timestamp, conversion
          await updateSheetRow(
            env.SHEET_ID,
            'clicks',
            rowIndex,
            [
              body.telegram_id,
              user?.username || '',
              user?.first_name || '',
              partner?.title || 'Unknown',
              partner?.category || '',
              body.url,
              String(newCount),                      // click - увеличиваем счетчик
              partner?.date_release || '',           // date_release - дата размещения ссылки
              existingClick.first_click_date || currentDate,  // сохраняем первую дату
              currentDate,                           // last_click_date - обновляем
              currentTime,                           // last_click_time
              timestamp,                             // timestamp
              conversionRate + '%'                   // conversion - процент конверсии
            ],
            accessToken
          );
          
          console.log(`[CLICK] 🔄 Updated click count: ${body.telegram_id} → ${body.url} (${newCount} times), conversion: ${conversionRate}%`);
        } else {
          // Создаем новую запись
          await appendSheetRow(
            env.SHEET_ID,
            'clicks',
            [
              body.telegram_id,
              user?.username || '',
              user?.first_name || '',
              partner?.title || 'Unknown',
              partner?.category || '',
              body.url,
              '1',                  // click - первый клик
              partner?.date_release || '',  // date_release - дата размещения ссылки
              currentDate,          // first_click_date
              currentDate,          // last_click_date
              currentTime,          // last_click_time
              timestamp,            // timestamp
              conversionRate + '%'  // conversion - процент конверсии
            ],
            accessToken
          );
          
          console.log(`[CLICK] 🆕 New click recorded: ${body.telegram_id} → ${body.url}, conversion: ${conversionRate}%`);
        }
        
        // Отправляем промокод пользователю, если он есть
        console.log(`[PROMOCODE] Checking: partner=${!!partner}, promocode="${partner?.promocode}"`);
        
        if (partner?.promocode && partner.promocode.trim() !== '') {
          console.log(`[PROMOCODE] 🎯 Attempting to send promocode to user ${body.telegram_id}`);
          try {
            const bot = setupBot(env);
            const promocode = partner.promocode.trim();
            
            console.log(`[PROMOCODE] Bot created, preparing message...`);
            
            // Формируем сообщение с промокодом
            const message = `🎁 Ваш промокод от [${partner.title}](${body.url})\n\n` +
                          `\`${promocode}\``;
            
            // Кнопка с URL партнера
            const keyboard = new InlineKeyboard()
              .url('🔗 Перейти к партнеру', body.url);
            
            console.log(`[PROMOCODE] Sending message to ${body.telegram_id}...`);
            
            const sentMessage = await bot.api.sendMessage(body.telegram_id, message, {
              parse_mode: 'Markdown',
              reply_markup: keyboard,
              disable_web_page_preview: true,
            });
            
            console.log(`[PROMOCODE] ✅ Successfully sent to user ${body.telegram_id}: ${promocode}`);
            
            // Сохраняем message_id для автоматического удаления через 24 часа
            const deleteAt = Date.now() + (24 * 60 * 60 * 1000); // 24 часа
            const messageKey = `promo_msg_${body.telegram_id}_${sentMessage.message_id}`;
            await env.BROADCAST_STATE.put(messageKey, JSON.stringify({
              chat_id: body.telegram_id,
              message_id: sentMessage.message_id,
              delete_at: deleteAt,
              promocode: promocode,
              partner: partner.title
            }), {
              expirationTtl: 86400 // 24 часа в секундах
            });
            
            console.log(`[PROMOCODE] 📅 Scheduled for deletion at ${new Date(deleteAt).toISOString()}`);
          } catch (error) {
            console.error(`[PROMOCODE] ❌ Failed to send to ${body.telegram_id}:`, error);
            console.error(`[PROMOCODE] Error details:`, {
              error_code: error.error_code,
              description: error.description,
              message: error.message
            });
            // Не останавливаем выполнение если отправка не удалась
          }
        } else {
          console.log(`[PROMOCODE] ⏭️ No promocode to send (partner=${!!partner}, promocode="${partner?.promocode}")`);
        }
        
        // Возвращаем корректное количество кликов + информацию о промокоде
        const clickCount = existingClickIndex !== -1 ? newCount : 1;
        return jsonResponse({ 
          ok: true, 
          success: true, 
          clicks: clickCount,
          promocode_sent: !!(partner?.promocode && partner.promocode.trim() !== '')
        });
      }

      if (path === '/api/user' && request.method === 'POST') {
        const body = await request.json();
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const existing = users.find(u => String(u.telegram_id) === String(body.id));
        const currentDate = new Date().toISOString().split('T')[0];

        if (!existing) {
          // Добавляем нового пользователя
          await appendSheetRow(
            env.SHEET_ID,
            'users',
            [
              body.id, 
              body.username || 'N/A', 
              body.first_name || 'Unknown', 
              currentDate,  // date_registered
              'TRUE',       // bot_started
              currentDate   // last_active
            ],
            accessToken
          );
          console.log(`[API] 🆕 New user registered via API: ${body.id}`);
        } else {
          // Обновляем существующего пользователя
          const userIndex = users.findIndex(u => String(u.telegram_id) === String(body.id));
          if (userIndex !== -1) {
            const rowIndex = userIndex + 2;
            await updateSheetRow(
              env.SHEET_ID,
              'users',
              rowIndex,
              [
                body.id,
                body.username || existing.username || 'N/A',
                body.first_name || existing.first_name || 'Unknown',
                existing.date_registered || currentDate,
                'TRUE',      // bot_started
                currentDate  // last_active (обновляем)
              ],
              accessToken
            );
            console.log(`[API] 🔄 User updated via API: ${body.id}`);
          }
        }

        return jsonResponse({ ok: true, registered: !existing });
      }

      if (path === '/api/me' && request.method === 'POST') {
        const body = await request.json();
        const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
        const isAdmin = admins.some(a => a.username && a.username.toLowerCase() === body.username?.toLowerCase());

        return jsonResponse({ isAdmin });
      }

      if (path === '/api/subscribers' && request.method === 'GET') {
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        return jsonResponse({
          total: users.length,
          subscribed: users.filter(u => u.subscribed === 'TRUE').length,
        });
      }

      return errorResponse('Endpoint not found', 404);
    } catch (error) {
      console.error('Error:', error);
      return errorResponse(error.message || 'Internal server error', 500);
    }
  },
};
