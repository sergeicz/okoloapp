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
    
    // Проверяем админа
    const isAdmin = await checkAdmin(env, user);
    
    // Клавиатура
    const keyboard = new InlineKeyboard()
      .webApp('🚀 Открыть Mini App', env.WEBAPP_URL);
    
    if (isAdmin) {
      keyboard.row().text('⚙️ Админ-панель', 'admin_panel');
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
    
    state.step = 'image';
    await saveBroadcastState(env, ctx.chat.id, state);
    
    const keyboard = new InlineKeyboard()
      .text('⏭️ Пропустить', 'broadcast_skip_image').row()
      .text('❌ Отменить', 'broadcast_cancel');
    
    await ctx.reply(
      '📢 *Создание рассылки*\n\n*Шаг 3 из 4:* Изображение\n\n🖼️ *Прикрепите изображение* или отправьте ссылку (URL):',
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
    
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    const accessToken = await getAccessToken(creds);
    const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
    
    const text = `👥 *Пользователи*\n\nВсего пользователей: ${users.length}\n\nСписок пользователей сохранен в Google Sheets.`;
    
    const keyboard = new InlineKeyboard().text('« Назад', 'admin_panel');
    
    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
    await ctx.answerCallbackQuery();
  });

  // Назад к старту
  bot.callbackQuery('back_to_start', async (ctx) => {
    const user = ctx.from;
    const isAdmin = await checkAdmin(env, user);
    
    const keyboard = new InlineKeyboard()
      .webApp('🚀 Открыть Mini App', env.WEBAPP_URL);
    
    if (isAdmin) {
      keyboard.row().text('⚙️ Админ-панель', 'admin_panel');
    }
    
    await ctx.editMessageText(
      `👋 *Привет, ${user.first_name}!*\n\nДобро пожаловать в наш Mini App!\n\n🔗 Нажми кнопку ниже чтобы открыть приложение с партнерскими ссылками.`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
    await ctx.answerCallbackQuery();
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
      state.step = 'image';
      keyboard = new InlineKeyboard()
        .text('⏭️ Пропустить', 'broadcast_skip_image').row()
        .text('❌ Отменить', 'broadcast_cancel');
      
      await saveBroadcastState(env, ctx.chat.id, state);
      await ctx.reply(
        '📢 *Создание рассылки*\n\n*Шаг 4 из 5:* Изображение\n\n🖼️ *Прикрепите изображение* или отправьте ссылку (URL):',
        { parse_mode: 'Markdown', reply_markup: keyboard }
      );
      
    } else if (state.step === 'image') {
      state.image_url = text;
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
  // ОБРАБОТКА ФОТО (для рассылки)
  // ═══════════════════════════════════════════════════════════
  
  bot.on('message:photo', async (ctx) => {
    const state = await getBroadcastState(env, ctx.chat.id);
    if (!state || state.step !== 'image') return;
    
    const isAdmin = await checkAdmin(env, ctx.from);
    if (!isAdmin) return;
    
    const photos = ctx.message.photo;
    const largestPhoto = photos[photos.length - 1];
    state.image_file_id = largestPhoto.file_id;
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

  return bot;
}

// ═══════════════════════════════════════════════════════════════
// BROADCAST HELPERS
// ═══════════════════════════════════════════════════════════════

async function showBroadcastPreview(ctx, env, state) {
  const hasImage = (state.image_url && state.image_url.trim() !== '') || (state.image_file_id && state.image_file_id.trim() !== '');
  const photoSource = state.image_file_id || state.image_url;
  
  const keyboard = new InlineKeyboard()
    .text('✅ Отправить всем', 'broadcast_confirm').row()
    .text('❌ Отменить', 'broadcast_cancel');
  
  if (hasImage) {
    let caption = '📢 *Предпросмотр рассылки*\n\n';
    if (state.title) caption += `*${state.title}*\n`;
    if (state.subtitle) caption += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) caption += `\n🔘 Кнопка: "${state.button_text}"\n`;
    caption += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;
    
    await ctx.replyWithPhoto(photoSource, {
      caption: caption,
      parse_mode: 'Markdown',
      reply_markup: keyboard
    });
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
  
  const hasImage = (state.image_url && state.image_url.trim() !== '') || (state.image_file_id && state.image_file_id.trim() !== '');
  const photoSource = state.image_file_id || state.image_url;
  
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
      if (hasImage) {
        await ctx.api.sendPhoto(user.telegram_id, photoSource, {
          caption: messageText,
          parse_mode: 'Markdown',
          reply_markup: keyboard
        });
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
// MAIN HANDLER
// ═══════════════════════════════════════════════════════════════

export default {
  // Scheduled handler для Cron Triggers
  async scheduled(event, env, ctx) {
    console.log('[CRON] ⏰ Triggered at:', new Date().toISOString());
    const result = await checkAllUsers(env);
    console.log('[CRON] 📊 Result:', result);
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
        return jsonResponse(partners.map(p => ({
          title: p.title,
          logo_url: p.logo_url || '',
          url: p.url,
          category: p.category,
        })));
      }

      if (path === '/api/click' && request.method === 'POST') {
        const body = await request.json();
        
        // Получаем данные пользователя
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        const user = users.find(u => String(u.telegram_id) === String(body.telegram_id));
        
        // Получаем данные партнера
        const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
        const partner = partners.find(p => p.url === body.url);
        
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
        
        if (existingClickIndex !== -1) {
          // Обновляем существующую запись - увеличиваем счетчик
          const existingClick = clicks[existingClickIndex];
          const currentCount = parseInt(existingClick.click || '1') || 1;
          const newCount = currentCount + 1;
          
          const rowIndex = existingClickIndex + 2; // +2 для заголовка и 1-based индекса
          
          // Формат: telegram_id, username, first_name, partner_title, category, url, click, first_click_date, last_click_date, last_click_time, timestamp
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
              existingClick.first_click_date || currentDate,  // сохраняем первую дату
              currentDate,                           // last_click_date - обновляем
              currentTime,                           // last_click_time
              timestamp                              // timestamp
            ],
            accessToken
          );
          
          console.log(`[CLICK] 🔄 Updated click count: ${body.telegram_id} → ${body.url} (${newCount} times)`);
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
              currentDate,          // first_click_date
              currentDate,          // last_click_date
              currentTime,          // last_click_time
              timestamp             // timestamp
            ],
            accessToken
          );
          
          console.log(`[CLICK] 🆕 New click recorded: ${body.telegram_id} → ${body.url}`);
        }
        
        // Возвращаем корректное количество кликов
        const clickCount = existingClickIndex !== -1 ? newCount : 1;
        return jsonResponse({ ok: true, success: true, clicks: clickCount });
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
