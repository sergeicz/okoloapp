// Cloudflare Worker с API + Telegram Bot + Админ-панель в боте
import { GoogleSpreadsheet } from 'google-spreadsheet';
import { JWT } from 'google-auth-library';

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
  return await response.json();
}

// ═══════════════════════════════════════════════════════════════
// TELEGRAM BOT API
// ═══════════════════════════════════════════════════════════════

async function sendTelegramMessage(botToken, chatId, text, keyboard = null) {
  const body = {
    chat_id: chatId,
    text: text,
    parse_mode: 'Markdown',
  };
  
  if (keyboard) {
    body.reply_markup = keyboard;
  }

  const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  
  return await response.json();
}

async function answerCallbackQuery(botToken, callbackQueryId, text = '') {
  await fetch(`https://api.telegram.org/bot${botToken}/answerCallbackQuery`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      callback_query_id: callbackQueryId,
      text: text,
    }),
  });
}

// ═══════════════════════════════════════════════════════════════
// ADMIN CHECK
// ═══════════════════════════════════════════════════════════════

async function checkAdmin(env, user, accessToken) {
  const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
  
  console.log('🔍 Admin check - RAW DATA:', {
    userUsername: user.username,
    userUsernameType: typeof user.username,
    userId: user.id,
    userIdType: typeof user.id,
    firstName: user.first_name,
    adminsCount: admins.length,
    adminsRaw: JSON.stringify(admins)
  });
  
  // Проверяем каждого админа
  let found = false;
  for (const admin of admins) {
    const adminUsername = admin.username || admin.Username || admin['username'];
    const adminTelegramId = admin.telegram_id || admin.Telegram_id || admin['telegram_id'];
    
    console.log('🔎 Checking admin:', {
      adminUsername: adminUsername,
      adminUsernameType: typeof adminUsername,
      adminTelegramId: adminTelegramId,
      adminTelegramIdType: typeof adminTelegramId,
      userUsername: user.username,
      userId: user.id
    });
    
    // Проверка по username
    if (adminUsername && user.username) {
      const cleanAdminUsername = String(adminUsername).toLowerCase().replace('@', '').trim();
      const cleanUserUsername = String(user.username).toLowerCase().replace('@', '').trim();
      console.log('Username comparison:', cleanAdminUsername, '===', cleanUserUsername, '?', cleanAdminUsername === cleanUserUsername);
      if (cleanAdminUsername === cleanUserUsername) {
        found = true;
        break;
      }
    }
    
    // Проверка по telegram_id
    if (adminTelegramId && user.id) {
      const cleanAdminId = String(adminTelegramId).trim();
      const cleanUserId = String(user.id).trim();
      console.log('ID comparison:', cleanAdminId, '===', cleanUserId, '?', cleanAdminId === cleanUserId);
      if (cleanAdminId === cleanUserId) {
        found = true;
        break;
      }
    }
  }
  
  console.log('✅ Is admin:', found);
  return found;
}

// ═══════════════════════════════════════════════════════════════
// BOT HANDLERS
// ═══════════════════════════════════════════════════════════════

async function handleStart(env, chatId, user) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  
  // Регистрируем пользователя
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
  const existing = users.find(u => String(u.telegram_id) === String(chatId));
  
  if (!existing) {
    await appendSheetRow(
      env.SHEET_ID,
      'users',
      [chatId, user.username || 'N/A', user.first_name || 'Unknown', new Date().toISOString(), 'TRUE'],
      accessToken
    );
  }
  
  // Проверяем админа
  const isAdmin = await checkAdmin(env, user, accessToken);
  
  // Клавиатура
  const keyboard = {
    inline_keyboard: [
      [{ text: '🚀 Открыть Mini App', web_app: { url: env.WEBAPP_URL } }]
    ]
  };
  
  // Если админ - добавляем кнопку админки
  if (isAdmin) {
    keyboard.inline_keyboard.push([{ text: '⚙️ Админ-панель', callback_data: 'admin_panel' }]);
  }
  
  const welcomeText = `👋 *Привет, ${user.first_name}!*\n\nДобро пожаловать в наш Mini App!\n\n🔗 Нажми кнопку ниже чтобы открыть приложение с партнерскими ссылками.`;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, welcomeText, keyboard);
}

async function handleAdminPanel(env, chatId, messageId) {
  const keyboard = {
    inline_keyboard: [
      [{ text: '📊 Статистика', callback_data: 'admin_stats' }],
      [{ text: '📢 Рассылка', callback_data: 'admin_broadcast' }],
      [{ text: '👥 Пользователи', callback_data: 'admin_users' }],
      [{ text: '« Назад', callback_data: 'back_to_start' }],
    ]
  };
  
  const text = `⚙️ *Админ-панель*\n\nВыберите действие:`;
  
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: 'Markdown',
      reply_markup: keyboard,
    }),
  });
}

async function handleAdminStats(env, chatId, messageId) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
  const clicks = await getSheetData(env.SHEET_ID, 'clicks', accessToken);
  const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
  
  const subscribed = users.filter(u => String(u.subscribed).toUpperCase() === 'TRUE').length;
  
  const text = `📊 *Статистика*\n\n👥 Всего пользователей: ${users.length}\n✅ Подписаны: ${subscribed}\n❌ Отписаны: ${users.length - subscribed}\n\n🔗 Партнерских ссылок: ${partners.length}\n👆 Всего кликов: ${clicks.length}`;
  
  const keyboard = {
    inline_keyboard: [[{ text: '« Назад', callback_data: 'admin_panel' }]]
  };
  
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: 'Markdown',
      reply_markup: keyboard,
    }),
  });
}

async function handleAdminBroadcast(env, chatId, messageId) {
  // Создаем новое состояние рассылки
  const state = {
    step: 'title',
    chatId: chatId,
    messageId: messageId,
    title: null,
    subtitle: null,
    image_url: null,
    button_text: null,
    button_url: null,
    started_at: new Date().toISOString()
  };
  
  await env.BROADCAST_STATE.put(`broadcast_${chatId}`, JSON.stringify(state), { expirationTtl: 3600 });
  
  const text = `📢 *Создание рассылки*\n\n*Шаг 1 из 4:* Заголовок\n\n📝 Введите *заголовок* рассылки (обязательно):`;
  
  const keyboard = {
    inline_keyboard: [[{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }]]
  };
  
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: 'Markdown',
      reply_markup: keyboard,
    }),
  });
}

async function handleBroadcast(env, chatId, text) {
  // Парсим команду: /broadcast Заголовок\nТекст\nСсылка
  const lines = text.replace('/broadcast', '').trim().split('\n');
  
  if (lines.length < 3) {
    await sendTelegramMessage(env.BOT_TOKEN, chatId, '❌ Неверный формат! Нужно:\n/broadcast Заголовок\nТекст\nСсылка');
    return;
  }
  
  const title = lines[0].trim();
  const msg = lines.slice(1, -1).join('\n').trim();
  const link = lines[lines.length - 1].trim();
  
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
  const subscribedUsers = users.filter(u => String(u.subscribed).toUpperCase() === 'TRUE');
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, `⏳ Отправка рассылки ${subscribedUsers.length} пользователям...`);
  
  let successful = 0;
  let failed = 0;
  
  for (const user of subscribedUsers) {
    try {
      const keyboard = {
        inline_keyboard: [[{ text: '🔗 Перейти', url: link }]]
      };
      
      await sendTelegramMessage(env.BOT_TOKEN, user.telegram_id, `*${title}*\n\n${msg}`, keyboard);
      successful++;
      
      // Небольшая задержка между отправками
      await new Promise(resolve => setTimeout(resolve, 100));
    } catch (error) {
      failed++;
    }
  }
  
  await sendTelegramMessage(
    env.BOT_TOKEN,
    chatId,
    `✅ Рассылка завершена!\n\n✅ Успешно: ${successful}\n❌ Ошибок: ${failed}`
  );
}

async function handleAdminUsers(env, chatId, messageId) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
  
  const usersList = users.slice(0, 10).map((u, i) => 
    `${i + 1}. @${u.username || 'N/A'} (ID: ${u.telegram_id}) ${u.subscribed === 'TRUE' ? '✅' : '❌'}`
  ).join('\n');
  
  const text = `👥 *Последние пользователи* (${users.length} всего):\n\n${usersList}\n\n_Полный список в Google Sheets_`;
  
  const keyboard = {
    inline_keyboard: [[{ text: '« Назад', callback_data: 'admin_panel' }]]
  };
  
  await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/editMessageText`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      message_id: messageId,
      text: text,
      parse_mode: 'Markdown',
      reply_markup: keyboard,
    }),
  });
}

// ═══════════════════════════════════════════════════════════════
// BROADCAST STEP-BY-STEP HANDLERS
// ═══════════════════════════════════════════════════════════════

async function handleBroadcastMessage(env, chatId, messageText, user, photo) {
  const stateJson = await env.BROADCAST_STATE.get(`broadcast_${chatId}`);
  if (!stateJson) return false;
  
  const state = JSON.parse(stateJson);
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  const isAdmin = await checkAdmin(env, user, accessToken);
  if (!isAdmin) return false;
  
  let text = '';
  let keyboard = { inline_keyboard: [] };
  
  if (state.step === 'title') {
    if (!messageText) return false; // Игнорируем фото на этапе заголовка
    state.title = messageText;
    state.step = 'subtitle';
    text = `📢 *Создание рассылки*\n\n*Шаг 2 из 4:* Подзаголовок\n\n✅ Заголовок сохранен:\n"${messageText}"\n\n📝 Введите *подзаголовок* (описание):`;
    keyboard.inline_keyboard = [
      [{ text: '⏭️ Пропустить', callback_data: 'broadcast_skip_subtitle' }],
      [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
    ];
  } else if (state.step === 'subtitle') {
    if (!messageText) return false; // Игнорируем фото на этапе подзаголовка
    state.subtitle = messageText;
    state.step = 'image';
    text = `📢 *Создание рассылки*\n\n*Шаг 3 из 4:* Изображение\n\n✅ Подзаголовок сохранен!\n\n🖼️ *Прикрепите изображение* или отправьте ссылку (URL):`;
    keyboard.inline_keyboard = [
      [{ text: '⏭️ Пропустить', callback_data: 'broadcast_skip_image' }],
      [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
    ];
  } else if (state.step === 'image') {
    // Проверяем: это фото или текст?
    if (photo && photo.length > 0) {
      // Получаем самое большое фото (последнее в массиве)
      const largestPhoto = photo[photo.length - 1];
      state.image_file_id = largestPhoto.file_id;
      console.log('🖼️ Image file_id saved:', largestPhoto.file_id);
      text = `📢 *Создание рассылки*\n\n*Шаг 4 из 4:* Кнопка\n\n✅ Картинка сохранена!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com`;
    } else if (messageText) {
      // Это URL
      state.image_url = messageText;
      console.log('🖼️ Image URL saved:', messageText);
      text = `📢 *Создание рассылки*\n\n*Шаг 4 из 4:* Кнопка\n\n✅ Картинка сохранена!\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com`;
    } else {
      return false;
    }
    state.step = 'button';
    keyboard.inline_keyboard = [
      [{ text: '⏭️ Пропустить', callback_data: 'broadcast_skip_button' }],
      [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
    ];
  } else if (state.step === 'button') {
    if (!messageText) return false; // Игнорируем фото на этапе кнопки
    const parts = messageText.split('|').map(p => p.trim());
    if (parts.length === 2) {
      state.button_text = parts[0];
      state.button_url = parts[1];
      console.log('🔘 Button saved:', parts[0], '→', parts[1]);
    } else {
      console.log('⚠️ Button parse failed, parts:', parts);
    }
    console.log('📊 Final state before preview:', state);
    return await showBroadcastPreview(env, chatId, state);
  }
  
  await env.BROADCAST_STATE.put(`broadcast_${chatId}`, JSON.stringify(state), { expirationTtl: 3600 });
  await sendTelegramMessage(env.BOT_TOKEN, chatId, text, keyboard);
  return true;
}

async function showBroadcastPreview(env, chatId, state) {
  console.log('🔍 Preview state:', {
    hasTitle: !!state.title,
    hasSubtitle: !!state.subtitle,
    hasImageUrl: !!state.image_url,
    hasImageFileId: !!state.image_file_id,
    imageUrl: state.image_url,
    imageFileId: state.image_file_id,
    hasButton: !!(state.button_text && state.button_url),
    buttonText: state.button_text,
    buttonUrl: state.button_url,
    fullState: state
  });
  
  // Если есть изображение (URL или file_id) - показываем его с подписью
  const hasImage = (state.image_url && state.image_url.trim() !== '') || (state.image_file_id && state.image_file_id.trim() !== '');
  
  if (hasImage) {
    const photoSource = state.image_file_id || state.image_url;
    console.log('📸 Showing preview WITH image:', photoSource);
    let caption = `📢 *Предпросмотр рассылки*\n\n`;
    if (state.title) caption += `*${state.title}*\n`;
    if (state.subtitle) caption += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) caption += `\n🔘 Кнопка: "${state.button_text}"\n`;
    caption += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;
    
    const keyboard = {
      inline_keyboard: [
        [{ text: '✅ Отправить всем', callback_data: 'broadcast_confirm' }],
        [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
      ]
    };
    
    // Отправляем фото с подписью
    const response = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        photo: photoSource,
        caption: caption,
        parse_mode: 'Markdown',
        reply_markup: keyboard,
      }),
    });
    const result = await response.json();
    console.log('📸 sendPhoto result:', result);
  } else {
    console.log('📝 Showing preview WITHOUT image (text only)');
    // Текстовый предпросмотр без изображения
    let previewText = `📢 *Предпросмотр рассылки*\n\n━━━━━━━━━━━━━━━━\n`;
    if (state.title) previewText += `\n*${state.title}*\n`;
    if (state.subtitle) previewText += `\n${state.subtitle}\n`;
    if (state.button_text && state.button_url) previewText += `\n🔘 Кнопка: "${state.button_text}"\n`;
    previewText += `\n━━━━━━━━━━━━━━━━\n\nВсе готово! Отправить рассылку?`;
    
    const keyboard = {
      inline_keyboard: [
        [{ text: '✅ Отправить всем', callback_data: 'broadcast_confirm' }],
        [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
      ]
    };
    
    await sendTelegramMessage(env.BOT_TOKEN, chatId, previewText, keyboard);
  }
  
  state.step = 'confirm';
  await env.BROADCAST_STATE.put(`broadcast_${chatId}`, JSON.stringify(state), { expirationTtl: 3600 });
  return true;
}

async function executeBroadcast(env, chatId, state) {
  const creds = JSON.parse(env.CREDENTIALS_JSON);
  const accessToken = await getAccessToken(creds);
  const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
  
  console.log('📊 Broadcast execution:', {
    state: state,
    totalUsers: users.length,
    usersWithId: users.filter(u => u.telegram_id).length,
  });
  
  let messageText = '';
  if (state.title) messageText += `*${state.title}*\n`;
  if (state.subtitle) messageText += `\n${state.subtitle}`;
  
  let keyboard = null;
  if (state.button_text && state.button_url) {
    keyboard = { inline_keyboard: [[{ text: state.button_text, url: state.button_url }]] };
  }
  
  console.log('📝 Message config:', {
    hasImage: !!state.image_url,
    imageUrl: state.image_url,
    messageText: messageText,
    hasButton: !!keyboard,
    keyboard: keyboard
  });
  
  let successCount = 0;
  let failCount = 0;
  
  await sendTelegramMessage(env.BOT_TOKEN, chatId, `⏳ Начинаю рассылку...`);
  
  // Отправляем ВСЕМ пользователям с telegram_id
  for (const user of users) {
    if (user.telegram_id && String(user.telegram_id).trim() !== '') {
      try {
        const hasImage = (state.image_url && state.image_url.trim() !== '') || (state.image_file_id && state.image_file_id.trim() !== '');
        
        if (hasImage) {
          const photoSource = state.image_file_id || state.image_url;
          console.log(`📸 Sending photo to ${user.telegram_id}`);
          const response = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendPhoto`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              chat_id: user.telegram_id,
              photo: photoSource,
              caption: messageText,
              parse_mode: 'Markdown',
              reply_markup: keyboard,
            }),
          });
          const result = await response.json();
          if (!result.ok) {
            console.error(`Failed to send photo to ${user.telegram_id}:`, result);
            failCount++;
          } else {
            successCount++;
          }
        } else {
          console.log(`📝 Sending text to ${user.telegram_id}`);
          await sendTelegramMessage(env.BOT_TOKEN, user.telegram_id, messageText, keyboard);
          successCount++;
        }
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.error(`Failed to send to ${user.telegram_id}:`, error);
        failCount++;
      }
    }
  }
  
  await env.BROADCAST_STATE.delete(`broadcast_${chatId}`);
  await sendTelegramMessage(env.BOT_TOKEN, chatId, `✅ *Рассылка завершена!*\n\n✉️ Отправлено: ${successCount}\n❌ Ошибок: ${failCount}`, {
    inline_keyboard: [[{ text: '« Вернуться в админку', callback_data: 'admin_panel' }]]
  });
}

// ═══════════════════════════════════════════════════════════════
// MAIN HANDLER
// ═══════════════════════════════════════════════════════════════

export default {
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
      // TELEGRAM BOT WEBHOOK
      // ═══════════════════════════════════════════════════════════
      
      if (path === `/bot${env.BOT_TOKEN}` && request.method === 'POST') {
        const update = await request.json();
        
        // Обработка команд и сообщений
        if (update.message) {
          const chatId = update.message.chat.id;
          const text = update.message.text;
          const user = update.message.from;
          const photo = update.message.photo; // Получаем фото если есть
          
          // Проверяем, есть ли активная рассылка
          const broadcastHandled = await handleBroadcastMessage(env, chatId, text, user, photo);
          
          if (!broadcastHandled) {
            if (text === '/start') {
              await handleStart(env, chatId, user);
            }
          }
        }
        
        // Обработка callback queries (кнопок)
        if (update.callback_query) {
          const callbackQuery = update.callback_query;
          const chatId = callbackQuery.message.chat.id;
          const messageId = callbackQuery.message.message_id;
          const data = callbackQuery.data;
          const user = callbackQuery.from;
          
          // Проверка админа
          const isAdmin = await checkAdmin(env, user, accessToken);
          
          if (!isAdmin && data !== 'back_to_start') {
            await answerCallbackQuery(env.BOT_TOKEN, callbackQuery.id, '❌ У вас нет прав администратора');
            return jsonResponse({ ok: true });
          }
          
          if (data === 'admin_panel') {
            await handleAdminPanel(env, chatId, messageId);
          } else if (data === 'admin_stats') {
            await handleAdminStats(env, chatId, messageId);
          } else if (data === 'admin_broadcast') {
            await handleAdminBroadcast(env, chatId, messageId);
          } else if (data === 'admin_users') {
            await handleAdminUsers(env, chatId, messageId);
          } else if (data === 'back_to_start') {
            await handleStart(env, chatId, user);
          } else if (data === 'broadcast_skip_subtitle') {
            const stateJson = await env.BROADCAST_STATE.get(`broadcast_${chatId}`);
            if (stateJson) {
              const state = JSON.parse(stateJson);
              state.step = 'image';
              await env.BROADCAST_STATE.put(`broadcast_${chatId}`, JSON.stringify(state), { expirationTtl: 3600 });
              await sendTelegramMessage(env.BOT_TOKEN, chatId, `📢 *Создание рассылки*\n\n*Шаг 3 из 4:* Изображение\n\n🖼️ Отправьте *ссылку на картинку* (URL):`, {
                inline_keyboard: [
                  [{ text: '⏭️ Пропустить', callback_data: 'broadcast_skip_image' }],
                  [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
                ]
              });
            }
          } else if (data === 'broadcast_skip_image') {
            const stateJson = await env.BROADCAST_STATE.get(`broadcast_${chatId}`);
            if (stateJson) {
              const state = JSON.parse(stateJson);
              state.step = 'button';
              await env.BROADCAST_STATE.put(`broadcast_${chatId}`, JSON.stringify(state), { expirationTtl: 3600 });
              await sendTelegramMessage(env.BOT_TOKEN, chatId, `📢 *Создание рассылки*\n\n*Шаг 4 из 4:* Кнопка\n\n🔗 Отправьте *текст и ссылку для кнопки* в формате:\n\nТекст кнопки | https://example.com`, {
                inline_keyboard: [
                  [{ text: '⏭️ Пропустить', callback_data: 'broadcast_skip_button' }],
                  [{ text: '❌ Отменить', callback_data: 'broadcast_cancel' }],
                ]
              });
            }
          } else if (data === 'broadcast_skip_button') {
            const stateJson = await env.BROADCAST_STATE.get(`broadcast_${chatId}`);
            if (stateJson) {
              const state = JSON.parse(stateJson);
              await showBroadcastPreview(env, chatId, state);
            }
          } else if (data === 'broadcast_confirm') {
            const stateJson = await env.BROADCAST_STATE.get(`broadcast_${chatId}`);
            if (stateJson) {
              const state = JSON.parse(stateJson);
              await executeBroadcast(env, chatId, state);
            }
          } else if (data === 'broadcast_cancel') {
            await env.BROADCAST_STATE.delete(`broadcast_${chatId}`);
            await sendTelegramMessage(env.BOT_TOKEN, chatId, '❌ Создание рассылки отменено.', {
              inline_keyboard: [[{ text: '« Вернуться в админку', callback_data: 'admin_panel' }]]
            });
          }
          
          await answerCallbackQuery(env.BOT_TOKEN, callbackQuery.id);
        }
        
        return jsonResponse({ ok: true });
      }

      // ═══════════════════════════════════════════════════════════
      // API ENDPOINTS (для Mini App)
      // ═══════════════════════════════════════════════════════════

      if (path === '/api/health') {
        return jsonResponse({
          status: 'ok',
          timestamp: new Date().toISOString(),
          version: '2.0.0',
          mode: 'production_with_bot_and_sheets',
        });
      }


      if (path === '/api/partners' && request.method === 'GET') {
        const partners = await getSheetData(env.SHEET_ID, 'partners', accessToken);
        return jsonResponse(partners.map(p => ({
          title: p.title,
          url: p.url,
          category: p.category,
        })));
      }

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

      if (path === '/api/me' && request.method === 'POST') {
        const body = await request.json();
        const admins = await getSheetData(env.SHEET_ID, 'admins', accessToken);
        const is_admin = admins.some(a => 
          a.username && a.username.toLowerCase() === body.username?.toLowerCase()
        );
        return jsonResponse({ is_admin });
      }

      if (path === '/api/subscribers' && request.method === 'GET') {
        const users = await getSheetData(env.SHEET_ID, 'users', accessToken);
        return jsonResponse(users.map(u => ({
          telegram_id: u.telegram_id,
          username: u.username,
          subscribed: String(u.subscribed).toUpperCase() === 'TRUE',
        })));
      }

      return errorResponse('Endpoint not found', 404);
    } catch (error) {
      console.error('Error:', error);
      return errorResponse(error.message || 'Internal server error', 500);
    }
  },
};
