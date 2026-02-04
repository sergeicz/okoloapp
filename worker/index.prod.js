import { GoogleSpreadsheet } from 'google-spreadsheet';
import { JWT } from 'google-auth-library';

// CORS заголовки
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

// Функция для создания JSON ответа с CORS
function jsonResponse(data, status = 200, additionalHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
      ...additionalHeaders,
    },
  });
}

// Функция для создания ошибки
function errorResponse(message, status = 500) {
  console.error(`Error ${status}: ${message}`);
  return jsonResponse({ error: message, success: false }, status);
}

// Валидация переменных окружения
function validateEnv(env) {
  const required = ['CREDENTIALS_JSON', 'SHEET_ID', 'BOT_TOKEN'];
  const missing = required.filter(key => !env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing environment variables: ${missing.join(', ')}`);
  }
}

// Инициализация Google Sheets
async function initializeSheet(env) {
  try {
    const creds = JSON.parse(env.CREDENTIALS_JSON);
    
    const serviceAccountAuth = new JWT({
      email: creds.client_email,
      key: creds.private_key,
      scopes: ['https://www.googleapis.com/auth/spreadsheets'],
    });
    
    const doc = new GoogleSpreadsheet(env.SHEET_ID, serviceAccountAuth);
    await doc.loadInfo();
    return doc;
  } catch (error) {
    console.error('Failed to initialize Google Sheets:', error);
    throw new Error('Failed to connect to database');
  }
}

// Безопасное получение листа
function getSheet(doc, sheetName) {
  const sheet = doc.sheetsByTitle[sheetName];
  if (!sheet) {
    throw new Error(`Sheet "${sheetName}" not found`);
  }
  return sheet;
}

// Валидация Telegram данных
function validateTelegramData(data) {
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid data format');
  }
  return true;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Обработка CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Валидация окружения
      validateEnv(env);

      // Инициализация документа
      const doc = await initializeSheet(env);

      // === GET /api/partners - Получить список партнеров ===
      if (path === '/api/partners' && request.method === 'GET') {
        try {
          const sheet = getSheet(doc, 'partners');
          const rows = await sheet.getRows();
          
          const partners = rows
            .filter(r => r.title && r.url && r.category)
            .map(r => ({
              title: r.title,
              url: r.url,
              category: r.category,
            }));

          console.log(`Retrieved ${partners.length} partners`);
          return jsonResponse(partners);
        } catch (error) {
          return errorResponse(`Failed to fetch partners: ${error.message}`, 500);
        }
      }

      // === POST /api/click - Зарегистрировать клик ===
      if (path === '/api/click' && request.method === 'POST') {
        try {
          const body = await request.json();
          
          if (!body.telegram_id || !body.url) {
            return errorResponse('Missing required fields: telegram_id, url', 400);
          }

          const clicks = getSheet(doc, 'clicks');
          await clicks.addRow({
            telegram_id: String(body.telegram_id),
            url: body.url,
            timestamp: new Date().toISOString(),
          });

          console.log(`Click registered: ${body.telegram_id} -> ${body.url}`);
          return jsonResponse({ ok: true, success: true });
        } catch (error) {
          return errorResponse(`Failed to register click: ${error.message}`, 500);
        }
      }

      // === POST /api/user - Регистрация пользователя ===
      if (path === '/api/user' && request.method === 'POST') {
        try {
          const body = await request.json();
          validateTelegramData(body);

          if (!body.id) {
            return errorResponse('Missing user id', 400);
          }

          const users = getSheet(doc, 'users');
          const rows = await users.getRows();
          const existing = rows.find(r => String(r.telegram_id) === String(body.id));

          if (!existing) {
            await users.addRow({
              telegram_id: String(body.id),
              username: body.username || 'N/A',
              first_name: body.first_name || 'Unknown',
              date_added: new Date().toISOString(),
              subscribed: 'TRUE',
            });
            console.log(`New user registered: ${body.id} (@${body.username})`);
          } else {
            console.log(`User already exists: ${body.id}`);
          }

          return jsonResponse({ ok: true, success: true });
        } catch (error) {
          return errorResponse(`Failed to register user: ${error.message}`, 500);
        }
      }

      // === POST /api/me - Проверка прав администратора ===
      if (path === '/api/me' && request.method === 'POST') {
        try {
          const body = await request.json();
          
          if (!body.username) {
            return jsonResponse({ is_admin: false });
          }

          const admins = getSheet(doc, 'admins');
          const rows = await admins.getRows();
          const is_admin = rows.some(r => 
            r.username && r.username.toLowerCase() === body.username.toLowerCase()
          );

          console.log(`Admin check for @${body.username}: ${is_admin}`);
          return jsonResponse({ is_admin });
        } catch (error) {
          return errorResponse(`Failed to check admin status: ${error.message}`, 500);
        }
      }

      // === GET /api/subscribers - Получить список подписчиков ===
      if (path === '/api/subscribers' && request.method === 'GET') {
        try {
          const users = getSheet(doc, 'users');
          const rows = await users.getRows();
          
          const subscribers = rows.map(r => ({
            telegram_id: r.telegram_id,
            username: r.username || 'N/A',
            subscribed: String(r.subscribed).toUpperCase() === 'TRUE',
          }));

          console.log(`Retrieved ${subscribers.length} subscribers`);
          return jsonResponse(subscribers);
        } catch (error) {
          return errorResponse(`Failed to fetch subscribers: ${error.message}`, 500);
        }
      }

      // === POST /api/push - Отправить пуш-уведомление ===
      if (path === '/api/push' && request.method === 'POST') {
        try {
          const body = await request.json();

          if (!body.title || !body.msg || !body.link) {
            return errorResponse('Missing required fields: title, msg, link', 400);
          }

          const users = getSheet(doc, 'users');
          const rows = await users.getRows();
          const subscribedUsers = rows.filter(r => 
            String(r.subscribed).toUpperCase() === 'TRUE' && r.telegram_id
          );

          console.log(`Sending push to ${subscribedUsers.length} users`);

          // Отправка уведомлений асинхронно
          const sendPromises = subscribedUsers.map(async (user) => {
            try {
              const response = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  chat_id: user.telegram_id,
                  text: `*${body.title}*\n\n${body.msg}`,
                  parse_mode: 'Markdown',
                  reply_markup: {
                    inline_keyboard: [[{ text: 'Перейти', url: body.link }]],
                  },
                }),
              });

              if (!response.ok) {
                const error = await response.text();
                console.error(`Failed to send to ${user.telegram_id}: ${error}`);
                return { success: false, user: user.telegram_id };
              }

              return { success: true, user: user.telegram_id };
            } catch (error) {
              console.error(`Error sending to ${user.telegram_id}:`, error);
              return { success: false, user: user.telegram_id };
            }
          });

          // Ждем завершения всех отправок (с таймаутом)
          const results = await Promise.allSettled(sendPromises);
          const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;

          console.log(`Push sent: ${successful}/${subscribedUsers.length} successful`);
          
          return jsonResponse({ 
            ok: true, 
            success: true,
            sent: successful,
            total: subscribedUsers.length,
          });
        } catch (error) {
          return errorResponse(`Failed to send push: ${error.message}`, 500);
        }
      }

      // === GET /api/health - Проверка здоровья сервиса ===
      if (path === '/api/health' && request.method === 'GET') {
        return jsonResponse({ 
          status: 'ok', 
          timestamp: new Date().toISOString(),
          version: '1.0.0',
        });
      }

      // 404 для неизвестных эндпоинтов
      return errorResponse('Endpoint not found', 404);

    } catch (error) {
      console.error('Unhandled error:', error);
      return errorResponse(
        error.message || 'Internal server error',
        500
      );
    }
  },
};
