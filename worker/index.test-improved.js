// Улучшенная тестовая версия с редактируемыми мок-данными
import { mockData } from './mock-data.js';

// CORS заголовки
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

// Функция для создания JSON ответа с CORS
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // === Health check ===
      if (path === '/api/health' && request.method === 'GET') {
        return jsonResponse({
          status: 'ok',
          timestamp: new Date().toISOString(),
          version: '1.0.0 (TEST MODE)',
          mode: 'local_test_with_editable_data',
          info: 'Редактируйте worker/mock-data.js для изменения данных',
        });
      }

      // === Get partners ===
      if (path === '/api/partners' && request.method === 'GET') {
        console.log(`📦 Возвращено ${mockData.partners.length} партнерских ссылок`);
        return jsonResponse(mockData.partners);
      }

      // === Register user ===
      if (path === '/api/user' && request.method === 'POST') {
        const body = await request.json();
        console.log('👤 Регистрация пользователя:', body);
        
        // Проверяем существует ли
        const existing = mockData.users.find(u => String(u.telegram_id) === String(body.id));
        
        if (!existing) {
          mockData.users.push({
            telegram_id: String(body.id),
            username: body.username || 'N/A',
            first_name: body.first_name || 'Unknown',
            subscribed: true,
          });
          console.log(`✅ Новый пользователь: ${body.username} (${body.id})`);
        } else {
          console.log(`ℹ️ Пользователь уже существует: ${body.username}`);
        }
        
        return jsonResponse({ ok: true, success: true });
      }

      // === Check admin ===
      if (path === '/api/me' && request.method === 'POST') {
        const body = await request.json();
        const is_admin = mockData.admins.includes(body.username?.toLowerCase());
        
        console.log(`🔐 Проверка админа @${body.username}: ${is_admin ? '✅' : '❌'}`);
        console.log(`   Список админов:`, mockData.admins);
        
        return jsonResponse({ is_admin });
      }

      // === Get subscribers ===
      if (path === '/api/subscribers' && request.method === 'GET') {
        console.log(`📊 Возвращено ${mockData.users.length} подписчиков`);
        return jsonResponse(mockData.users.map(u => ({
          telegram_id: u.telegram_id,
          username: u.username,
          subscribed: u.subscribed,
        })));
      }

      // === Register click ===
      if (path === '/api/click' && request.method === 'POST') {
        const body = await request.json();
        mockData.clicks.push({
          telegram_id: body.telegram_id,
          url: body.url,
          timestamp: new Date().toISOString(),
        });
        console.log(`👆 Клик зарегистрирован: ${body.telegram_id} -> ${body.url}`);
        console.log(`   Всего кликов: ${mockData.clicks.length}`);
        return jsonResponse({ ok: true, success: true });
      }

      // === Send push ===
      if (path === '/api/push' && request.method === 'POST') {
        const body = await request.json();
        const subscribedCount = mockData.users.filter(u => u.subscribed).length;
        
        console.log(`📢 Push-уведомление:`);
        console.log(`   Заголовок: ${body.title}`);
        console.log(`   Сообщение: ${body.msg}`);
        console.log(`   Ссылка: ${body.link}`);
        console.log(`   Подписчиков: ${subscribedCount}`);
        
        return jsonResponse({
          ok: true,
          success: true,
          sent: subscribedCount,
          total: mockData.users.length,
          note: 'В тестовом режиме реальная отправка не выполняется',
        });
      }

      return jsonResponse({ error: 'Endpoint not found' }, 404);
      
    } catch (error) {
      console.error('❌ Ошибка:', error);
      return jsonResponse({ error: error.message || 'Internal server error' }, 500);
    }
  },
};
