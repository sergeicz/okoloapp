// =====================================================
// ПАРТНЁРСКИЕ ССЫЛКИ - ОСНОВНАЯ ЛОГИКА
// =====================================================

// Cookie Consent Management
function checkCookieConsent() {
  const consent = localStorage.getItem('cookieConsent');
  if (consent === 'accepted') {
    document.getElementById('cookieConsent').classList.add('hidden');
  } else {
    document.getElementById('cookieConsent').classList.remove('hidden');
  }
}

function acceptCookies() {
  localStorage.setItem('cookieConsent', 'accepted');
  const modal = document.getElementById('cookieConsent');
  modal.style.animation = 'fadeOut 0.5s ease';
  setTimeout(() => {
    modal.classList.add('hidden');
  }, 500);
}

// Check consent on page load
window.addEventListener('DOMContentLoaded', checkCookieConsent);

// =====================================================
// КОНФИГУРАЦИЯ
// =====================================================

const CONFIG = {
  API_URL: 'https://telegram-miniapp-api.worknotdead.workers.dev',  // ПРОДАКШЕН
};

const tg = Telegram.WebApp;

// Получаем данные пользователя из Telegram
let user = tg.initDataUnsafe.user || {
  id: 0,
  username: 'guest',
  first_name: 'Guest',
  language_code: 'ru'
};

console.log('👤 Пользователь:', user);

// Расширение Telegram WebApp
if (tg.expand) tg.expand();
if (tg.ready) tg.ready();

// =====================================================
// УТИЛИТЫ
// =====================================================

// Утилита для безопасных fetch запросов с обработкой ошибок
async function safeFetch(url, options = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Fetch error:', error);
    showError(error.message || 'Ошибка сети. Проверьте подключение.');
    throw error;
  }
}

// Показ ошибок пользователю
function showError(message) {
  console.error('❌ Ошибка:', message);
  if (tg.showAlert) {
    tg.showAlert(message);
  } else {
    alert(message);
  }
}

// Показ успешного действия
function showSuccess(message) {
  console.log('✅ Успех:', message);
  if (tg.showAlert) {
    tg.showAlert(message);
  } else {
    alert(message);
  }
}

// Показ загрузки
function showLoading(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = `
      <div class="loading">
        <div class="loading-bar-container">
          <div class="loading-bar"></div>
        </div>
        <div class="loading-text">Загрузка...</div>
      </div>
    `;
  }
}

// =====================================================
// ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ
// =====================================================

async function initApp() {
  try {
    console.log('🚀 Инициализация приложения...');
    console.log('👤 Пользователь:', user);
    
    // Регистрация пользователя
    await safeFetch(`${CONFIG.API_URL}/api/user`, {
      method: 'POST',
      body: JSON.stringify(user),
    }).catch(err => console.warn('User registration failed:', err));

    // Проверка прав администратора
    console.log('🔐 Проверка прав администратора...');
    await checkAdmin();

    // Загрузка партнеров
    console.log('📦 Загрузка партнерских ссылок...');
    await loadPartners();
    
    console.log('✅ Инициализация завершена!');

  } catch (error) {
    console.error('❌ Init error:', error);
    showError('Ошибка инициализации приложения');
  }
}

// =====================================================
// АДМИНИСТРИРОВАНИЕ
// =====================================================

// Проверка прав администратора
async function checkAdmin() {
  try {
    const data = await safeFetch(`${CONFIG.API_URL}/api/me`, {
      method: 'POST',
      body: JSON.stringify(user),
    });

    if (data.is_admin) {
      const btn = document.getElementById('adminBtn');
      btn.style.display = 'block';
      btn.onclick = toggleAdminPanel;
    }
  } catch (error) {
    console.error('Admin check failed:', error);
  }
}

// Переключение панели администратора
function toggleAdminPanel() {
  const panel = document.getElementById('adminPanel');
  
  // Получаем computed style, так как inline style может быть пустым
  const currentDisplay = window.getComputedStyle(panel).display;
  const isVisible = currentDisplay !== 'none';
  
  console.log('🔄 Переключение админ-панели. Текущее состояние:', isVisible ? 'видна' : 'скрыта');
  
  if (isVisible) {
    panel.style.display = 'none';
    console.log('❌ Админ-панель скрыта');
  } else {
    panel.style.display = 'block';
    console.log('✅ Админ-панель показана');
    loadAdminData();
  }
}

// Загрузка данных администратора
async function loadAdminData() {
  const statsDiv = document.getElementById('stats');
  const table = document.getElementById('userTable');

  showLoading('stats');
  table.innerHTML = '<tr><th>Username</th><th>Telegram ID</th><th>Подписан</th></tr>';

  try {
    const users = await safeFetch(`${CONFIG.API_URL}/api/subscribers`);

    // Статистика
    const subscribed = users.filter(u => u.subscribed).length;
    const unsubscribed = users.length - subscribed;
    statsDiv.innerHTML = `
      <div class="stat-card">
        <div class="number">${users.length}</div>
        <div class="label">Всего</div>
      </div>
      <div class="stat-card">
        <div class="number">${subscribed}</div>
        <div class="label">Подписаны</div>
      </div>
      <div class="stat-card">
        <div class="number">${unsubscribed}</div>
        <div class="label">Отписаны</div>
      </div>
    `;

    // Таблица пользователей
    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';
    users.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${u.username || 'N/A'}</td>
        <td>${u.telegram_id}</td>
        <td>${u.subscribed ? '✅' : '❌'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (error) {
    statsDiv.innerHTML = '<div style="color:#ff6b6b;text-align:center;">Ошибка загрузки данных</div>';
  }
}

// =====================================================
// ПАРТНЁРЫ И ССЫЛКИ
// =====================================================

// Загрузка партнеров
async function loadPartners() {
  const container = document.getElementById('categories');
  showLoading('categories');

  try {
    const partners = await safeFetch(`${CONFIG.API_URL}/api/partners`);
    console.log('[PARTNERS] Data loaded:', partners);

    if (!partners || partners.length === 0) {
      container.innerHTML = '<p style="text-align:center;">Партнерские ссылки пока не добавлены</p>';
      return;
    }

    // Группировка по категориям
    const categories = {};
    partners.forEach(p => {
      if (!categories[p.category]) categories[p.category] = [];
      categories[p.category].push(p);
    });

    // Отрисовка категорий
    container.innerHTML = '';
    for (const [catName, links] of Object.entries(categories)) {
      const div = document.createElement('div');
      div.className = 'glass-card';

      const h = document.createElement('h3');
      h.textContent = catName;
      div.appendChild(h);

      links.forEach(link => {
        console.log(`[BTN] ${link.title} | Logo: ${link.logo_url || 'none'}`);
        
        const a = document.createElement('a');
        a.className = 'modern-btn';
        a.href = link.url;
        a.target = '_blank';
        a.onclick = (e) => handleLinkClick(e, link);
        
        // Добавляем логотип если есть
        if (link.logo_url && link.logo_url.trim() !== '') {
          console.log('[LOGO] Adding:', link.logo_url);
          
          const logo = document.createElement('img');
          logo.src = link.logo_url;
          logo.alt = link.title;
          logo.className = 'btn-logo';
          
          logo.onerror = function() {
            console.error('[LOGO] Load failed:', link.logo_url);
            this.style.display = 'none';
          };
          
          logo.onload = function() {
            console.log('[LOGO] Load success:', link.logo_url);
          };
          
          a.appendChild(logo);
        }
        
        // Добавляем текст
        const text = document.createElement('span');
        text.textContent = link.title;
        a.appendChild(text);
        
        div.appendChild(a);
      });

      container.appendChild(div);
    }
  } catch (error) {
    container.innerHTML = '<p style="text-align:center;color:red;">Ошибка загрузки партнеров</p>';
  }
}

// Обработка клика по ссылке
async function handleLinkClick(event, link) {
  try {
    console.log('[CLICK] Tracking click:', link.title || link.url);
    
    // Регистрация клика (не блокируем переход)
    safeFetch(`${CONFIG.API_URL}/api/click`, {
      method: 'POST',
      body: JSON.stringify({
        telegram_id: user.id,
        url: link.url,
        title: link.title,
        category: link.category,
      }),
    }).catch(err => console.warn('Click tracking failed:', err));

    // Вибрация для обратной связи
    if (tg.HapticFeedback) {
      tg.HapticFeedback.impactOccurred('light');
    }
  } catch (error) {
    console.error('Link click handler error:', error);
  }
}

// =====================================================
// ОБРАБОТКА ФОРМЫ РАССЫЛКИ
// =====================================================

document.getElementById('pushForm').onsubmit = async (e) => {
  e.preventDefault();

  const title = document.getElementById('pushTitle').value.trim();
  const msg = document.getElementById('pushMessage').value.trim();
  const link = document.getElementById('pushLink').value.trim();

  // Валидация
  if (!title || !msg || !link) {
    showError('Заполните все поля');
    return;
  }

  if (!link.startsWith('http://') && !link.startsWith('https://')) {
    showError('Ссылка должна начинаться с http:// или https://');
    return;
  }

  const submitBtn = e.target.querySelector('button');
  const originalText = submitBtn.textContent;
  submitBtn.disabled = true;
  submitBtn.textContent = '⏳ Отправка...';

  try {
    const result = await safeFetch(`${CONFIG.API_URL}/api/push`, {
      method: 'POST',
      body: JSON.stringify({ title, msg, link }),
    });

    showSuccess(`✅ Пуш отправлен! (${result.sent || 0}/${result.total || 0} успешно)`);

    // Очистка формы
    document.getElementById('pushTitle').value = '';
    document.getElementById('pushMessage').value = '';
    document.getElementById('pushLink').value = '';

  } catch (error) {
    // Ошибка уже показана в safeFetch
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = originalText;
  }
};

// =====================================================
// ОБРАБОТКА СОБЫТИЙ И ОШИБОК
// =====================================================

// Запуск приложения при загрузке
window.addEventListener('DOMContentLoaded', initApp);

// Обработка ошибок приложения
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
});
