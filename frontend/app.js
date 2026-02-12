// =====================================================
// ПАРТНЁРСКИЕ ССЫЛКИ - ОСНОВНАЯ ЛОГИКА
// =====================================================
//
// ОПТИМИЗАЦИЯ ЗАГРУЗКИ:
// - Lazy loading для изображений логотипов
// - Асинхронная декодировка изображений
// - DNS prefetch для API
// - Preload критичных ресурсов
// - Defer для скриптов
// =====================================================

// =====================================================
// YANDEX.METRIKA COUNTER
// =====================================================
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
  API_URL: 'https://app.okolotattooing.ru',  // VPS ПРОДАКШЕН
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

// Утилита для безопасных fetch запросов с обработкой ошибок и retry logic
async function safeFetch(url, options = {}, retries = 3) {
  let lastError;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000); // 10 секунд таймаут
      
      const response = await fetch(url, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeout);

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || `HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;
      console.error(`Fetch error (attempt ${attempt}/${retries}):`, error);
      
      // Не повторяем если это abort
      if (error.name === 'AbortError') {
        console.error('Request timeout');
        break;
      }
      
      // Не повторяем если это client error (4xx)
      if (error.message.includes('HTTP 4')) {
        break;
      }
      
      // Ждем перед следующей попыткой (exponential backoff)
      if (attempt < retries) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
        console.log(`Повторная попытка через ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  // Все попытки исчерпаны
  showError(lastError?.message || 'Ошибка сети. Проверьте подключение.');
  throw lastError;
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

// Показ красивого уведомления о промокоде
function showPromoNotification() {
  // Удаляем предыдущее уведомление если есть
  const existing = document.querySelector('.promo-notification');
  if (existing) {
    existing.remove();
  }
  
  // Создаем новое уведомление
  const notification = document.createElement('div');
  notification.className = 'promo-notification';
  notification.innerHTML = `
    <div class="promo-notification-icon">🎁</div>
    <div class="promo-notification-content">
      <div class="promo-notification-title">Промокод отправлен!</div>
      <div class="promo-notification-text">Проверьте личные сообщения с ботом</div>
    </div>
    <button class="promo-notification-close">×</button>
  `;
  
  // Добавляем на страницу
  document.body.appendChild(notification);
  
  // Вибрация для обратной связи
  if (tg.HapticFeedback) {
    tg.HapticFeedback.notificationOccurred('success');
  }
  
  // Закрытие по клику на крестик
  const closeBtn = notification.querySelector('.promo-notification-close');
  closeBtn.onclick = () => {
    notification.classList.add('hiding');
    setTimeout(() => notification.remove(), 300);
  };
  
  // Автоматическое закрытие через 4 секунды
  setTimeout(() => {
    if (notification.parentElement) {
      notification.classList.add('hiding');
      setTimeout(() => {
        if (notification.parentElement) {
          notification.remove();
        }
      }, 300);
    }
  }, 4000);
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

// Initialize swipe functionality for categories
function initSwipeForCategories() {
  const container = document.querySelector('.categories-swipe');
  if (!container) return;

  let isDown = false;
  let startX;
  let scrollLeft;

  container.addEventListener('mousedown', (e) => {
    isDown = true;
    startX = e.pageX - container.offsetLeft;
    scrollLeft = container.scrollLeft;
  });

  container.addEventListener('mouseleave', () => {
    isDown = false;
  });

  container.addEventListener('mouseup', () => {
    isDown = false;
  });

  container.addEventListener('mousemove', (e) => {
    if (!isDown) return;
    e.preventDefault();
    const x = e.pageX - container.offsetLeft;
    const walk = (x - startX) * 2; // Multiplier for faster scrolling
    container.scrollLeft = scrollLeft - walk;
  });

  // Touch events for mobile devices
  container.addEventListener('touchstart', (e) => {
    const touch = e.touches[0];
    isDown = true;
    startX = touch.pageX - container.offsetLeft;
    scrollLeft = container.scrollLeft;
  });

  container.addEventListener('touchend', () => {
    isDown = false;
  });

  container.addEventListener('touchmove', (e) => {
    if (!isDown) return;
    const touch = e.touches[0];
    const x = touch.pageX - container.offsetLeft;
    const walk = (x - startX) * 2; // Multiplier for faster scrolling
    container.scrollLeft = scrollLeft - walk;
  });
}

// Initialize swipe when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  // Initialize swipe functionality after a short delay to ensure elements are rendered
  setTimeout(initSwipeForCategories, 500);
});

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
    const response = await safeFetch(`${CONFIG.API_URL}/api/partners`);
    const partners = response.partners || [];
    console.log('[PARTNERS] Data loaded:', partners);
    console.log('[PARTNERS] Total partners:', partners.length);
    
    // Логируем партнеров с промокодами
    partners.forEach(p => {
      if (p.promocode && p.promocode.trim() !== '') {
        console.log(`[PARTNERS] ${p.title} has promocode: "${p.promocode}"`);
      }
    });

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
      div.className = 'glass-card category-item';

      const h = document.createElement('h3');
      h.textContent = catName;
      div.appendChild(h);

      links.forEach(link => {
        console.log(`[BTN] Creating button: ${link.title}`);
        console.log(`[BTN] - Logo: ${link.logo_url || 'none'}`);
        console.log(`[BTN] - URL: ${link.url}`);
        console.log(`[BTN] - Promocode: ${link.promocode || 'none'}`);
        
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
          logo.loading = 'lazy'; // Lazy loading для логотипов
          logo.decoding = 'async'; // Асинхронная декодировка
          
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
  // ВАЖНО: Предотвращаем стандартное поведение ссылки
  event.preventDefault();
  
  console.log('[CLICK] Tracking click:', link.title || link.url);
  console.log('[CLICK] User ID:', user.id);
  console.log('[CLICK] Partner data:', { title: link.title, url: link.url, promocode: link.promocode });
  
  // Вибрация для обратной связи
  if (tg.HapticFeedback) {
    tg.HapticFeedback.impactOccurred('light');
  }
  
  // Отправляем данные о клике и ЖДЕМ завершения
  try {
    console.log('[CLICK] Sending tracking request...');
    const response = await fetch(`${CONFIG.API_URL}/api/click`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        partner_id: link.id || link.title,
        user_id: user.id,
        username: user.username || '',
        partner_url: link.url,
      }),
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('[CLICK] Response:', data);
      
      if (data.promocode_sent) {
        console.log('[PROMOCODE] ✅ Промокод отправлен в бот!');
        // Показываем красивое уведомление
        showPromoNotification();
      }
    } else {
      console.error('[CLICK] Request failed:', response.status);
    }
  } catch (error) {
    console.error('[CLICK] Tracking error:', error);
    // Продолжаем даже если трекинг не удался
  }
  
  // Небольшая задержка перед открытием ссылки
  await new Promise(resolve => setTimeout(resolve, 200));
  
  // Открываем ссылку правильным способом
  console.log('[CLICK] Opening URL:', link.url);
  
  try {
    if (link.url.includes('t.me/') || link.url.includes('telegram.me/')) {
      // Для Telegram ссылок
      console.log('[CLICK] Using openTelegramLink');
      if (tg.openTelegramLink) {
        tg.openTelegramLink(link.url);
      } else {
        window.open(link.url, '_blank');
      }
    } else {
      // Для обычных ссылок
      console.log('[CLICK] Using openLink');
      if (tg.openLink) {
        tg.openLink(link.url);
      } else {
        window.open(link.url, '_blank');
      }
    }
  } catch (error) {
    console.error('[CLICK] Error opening link:', error);
    // Fallback - просто открываем в новой вкладке
    window.open(link.url, '_blank');
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

// Показ баннера партнёрам при скролле до него (только после полной загрузки страницы)
window.addEventListener('load', () => {
  const partnerBanner = document.querySelector('.partner-banner');
  
  if (partnerBanner) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          partnerBanner.classList.add('show');
          console.log('✨ Partner banner shown on scroll');
          observer.unobserve(partnerBanner);
        }
      });
    }, {
      threshold: 0.2,
      rootMargin: '0px 0px -50px 0px'
    });
    
    observer.observe(partnerBanner);
  }
});

// Показ социальных сетей, футера и блока перезапуска бота через 5 секунд после загрузки
window.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => {
    const social = document.querySelector('social');
    const footer = document.querySelector('.app-footer');
    const promoRestart = document.querySelector('.promo-restart-box');
    
    if (social) {
      social.classList.add('show');
      console.log('✨ Social media shown after 5 seconds');
    }
    
    if (footer) {
      footer.classList.add('show');
      console.log('✨ Footer shown after 5 seconds');
    }
    
    if (promoRestart) {
      promoRestart.classList.add('show');
      console.log('✨ Promo restart box shown after 5 seconds');
    }
  }, 5000);
});

// Обработка ошибок приложения
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
});
