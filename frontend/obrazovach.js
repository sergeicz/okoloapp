// =====================================================
// ОБРАЗОВАТЕЛЬНЫЕ МАТЕРИАЛЫ - ЛОГИКА
// =====================================================

// Конфигурация
const EDUCATION_CONFIG = {
  API_URL: window.location.origin,  // Используем текущий домен
};

// Глобальные переменные
let tg;
let user = null;

// Инициализация Telegram WebApp
function initTelegramWebApp() {
  // Ждем полной загрузки Telegram WebApp
  if (typeof Telegram !== 'undefined' && Telegram.WebApp) {
    tg = Telegram.WebApp;
    
    // Получаем данные пользователя из Telegram
    user = tg.initDataUnsafe?.user || {
      id: 0,
      username: 'guest',
      first_name: 'Guest',
      language_code: 'ru'
    };

    console.log('👤 Пользователь:', user);

    // Расширение Telegram WebApp
    if (tg.expand) tg.expand();
    if (tg.ready) tg.ready();
  } else {
    console.warn('⚠️ Telegram WebApp SDK не загружен');
    user = {
      id: 0,
      username: 'guest',
      first_name: 'Guest',
      language_code: 'ru'
    };
  }
}

// Утилита для безопасных fetch запросов с обработкой ошибок и retry logic
async function safeFetchEducation(url, options = {}, retries = 3) {
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

// Показ успешных уведомлений
function showSuccess(message) {
  console.log('✅ Успех:', message);
  if (tg.showAlert) {
    tg.showAlert(message);
  } else {
    alert(message);
  }
}

// Показ загрузки
function showEducationLoading(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = `
      <div class="loading">
        <div class="hamster-container">
          <span class="hamster hamster-1">🐹</span>
          <span class="hamster hamster-2">🐹</span>
          <span class="hamster hamster-3">🐹</span>
          <span class="hamster hamster-4">🐹</span>
          <span class="hamster hamster-5">🐹</span>
        </div>
        <div class="loading-text">Загрузка образовательных материалов...</div>
      </div>
    `;
  }
}

// Инициализация свайпа для карточек
function initSwipeForEducationCards() {
  const container = document.querySelector('.education-swipe');
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

// Инициализация свайпа когда DOM загружен
document.addEventListener('DOMContentLoaded', () => {
  // Инициализация свайп-функциональности после короткой задержки для обеспечения отрисовки элементов
  setTimeout(initSwipeForEducationCards, 500);
});

// Загрузка образовательных материалов
async function loadEducationMaterials() {
  const container = document.getElementById('education-cards');
  showEducationLoading('education-cards');

  try {
    // Загрузка данных из API
    console.log('[EDUCATION] Attempting to fetch data from:', `${EDUCATION_CONFIG.API_URL}/api/obrazovach`);
    const response = await safeFetchEducation(`${EDUCATION_CONFIG.API_URL}/api/obrazovach`);
    console.log('[EDUCATION] Raw response:', response);
    
    const materials = response.materials || [];
    console.log('[EDUCATION] Data loaded:', materials);
    console.log('[EDUCATION] Total materials:', materials.length);

    if (!materials || materials.length === 0) {
      container.innerHTML = '<p style="text-align:center;">Образовательные материалы пока не добавлены</p>';
      return;
    }

    // Создание контейнера для карточек (вертикальное отображение)
    container.innerHTML = '<div class="education-vertical-list"></div>';

    const listContainer = container.querySelector('.education-vertical-list');

    // Отрисовка карточек вертикально
    materials.forEach(material => {
      const card = document.createElement('div');
      card.className = 'glass-card education-card';
      card.style.marginBottom = '20px';
      card.style.width = '100%';

      // Обложка
      if (material.url_cover) {
        const coverImg = document.createElement('img');
        coverImg.src = material.url_cover;
        coverImg.alt = material.title;
        coverImg.style.width = '100%';
        coverImg.style.borderRadius = '12px';
        coverImg.style.marginBottom = '15px';
        coverImg.style.objectFit = 'cover';
        coverImg.style.height = '200px';
        coverImg.onerror = function() {
          console.error('[EDUCATION] Failed to load image:', material.url_cover);
          this.style.display = 'none';
        };
        card.appendChild(coverImg);
      }

      // Заголовок
      const title = document.createElement('h3');
      title.textContent = material.title;
      card.appendChild(title);

      // Подзаголовок
      if (material.subtitle) {
        const subtitle = document.createElement('p');
        subtitle.textContent = material.subtitle;
        subtitle.style.marginTop = '10px';
        subtitle.style.color = 'var(--text-secondary)';
        subtitle.style.fontSize = '0.9rem';
        card.appendChild(subtitle);
      }

      // Кнопка - текст берётся из text_button
      const button = document.createElement('a');
      button.className = 'modern-btn';
      button.href = '#';
      button.textContent = material.text_button || 'Смотреть видео'; // Используем text_button из таблицы
      button.onclick = (e) => handleVideoButtonClick(e, material);

      card.appendChild(button);

      listContainer.appendChild(card);
    });
  } catch (error) {
    console.error('[EDUCATION] Error loading materials:', error);
    container.innerHTML = '<p style="text-align:center;color:red;">Ошибка загрузки образовательных материалов: ' + error.message + '</p>';
  }
}

// Обработка клика по кнопке видео
async function handleVideoButtonClick(event, material) {
  // ВАЖНО: Предотвращаем стандартное поведение
  event.preventDefault();

  console.log('[VIDEO CLICK] Sending video info to bot:', material.title || material.url_video);
  console.log('[VIDEO CLICK] User ID:', user.id);
  console.log('[VIDEO CLICK] Video URL:', material.url_video);

  // Вибрация для обратной связи
  if (tg.HapticFeedback) {
    tg.HapticFeedback.impactOccurred('light');
  }

  // Отправляем информацию о видео в бот
  try {
    console.log('[VIDEO CLICK] Sending video info request...');
    const response = await fetch(`${EDUCATION_CONFIG.API_URL}/api/send-video`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        user_id: user.id,
        username: user.username || '',
        video_url: material.url_video,
        title: material.title,
        subtitle: material.subtitle || '',
        url_cover: material.url_cover,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      console.log('[VIDEO CLICK] Response:', data);

      if (data.message_sent) {
        console.log('[VIDEO MESSAGE] ✅ Сообщение с видео отправлено в бот!');

        // Track education video click in Yandex.Metrika
        if (window.metrikaTrack) {
          window.metrikaTrack.educationVideoClick(material.title);
        }

        // Показываем уведомление
        showSuccess('Видео отправлено в бот. Проверьте сообщения.');
      }
    } else {
      console.error('[VIDEO CLICK] Request failed:', response.status);
    }
  } catch (error) {
    console.error('[VIDEO CLICK] Error sending video info:', error);
  }
}

// Инициализация приложения
async function initEducationApp() {
  try {
    console.log('🚀 Инициализация образовательного приложения...');
    console.log('👤 Пользователь:', user);

    // Регистрация пользователя
    await safeFetchEducation(`${EDUCATION_CONFIG.API_URL}/api/user`, {
      method: 'POST',
      body: JSON.stringify(user),
    }).catch(err => console.warn('User registration failed:', err));

    // Загрузка образовательных материалов
    console.log('📚 Загрузка образовательных материалов...');
    await loadEducationMaterials();

    // Track page view in Yandex.Metrika
    if (window.metrikaTrack) {
      window.metrikaTrack.obrazovachPageView();
    }

    console.log('✅ Инициализация образовательного приложения завершена!');

  } catch (error) {
    console.error('❌ Education app init error:', error);
    showError('Ошибка инициализации образовательного приложения');
  } finally {
    // ВСЕГДА скрываем preloader после завершения инициализации
    hidePreloader();
  }
}

// Функция скрытия preloader
function hidePreloader() {
  const preloader = document.getElementById('preloader');
  if (preloader) {
    console.log('🔄 Hiding preloader...');
    preloader.style.opacity = '0';
    preloader.style.transition = 'opacity 0.5s ease-out';
    setTimeout(() => {
      preloader.style.display = 'none';
      console.log('✅ Preloader hidden');
    }, 500);
  }
}

// Функция для ожидания загрузки Telegram WebApp SDK
function waitForTelegramWebApp(timeout = 10000) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    
    function checkTg() {
      if (typeof Telegram !== 'undefined' && Telegram.WebApp) {
        resolve(Telegram.WebApp);
      } else if (Date.now() - startTime >= timeout) {
        console.warn('⚠️ Telegram WebApp SDK не загрузился за отведенное время');
        resolve(null); // Продолжаем выполнение даже если SDK не загрузился
      } else {
        setTimeout(checkTg, 100);
      }
    }
    
    checkTg();
  });
}

// Запуск приложения при загрузке
document.addEventListener('DOMContentLoaded', async () => {
  // Ждем загрузки Telegram WebApp SDK
  await waitForTelegramWebApp();
  
  // Инициализируем Telegram WebApp
  initTelegramWebApp();
  
  // Запускаем приложение
  initEducationApp();
});