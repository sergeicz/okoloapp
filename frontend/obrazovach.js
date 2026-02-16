// =====================================================
// ОБРАЗОВАТЕЛЬНЫЕ МАТЕРИАЛЫ - ЛОГИКА
// =====================================================

// =====================================================
// CLOUD STORAGE DIRECT LINK CONVERTER
// =====================================================

/**
 * Converts Yandex Disk and Google Drive share links to direct download/view links
 * @param {string} url - Original share URL
 * @returns {string} - Direct link or original URL if conversion failed
 */
function convertToDirectLink(url) {
  if (!url || typeof url !== 'string') return url;

  // Yandex Disk: https://disk.yandex.ru/i/xxx or https://yadi.sk/i/xxx
  if (url.includes('disk.yandex.ru') || url.includes('yadi.sk')) {
    // Extract the file ID
    const match = url.match(/\/[id]\/([a-zA-Z0-9_-]+)/);
    if (match) {
      const fileId = match[1];
      return `https://downloader.disk.yandex.ru/disk/file/${fileId}`;
    }
    // If it's already a public link, try to get direct download
    if (url.includes('/d/')) {
      return url.replace('/d/', '/i/');
    }
  }

  // Google Drive: https://drive.google.com/file/d/FILE_ID/view
  if (url.includes('drive.google.com')) {
    const match = url.match(/\/d\/([a-zA-Z0-9_-]+)/);
    if (match) {
      const fileId = match[1];
      // Use Google Drive's thumbnail/direct view endpoint
      return `https://drive.google.com/uc?export=view&id=${fileId}`;
    }
  }

  // Return original URL if no conversion needed
  return url;
}

// Конфигурация
const EDUCATION_CONFIG = {
  API_URL: 'https://app.okolotattooing.ru',  // Используем серверный домен
};

// Глобальные переменные
let educationTg;
let user = null;

// Инициализация Telegram WebApp
function initTelegramWebApp() {
  // Ждем полной загрузки Telegram WebApp
  if (typeof Telegram !== 'undefined' && Telegram.WebApp) {
    educationTg = Telegram.WebApp;
    
    // Получаем данные пользователя из Telegram
    user = educationTg.initDataUnsafe?.user || {
      id: 0,
      username: 'guest',
      first_name: 'Guest',
      language_code: 'ru'
    };

    console.log('👤 Пользователь:', user);

    // Расширение Telegram WebApp
    if (educationTg.expand) educationTg.expand();
    if (educationTg.ready) educationTg.ready();
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
        const errorText = await response.text(); // Получаем текст ошибки
        console.error(`HTTP ${response.status} Response:`, errorText);
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;
      console.error(`Fetch error (attempt ${attempt}/${retries}):`, error);
      console.error(`Error details:`, {
        name: error.name,
        message: error.message,
        stack: error.stack
      });

      // Не повторяем если это abort
      if (error.name === 'AbortError') {
        console.error('Request timeout');
        break;
      }

      // Не повторяем если это CORS или network error
      if (error.message.includes('HTTP 4') || 
          error.message.includes('Failed to fetch') || 
          error.message.includes('CORS')) {
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
  showError(lastError?.message || 'Ошибка сети. Проверь подключение.');
  throw lastError;
}

// Показ ошибок пользователю
function showError(message, subtext = '', duration = 4000) {
  console.error('❌ Ошибка:', message);

  // Используем тот же popup, но с красной иконкой
  showSuccess(message, subtext, '❌', duration);
}

// Показ успешных уведомлений
function showSuccess(message, subtext = '', icon = '✅', duration = 3000) {
  console.log('✅ Успех:', message);

  // Получаем элементы popup
  const popup = document.getElementById('notificationPopup');
  const iconElement = document.getElementById('notificationIcon');
  const textElement = document.getElementById('notificationText');
  const subtextElement = document.getElementById('notificationSubtext');

  if (!popup || !iconElement || !textElement || !subtextElement) {
    // Fallback если элементы не найдены
    if (educationTg && educationTg.showAlert) {
      educationTg.showAlert(message);
    } else {
      alert(message);
    }
    return;
  }

  // Устанавливаем содержимое
  iconElement.textContent = icon;
  textElement.textContent = message;
  subtextElement.textContent = subtext;

  // Скрываем subtext если его нет
  if (!subtext) {
    subtextElement.style.display = 'none';
  } else {
    subtextElement.style.display = 'block';
  }

  // Показываем popup
  popup.classList.add('show');
  popup.classList.remove('hide');

  // Вибрация
  if (educationTg && educationTg.HapticFeedback) {
    educationTg.HapticFeedback.notificationOccurred('success');
  }

  // Автоматически скрываем через duration миллисекунд
  setTimeout(() => {
    hideNotification();
  }, duration);
}

// Скрытие notification popup
function hideNotification() {
  const popup = document.getElementById('notificationPopup');
  if (popup) {
    popup.classList.remove('show');
    popup.classList.add('hide');

    // Полностью убираем классы после анимации
    setTimeout(() => {
      popup.classList.remove('hide');
    }, 300);
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

// Инициализация свайпа для карточек - ОТКЛЮЧЕНО
// function initSwipeForEducationCards() {
//   const container = document.querySelector('.education-swipe');
//   if (!container) return;
//
//   let isDown = false;
//   let startX;
//   let scrollLeft;
//
//   container.addEventListener('mousedown', (e) => {
//     isDown = true;
//     startX = e.pageX - container.offsetLeft;
//     scrollLeft = container.scrollLeft;
//   });
//
//   container.addEventListener('mouseleave', () => {
//     isDown = false;
//   });
//
//   container.addEventListener('mouseup', () => {
//     isDown = false;
//   });
//
//   container.addEventListener('mousemove', (e) => {
//     if (!isDown) return;
//     e.preventDefault();
//     const x = e.pageX - container.offsetLeft;
//     const walk = (x - startX) * 2;
//     container.scrollLeft = scrollLeft - walk;
//   });
//
//   container.addEventListener('touchstart', (e) => {
//     const touch = e.touches[0];
//     isDown = true;
//     startX = touch.pageX - container.offsetLeft;
//     scrollLeft = container.scrollLeft;
//   });
//
//   container.addEventListener('touchend', () => {
//     isDown = false;
//   });
//
//   container.addEventListener('touchmove', (e) => {
//     if (!isDown) return;
//     const touch = e.touches[0];
//     const x = touch.pageX - container.offsetLeft;
//     const walk = (x - startX) * 2;
//     container.scrollLeft = scrollLeft - walk;
//   });
// }

// Инициализация свайпа отключена - карточки отображаются вертикально без эффектов
document.addEventListener('DOMContentLoaded', () => {
  console.log('[EDUCATION] Swipe effects disabled - vertical list only');
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
        const originalUrl = material.url_cover;
        const directUrl = convertToDirectLink(originalUrl);

        if (originalUrl !== directUrl) {
          console.log('[EDUCATION] Converted cover URL to direct link:', directUrl);
        }

        const coverImg = document.createElement('img');
        coverImg.src = directUrl;
        coverImg.alt = material.title;
        coverImg.style.width = '100%';
        coverImg.style.borderRadius = '12px';
        coverImg.style.marginBottom = '15px';
        coverImg.style.objectFit = 'cover';
        coverImg.style.height = '200px';
        coverImg.onerror = function() {
          console.error('[EDUCATION] Failed to load image:', directUrl);
          this.style.display = 'none';
        };
        card.appendChild(coverImg);
      }

      // Заголовок
      const title = document.createElement('h3');
      title.textContent = material.title;
      card.appendChild(title);

      // Лектор (если указан)
      if (material.lector_username && material.lector_username.trim() !== '') {
        const lectorContainer = document.createElement('div');
        lectorContainer.style.marginTop = '8px';
        lectorContainer.style.marginBottom = '8px';
        
        const lectorLabel = document.createElement('span');
        lectorLabel.textContent = 'Образовывает: ';
        lectorLabel.style.color = 'rgba(255, 255, 255, 0.6)';
        lectorLabel.style.fontSize = '0.85rem';
        
        const lectorLink = document.createElement('a');
        // Удаляем @ если есть и пробелы
        const cleanUsername = material.lector_username.replace('@', '').trim();
        lectorLink.href = 'https://t.me/' + cleanUsername;
        lectorLink.target = '_blank';
        lectorLink.textContent = '@' + cleanUsername;
        lectorLink.style.color = 'rgba(124, 58, 237, 0.9)';
        lectorLink.style.fontSize = '0.85rem';
        lectorLink.style.fontWeight = '600';
        lectorLink.style.textDecoration = 'underline';
        lectorLink.style.textDecorationColor = 'rgba(124, 58, 237, 0.4)';
        lectorLink.style.transition = 'all 0.2s ease';
        lectorLink.onmouseover = function() {
          this.style.color = 'rgba(124, 58, 237, 1)';
          this.style.textDecorationColor = 'rgba(124, 58, 237, 0.8)';
        };
        lectorLink.onmouseout = function() {
          this.style.color = 'rgba(124, 58, 237, 0.9)';
          this.style.textDecorationColor = 'rgba(124, 58, 237, 0.4)';
        };
        
        lectorContainer.appendChild(lectorLabel);
        lectorContainer.appendChild(lectorLink);
        card.appendChild(lectorContainer);
      }

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
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
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
  if (educationTg.HapticFeedback) {
    educationTg.HapticFeedback.impactOccurred('light');
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

        // Показываем красивое уведомление в стиле iPhone
        showEducationNotification();
      }
    } else {
      console.error('[VIDEO CLICK] Request failed:', response.status);
    }
  } catch (error) {
    console.error('[VIDEO CLICK] Error sending video info:', error);
  }
}

// Показ уведомления об отправке урока (iPhone стиль)
function showEducationNotification() {
  console.log('[EDU-UI] Showing notification...');
  
  // Удаляем предыдущее уведомление если есть
  const existing = document.querySelector('.edu-notification');
  if (existing) {
    console.log('[EDU-UI] Removing existing notification');
    existing.remove();
  }

  // Создаем новое уведомление с таймером
  const notification = document.createElement('div');
  notification.className = 'edu-notification';
  notification.innerHTML = `
    <div class="edu-notification-icon">🎥</div>
    <div class="edu-notification-content">
      <div class="edu-notification-title">Урок отправлен!</div>
      <div class="edu-notification-text">
        Открой Telegram и проверь сообщения
        <div class="edu-notification-timer">Получение: <span id="edu-timer">3</span> сек</div>
      </div>
    </div>
    <button class="edu-notification-close">×</button>
  `;

  // Добавляем на страницу
  document.body.appendChild(notification);
  console.log('[EDU-UI] Notification appended to body');

  // Запускаем таймер обратного отсчёта
  let secondsLeft = 3;
  const timerElement = document.getElementById('edu-timer');
  const timerInterval = setInterval(() => {
    secondsLeft--;
    if (timerElement) {
      timerElement.textContent = secondsLeft;
    }
    if (secondsLeft <= 0) {
      clearInterval(timerInterval);
      if (timerElement) {
        timerElement.parentElement.textContent = '✅ Сообщение должно прийти!';
      }
    }
  }, 1000);

  // Вибрация для обратной связи
  if (educationTg.HapticFeedback) {
    educationTg.HapticFeedback.notificationOccurred('success');
  }

  // Закрытие по клику на крестик
  const closeBtn = notification.querySelector('.edu-notification-close');
  closeBtn.onclick = () => {
    console.log('[EDU-UI] Closing notification via close button');
    clearInterval(timerInterval);
    notification.classList.add('hiding');
    setTimeout(() => notification.remove(), 300);
  };

  // Автоматическое закрытие через 3 секунды
  setTimeout(() => {
    clearInterval(timerInterval);
    if (notification.parentElement) {
      console.log('[EDU-UI] Auto-closing notification');
      notification.classList.add('hiding');
      setTimeout(() => {
        if (notification.parentElement) {
          notification.remove();
        }
      }, 300);
    }
  }, 3000);
}

// Инициализация приложения
async function initEducationApp() {
  try {
    console.log('🚀 Инициализация образовательного приложения...');
    console.log('👤 Пользователь:', user);
    console.log('🌐 API URL:', EDUCATION_CONFIG.API_URL);

    // Регистрация пользователя
    console.log('📝 Регистрация пользователя...');
    await safeFetchEducation(`${EDUCATION_CONFIG.API_URL}/api/user`, {
      method: 'POST',
      body: JSON.stringify(user),
    }).catch(err => console.warn('User registration failed:', err));

    // Загрузка образовательных материалов
    console.log('📚 Загрузка образовательных материалов...');
    await loadEducationMaterials();

    // Track page view in Yandex.Metrika
    if (window.metrikaTrack) {
      console.log('📊 Отправка просмотра страницы в Metrika');
      window.metrikaTrack.obrazovachPageView();
    }

    console.log('✅ Инициализация образовательного приложения завершена!');

  } catch (error) {
    console.error('❌ Education app init error:', error);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    showError('Ошибка инициализации образовательного приложения: ' + error.message);
  } finally {
    console.log('🔄 Пытаемся скрыть preloader...');
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
      // Полностью удаляем из DOM
      setTimeout(() => {
        if (preloader.parentNode) {
          preloader.parentNode.removeChild(preloader);
          console.log('✅ Preloader removed from DOM');
        }
      }, 100);
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

  // Добавляем обработчик клика на popup для закрытия
  const popup = document.getElementById('notificationPopup');
  if (popup) {
    popup.addEventListener('click', (e) => {
      // Закрываем только если клик был на фоне, а не на самом notification-box
      if (e.target === popup) {
        hideNotification();
      }
    });
  }
});