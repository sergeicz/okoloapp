// =====================================================
// RESTART BOT FUNCTION
// =====================================================

/**
 * Перезапуск бота с вибрацией (haptic feedback)
 * Вызывается при клике на кнопку "Перезапусти бот"
 */
function restartBotAndVibrate() {
  // 1. Проверяем, доступен ли Telegram WebApp
  if (window.Telegram && window.Telegram.WebApp) {
    // 2. Вызываем openTelegramLink для перезапуска бота
    window.Telegram.WebApp.openTelegramLink('https://t.me/okolotattoo_bot?start=restart_from_mini_app');

    // 3. Вибрация через HapticFeedback (если доступен)
    if (window.Telegram.WebApp.HapticFeedback) {
      try {
        window.Telegram.WebApp.HapticFeedback.impactOccurred('medium');
      } catch (e) {
        console.warn('HapticFeedback impactOccurred failed:', e);
        // Fallback: обычная вибрация браузера
        if (navigator.vibrate) {
          navigator.vibrate([10]); // Вибрация на 10мс
        }
      }
    } else {
      // Fallback: обычная вибрация браузера
      if (navigator.vibrate) {
        navigator.vibrate([10]); // Вибрация на 10мс
      }
    }
  } else {
    // Fallback: если WebApp API недоступен, открываем в новой вкладке
    console.warn('Telegram WebApp API недоступен. Открываем ссылку в новой вкладке.');
    window.open('https://t.me/okolotattoo_bot', '_blank');

    // Вибрация браузера (если поддерживается)
    if (navigator.vibrate) {
      navigator.vibrate([10]);
    }
  }
}

// =====================================================
// COOKIE MODAL - KEYBOARD SUPPORT
// =====================================================

/**
 * Добавляем keyboard support для cookie modal
 * Enter/Space на label должны переключать checkbox
 */
document.addEventListener('DOMContentLoaded', function() {
  // Cookie policy/offer links
  const policyLinks = document.querySelectorAll('[data-action="openPolicy"]');
  const offerLinks = document.querySelectorAll('[data-action="openOffer"]');
  
  policyLinks.forEach(function(link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      if (typeof openPolicy === 'function') {
        openPolicy();
      }
    });
    
    link.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (typeof openPolicy === 'function') {
          openPolicy();
        }
      }
    });
  });
  
  offerLinks.forEach(function(link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      if (typeof openOffer === 'function') {
        openOffer();
      }
    });
    
    link.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (typeof openOffer === 'function') {
          openOffer();
        }
      }
    });
  });

  // Cookie accept button
  const cookieAcceptBtn = document.getElementById('cookieAcceptBtn');
  if (cookieAcceptBtn) {
    cookieAcceptBtn.addEventListener('click', handleCookieAccept);
    
    cookieAcceptBtn.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (!this.disabled) {
          handleCookieAccept();
        }
      }
    });
  }

  // Cookie checkbox keyboard support
  const cookieLabels = document.querySelectorAll('.cookie-checkbox-label');
  
  cookieLabels.forEach(function(label) {
    label.addEventListener('click', function(e) {
      if (e.target.tagName !== 'A') {
        const checkbox = label.querySelector('input[type="checkbox"]');
        if (checkbox) {
          checkbox.checked = !checkbox.checked;
          checkbox.dispatchEvent(new Event('change'));
        }
      }
    });
    
    label.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const checkbox = label.querySelector('input[type="checkbox"]');
        if (checkbox) {
          checkbox.checked = !checkbox.checked;
          checkbox.dispatchEvent(new Event('change'));
        }
      }
    });
  });

  // Promo restart button
  const promoRestartBtn = document.querySelector('[data-action="restartBot"]');
  if (promoRestartBtn) {
    promoRestartBtn.addEventListener('click', function(e) {
      e.preventDefault();
      restartBotAndVibrate();
    });
    
    promoRestartBtn.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        restartBotAndVibrate();
      }
    });
  }

  // Admin button keyboard support
  const adminBtn = document.getElementById('adminBtn');
  if (adminBtn) {
    adminBtn.addEventListener('keydown', function(e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        adminBtn.click();
      }
    });
  }
});
