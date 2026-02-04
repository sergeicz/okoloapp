// 📝 РЕДАКТИРУЙТЕ ЭТОТ ФАЙЛ ДЛЯ ИЗМЕНЕНИЯ ТЕСТОВЫХ ДАННЫХ
// После сохранения worker автоматически перезагрузится

export const mockData = {
  // ПАРТНЕРСКИЕ ССЫЛКИ - добавьте свои!
  partners: [
    { title: 'Google', url: 'https://google.com', category: 'Поисковики' },
    { title: 'Yandex', url: 'https://yandex.ru', category: 'Поисковики' },
    { title: 'Amazon', url: 'https://amazon.com', category: 'Магазины' },
    { title: 'AliExpress', url: 'https://aliexpress.com', category: 'Магазины' },
    { title: 'Wildberries', url: 'https://wildberries.ru', category: 'Магазины' },
    { title: 'YouTube', url: 'https://youtube.com', category: 'Видео' },
    { title: 'Netflix', url: 'https://netflix.com', category: 'Видео' },
    { title: 'Udemy', url: 'https://udemy.com', category: 'Образование' },
    { title: 'Coursera', url: 'https://coursera.org', category: 'Образование' },
    { title: 'Spotify', url: 'https://spotify.com', category: 'Музыка' },
    // Добавьте свои ссылки здесь:
    // { title: 'Название', url: 'https://...', category: 'Категория' },
  ],

  // ПОЛЬЗОВАТЕЛИ (будут добавляться автоматически)
  users: [
    { telegram_id: '123456789', username: 'testuser', first_name: 'Test', subscribed: true },
    { telegram_id: '1093761679', username: 'ebashordie', first_name: 'User', subscribed: true },
  ],

  // АДМИНИСТРАТОРЫ - добавьте свой Telegram username БЕЗ @
  admins: [
    'testuser',     // Тестовый пользователь
    'ebashordie',  // ← ЗАМЕНИТЕ на ваш username
  ],

  // КЛИКИ (будут добавляться автоматически)
  clicks: [],
};
