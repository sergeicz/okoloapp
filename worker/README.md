# Cloudflare Worker API

## Описание
Backend API для Telegram Mini App на Cloudflare Workers.

## Установка

### 1. Установите зависимости
```bash
npm install
```

### 2. Авторизуйтесь в Cloudflare
```bash
npx wrangler login
```

### 3. Настройте секреты
```bash
# Токен бота
npx wrangler secret put BOT_TOKEN

# ID Google таблицы
npx wrangler secret put SHEET_ID

# Credentials для Google Service Account (весь JSON в одну строку)
npx wrangler secret put CREDENTIALS_JSON
```

**Важно:** При добавлении `CREDENTIALS_JSON` вставьте весь JSON как одну строку без переносов.

## Разработка

### Локальный запуск
```bash
npm run dev
```

API будет доступно на `http://localhost:8787`

### Тестирование эндпоинтов
```bash
# Проверка здоровья
curl http://localhost:8787/api/health

# Получить партнеров
curl http://localhost:8787/api/partners
```

## Деплой на Cloudflare

### Первый деплой
```bash
npm run deploy
```

После деплоя вы получите URL вашего worker, например:
```
https://telegram-miniapp-api.your-subdomain.workers.dev
```

### Обновление после изменений
```bash
npm run deploy
```

### Просмотр логов
```bash
npm run tail
```

## API Endpoints

### `GET /api/health`
Проверка здоровья сервиса
```json
{
  "status": "ok",
  "timestamp": "2024-02-04T12:00:00.000Z",
  "version": "1.0.0"
}
```

### `GET /api/partners`
Получить список партнерских ссылок
```json
[
  {
    "title": "Partner 1",
    "url": "https://example.com",
    "category": "Category 1"
  }
]
```

### `POST /api/user`
Зарегистрировать пользователя
```json
{
  "id": 123456789,
  "username": "user",
  "first_name": "John"
}
```

### `POST /api/me`
Проверить права администратора
```json
{
  "username": "admin"
}
```

Response:
```json
{
  "is_admin": true
}
```

### `GET /api/subscribers`
Получить список подписчиков (для админов)
```json
[
  {
    "telegram_id": "123456789",
    "username": "user",
    "subscribed": true
  }
]
```

### `POST /api/click`
Зарегистрировать клик по ссылке
```json
{
  "telegram_id": 123456789,
  "url": "https://example.com"
}
```

### `POST /api/push`
Отправить push-уведомление (для админов)
```json
{
  "title": "Заголовок",
  "msg": "Сообщение",
  "link": "https://example.com"
}
```

Response:
```json
{
  "ok": true,
  "success": true,
  "sent": 50,
  "total": 52
}
```

## CORS
API настроен с открытым CORS (`Access-Control-Allow-Origin: *`) для работы с GitHub Pages.

## Лимиты Cloudflare Workers (Free план)
- 100,000 запросов в день
- 10ms CPU time на запрос
- 128 MB памяти

Для большей нагрузки рассмотрите платный план ($5/месяц).

## Мониторинг
Используйте Cloudflare Dashboard для мониторинга:
- Количество запросов
- Ошибки
- Производительность

## Безопасность
- Секреты хранятся в Cloudflare Workers Secrets (зашифрованы)
- CORS открыт для всех доменов (можно ограничить в коде)
- Рекомендуется добавить rate limiting для защиты от DDoS
