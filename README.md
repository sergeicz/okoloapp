# 🚀 Telegram Mini App - Partner Links Manager

> Полнофункциональное Telegram Mini App для управления партнерскими ссылками с админ-панелью и push-рассылками

[![Status](https://img.shields.io/badge/status-production-success)]()
[![Cloudflare](https://img.shields.io/badge/powered%20by-Cloudflare%20Workers-orange)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## 📖 Описание

Telegram Mini App с возможностью:

* 📊 Отображения партнерских ссылок по категориям
* 📈 Отслеживания кликов и статистики
* 👥 Управления пользователями
* 📢 Массовой рассылки push-уведомлений через бота
* 🔐 Админ-панели прямо в Telegram боте
* 💾 Google Sheets как база данных

## 🏗️ Архитектура

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  Telegram User  │──────│  GitHub Pages    │──────│  Cloudflare     │
│                 │      │  (Frontend)      │      │  Worker         │
│                 │      └──────────────────┘      │  (API + Bot)    │
│                 │                                 └─────────────────┘
│                 │                                          │
│    Админ в боте │◄─────────────────────────────────────────┤
│    /start       │                                          │
│    Админ-панель │                                          ▼
└─────────────────┘                              ┌─────────────────┐
                                                  │  Google Sheets  │
                                                  │  (Database)     │
                                                  └─────────────────┘
```

### Компоненты:

1. **Frontend** (`frontend/`) - Веб-интерфейс Mini App  
   * Deployment: GitHub Pages  
   * Tech: HTML, CSS, JavaScript, Telegram WebApp API

2. **Backend** (`worker/`) - API + Telegram Bot на одном Worker  
   * Deployment: Cloudflare Workers  
   * Tech: JavaScript, Google Sheets API, Telegram Bot API
   * Features: REST API, Telegram Webhook, Админ-панель в боте

3. **Database** - Google Sheets  
   * Листы: users, partners, admins, clicks  
   * Free, простая настройка, визуальное управление

## ✨ Возможности

### Для пользователей:
* ✅ Просмотр партнерских ссылок в Mini App
* ✅ Группировка по категориям
* ✅ Быстрый доступ через кнопку Menu в боте
* ✅ Современный glassmorphism UI

### Для администраторов (в Telegram боте):
* ✅ Команда `/start` - главное меню с кнопкой админки
* ✅ Админ-панель прямо в боте
* ✅ Статистика пользователей и кликов
* ✅ Массовая рассылка push-уведомлений
* ✅ Список пользователей

## 🚀 Быстрый старт

### Предварительные требования

* Аккаунт GitHub (для Frontend)
* Аккаунт Cloudflare (для Backend + Bot)
* Google аккаунт (для Database)
* Telegram бот (через @BotFather)

### Деплой за 3 шага

#### 1. Настройте Google Sheets

1. Создайте таблицу с 4 листами:
   - `users` (telegram_id, username, first_name, date_added, subscribed)
   - `partners` (title, url, category)
   - `admins` (username)
   - `clicks` (telegram_id, url, timestamp)

2. Создайте Service Account в Google Cloud Console
3. Получите `credentials.json`
4. Расшарьте таблицу с email Service Account

#### 2. Деплой на Cloudflare

```bash
cd worker
npm install
npx wrangler login

# Добавьте secrets
npx wrangler secret put BOT_TOKEN
npx wrangler secret put SHEET_ID
npx wrangler secret put WEBAPP_URL
npx wrangler secret put CREDENTIALS_JSON

# Деплой
npm run deploy
```

#### 3. Настройте Telegram Bot Webhook

```bash
curl "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=https://your-worker.workers.dev/bot<YOUR_BOT_TOKEN>"
```

#### 4. Деплой Frontend на GitHub Pages

1. Создайте репозиторий
2. Запушьте код
3. В Settings → Pages выберите `main` branch
4. Ваш URL: `https://username.github.io/repo-name/frontend/`

#### 5. Обновите WEBAPP_URL

```bash
npx wrangler secret put WEBAPP_URL
# Введите: https://username.github.io/repo-name/frontend/
```

**Готово!** 🎉

## 📂 Структура проекта

```
telegram-miniapp/
├── frontend/              # Mini App интерфейс
│   ├── index.html        # Главный файл
│   └── README.md         # Документация Frontend
│
├── worker/               # Cloudflare Worker (API + Bot)
│   ├── index.js          # API endpoints + Bot handlers
│   ├── package.json      # Зависимости
│   ├── wrangler.toml     # Конфигурация Cloudflare
│   └── README.md         # Документация Worker
│
├── credentials.json      # Google Service Account (НЕ коммитить!)
├── bot_token.txt         # Telegram Bot Token (НЕ коммитить!)
├── sheet_id.txt          # Google Sheets ID (НЕ коммитить!)
├── .gitignore           
├── ДЕПЛОЙ_БОТА_НА_CLOUDFLARE.md  # Инструкция по деплою
├── ИНСТРУКЦИЯ_ДЕПЛОЙ.md  # Подробная инструкция (русский)
└── README.md            # Этот файл
```

## 🤖 Использование Telegram Bot

### Для всех пользователей:

Команда `/start` - открывает главное меню с кнопками:
- 🚀 **Открыть Mini App** - запускает приложение
- ⚙️ **Админ-панель** (только для админов)

### Для администраторов:

Добавьте свой username (БЕЗ @) в лист `admins` в Google Sheets.

После этого в боте появится кнопка **⚙️ Админ-панель** с функциями:

1. **📊 Статистика**
   - Количество пользователей
   - Количество подписанных/отписанных
   - Количество ссылок и кликов

2. **📢 Рассылка**
   - Отправьте сообщение в формате:
   ```
   /broadcast Заголовок рассылки
   Текст сообщения.
   Можно несколько строк.
   https://ссылка-для-кнопки.com
   ```

3. **👥 Пользователи**
   - Список последних пользователей
   - Username, Telegram ID, статус подписки

## 🔧 API Endpoints

| Method | Endpoint         | Описание                           |
| ------ | ---------------- | ---------------------------------- |
| GET    | /api/health      | Проверка здоровья сервиса          |
| GET    | /api/partners    | Получить список партнерских ссылок |
| POST   | /api/user        | Зарегистрировать пользователя      |
| POST   | /api/me          | Проверить права администратора     |
| GET    | /api/subscribers | Получить список подписчиков        |
| POST   | /api/click       | Зарегистрировать клик              |

## 📊 Google Sheets структура

### Лист "partners"
| title | url | category |
|-------|-----|----------|
| Google | https://google.com | Поисковики |
| Amazon | https://amazon.com | Магазины |

### Лист "users"
| telegram_id | username | first_name | date_added | subscribed |
|-------------|----------|------------|------------|------------|
| 123456789 | user1 | John | 2024-01-01T00:00:00Z | TRUE |

### Лист "admins"
| username |
|----------|
| admin1 |
| admin2 |

### Лист "clicks"
| telegram_id | url | timestamp |
|-------------|-----|-----------|
| 123456789 | https://google.com | 2024-01-01T00:00:00Z |

## 💰 Стоимость

**Полностью бесплатно:**
* ✅ GitHub Pages: бесплатно
* ✅ Cloudflare Workers: бесплатно (100k запросов/день)
* ✅ Google Sheets: бесплатно
* ✅ Telegram Bot API: бесплатно

## 🔐 Безопасность

* ✅ Все секреты в Cloudflare Secrets
* ✅ HTTPS для всех соединений
* ✅ Проверка прав администратора
* ✅ CORS настроен

**⚠️ Важно:** Никогда не коммитьте `credentials.json`, `bot_token.txt` или другие секреты в Git!

## 📝 Обновление

### Обновить код Worker:

```bash
cd worker
# Измените index.js
npm run deploy
```

### Обновить Frontend:

```bash
# Измените frontend/index.html
git add .
git commit -m "Update frontend"
git push
# GitHub Pages обновится автоматически через 1-2 минуты
```

### Добавить новые ссылки:

Просто добавьте строки в лист `partners` в Google Sheets!

## 📞 Поддержка

Если возникли вопросы:
1. Проверьте `ДЕПЛОЙ_БОТА_НА_CLOUDFLARE.md` для подробной инструкции
2. Проверьте README в папках `worker/` и `frontend/`
3. Откройте Issue в GitHub репозитории

## 📄 Лицензия

MIT License

---

**Сделано с ❤️ для Telegram сообщества**

**⭐ Если проект был полезен, поставьте звезду на GitHub!**
