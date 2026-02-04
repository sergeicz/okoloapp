# ⚡ Quick Start Guide (15 минут)

> Минимальная инструкция для быстрого запуска проекта

## 📋 Чеклист перед началом

Подготовьте:
- [ ] Gmail аккаунт
- [ ] GitHub аккаунт
- [ ] Cloudflare аккаунт (бесплатный)
- [ ] Replit аккаунт (бесплатный)
- [ ] Telegram бот токен (получить у @BotFather)

---

## ⏱️ Шаг 1: Google Sheets (3 минуты)

### 1.1 Создайте таблицу
1. Откройте [sheets.google.com](https://sheets.google.com)
2. Создайте таблицу "Telegram Mini App"
3. Создайте 4 листа: `users`, `partners`, `admins`, `clicks`

### 1.2 Добавьте заголовки

**Лист users:**
```
telegram_id | username | first_name | date_added | subscribed
```

**Лист partners:** (добавьте тестовые данные)
```
title          | url                          | category
Google         | https://google.com           | Поисковики
Amazon         | https://amazon.com           | Магазины
```

**Лист admins:** (ваш Telegram username БЕЗ @)
```
username
your_username
```

**Лист clicks:**
```
telegram_id | url | timestamp
```

### 1.3 Service Account
1. [console.cloud.google.com](https://console.cloud.google.com) → Новый проект
2. APIs & Services → Enable APIs → Google Sheets API (включить)
3. Credentials → Create → Service Account → Создать
4. Keys → Add Key → JSON → Скачать
5. Откройте JSON, скопируйте `client_email`
6. В Google Sheets: Share → вставьте email → Editor → Share

✅ Сохраните: `credentials.json`, `SHEET_ID` из URL таблицы

---

## ⏱️ Шаг 2: Cloudflare Worker (3 минуты)

```bash
# В папке worker
cd worker
npm install
npx wrangler login  # Войдите в браузере

# Добавьте секреты
npx wrangler secret put BOT_TOKEN
# Вставьте: ваш_токен_от_BotFather

npx wrangler secret put SHEET_ID
# Вставьте: ID_из_URL_Google_Sheets

npx wrangler secret put CREDENTIALS_JSON
# Вставьте: содержимое_credentials.json_в_одну_строку
# Используйте: https://jsonformatter.org/json-minify

# Деплой
npm run deploy
```

✅ Сохраните полученный URL (например: `https://telegram-miniapp-api.xxx.workers.dev`)

---

## ⏱️ Шаг 3: GitHub Pages (3 минуты)

### 3.1 Обновите конфигурацию
В файле `frontend/index.html` найдите:
```javascript
const CONFIG = {
  API_URL: 'https://your-worker.your-domain.workers.dev',
};
```

Замените на ваш URL из Шага 2.

### 3.2 Загрузите на GitHub
```bash
git init
git add .
git commit -m "Initial: Telegram Mini App"

# Создайте репозиторий на github.com (New repository)
# Затем:
git remote add origin https://github.com/ВАШ_USERNAME/telegram-miniapp.git
git branch -M main
git push -u origin main
```

### 3.3 Включите Pages
1. Repo → Settings → Pages
2. Source: Deploy from branch
3. Branch: main, folder: / (root)
4. Save

✅ Сохраните URL (например: `https://username.github.io/telegram-miniapp/frontend/`)

---

## ⏱️ Шаг 4: Replit Bot (3 минуты)

1. [replit.com](https://replit.com) → + Create Repl → Python
2. Назовите: `telegram-bot`
3. Удалите `main.py`
4. Загрузите файлы из папки `bot/`:
   - `bot.py`
   - `requirements.txt`

5. Добавьте Secrets (🔒 слева):

```
BOT_TOKEN = ваш_токен_от_BotFather
SHEET_ID = ID_из_Google_Sheets
WEBAPP_URL = https://username.github.io/telegram-miniapp/frontend/
```

```
CREDENTIALS_JSON = {весь JSON из credentials.json}
```

6. В Shell (внизу):
```bash
pip install -r requirements.txt
```

7. Нажмите **Run** ▶️

✅ Бот должен написать: "Бот успешно инициализирован"

---

## ⏱️ Шаг 5: Настройка Telegram (3 минуты)

### 5.1 BotFather
1. Откройте [@BotFather](https://t.me/BotFather) в Telegram
2. `/mybots` → Выберите вашего бота
3. `Bot Settings` → `Menu Button` → `Configure menu button`
4. URL: `https://username.github.io/telegram-miniapp/frontend/`
5. Text: `🚀 Открыть приложение`

### 5.2 Тест
1. Найдите вашего бота в Telegram
2. `/start`
3. Нажмите кнопку "🚀 Открыть приложение"
4. Должно открыться приложение с ссылками Google и Amazon

### 5.3 Админка
1. В приложении должна появиться кнопка "Админка" (вы в списке admins)
2. Нажмите → Увидите статистику и список пользователей

---

## ⏱️ Шаг 6: Держим бота онлайн 24/7 (2 минуты)

Бесплатный Replit засыпает. Используйте UptimeRobot:

1. [uptimerobot.com](https://uptimerobot.com) → Sign Up (бесплатно)
2. Add New Monitor:
   - Type: `HTTP(s)`
   - Name: `Telegram Bot`
   - URL: `https://telegram-miniapp-bot.YOUR_USERNAME.repl.co`
   - Interval: `5 minutes`
3. Create Monitor

✅ Готово! Бот будет онлайн 24/7

---

## ✅ Проверка

Все должно работать:
- ✅ Бот отвечает на `/start`
- ✅ Mini App открывается
- ✅ Ссылки отображаются (Google, Amazon)
- ✅ Кнопка "Админка" видна
- ✅ В админке показывается статистика
- ✅ При клике на ссылку она открывается

---

## 🔥 Быстрые команды

### Обновить Frontend
```bash
# Измените frontend/index.html
git add .
git commit -m "Update frontend"
git push
# Подождите 1-2 минуты
```

### Обновить Worker
```bash
cd worker
# Измените index.js
npm run deploy
```

### Обновить Bot
1. Остановите (Stop) в Replit
2. Измените `bot.py`
3. Запустите (Run)

---

## 🐛 Не работает?

### Frontend не загружается
```bash
# Проверьте что Pages включен:
# GitHub Repo → Settings → Pages → Source должен быть "main"

# Проверьте URL в браузере:
https://ВАШ_USERNAME.github.io/telegram-miniapp/frontend/
```

### API ошибки
```bash
# Проверьте Worker в браузере:
https://ваш-worker.workers.dev/api/health
# Должен вернуть: {"status":"ok",...}

# Проверьте API_URL в frontend/index.html
```

### Бот не отвечает
```bash
# Откройте Repl URL в браузере (разбудит бот)
https://telegram-miniapp-bot.YOUR_USERNAME.repl.co

# Проверьте логи в Replit Console
```

### Админка не видна
```bash
# Проверьте лист "admins" в Google Sheets
# Убедитесь что ваш username БЕЗ символа @
```

---

## 📚 Дальше

- **Добавьте свои ссылки** в лист `partners`
- **Настройте дизайн** в `frontend/index.html`
- **Добавьте админов** в лист `admins`
- **Тестируйте рассылку** через админ-панель

Полная документация: [DEPLOYMENT.md](DEPLOYMENT.md)

---

**🎉 Готово! Ваше Telegram Mini App работает!**

**⭐ Полезно? Поставьте звезду на GitHub!**
