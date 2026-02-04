# Telegram Bot для Mini App

## Описание
Telegram бот для управления пользователями и рассылки push-уведомлений.

## Установка на Replit

### 1. Создайте новый Repl
- Зайдите на [replit.com](https://replit.com)
- Создайте новый Python Repl
- Загрузите файлы из папки `bot/`

### 2. Установите зависимости
```bash
pip install -r requirements.txt
```

### 3. Настройте переменные окружения (Secrets)
В разделе "Secrets" (🔒) добавьте:

**BOT_TOKEN**
```
your_telegram_bot_token_here
```

**SHEET_ID**
```
your_google_sheet_id_here
```

**CREDENTIALS_JSON**
```json
{
  "type": "service_account",
  "project_id": "your-project",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "your-service-account@your-project.iam.gserviceaccount.com",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "..."
}
```

**WEBAPP_URL** (опционально, если используете GitHub Pages)
```
https://yourusername.github.io/telegram-miniapp
```

### 4. Структура Google Sheets
Создайте Google таблицу с листами:
- **users** - колонки: `telegram_id`, `username`, `first_name`, `date_added`, `subscribed`
- **admins** - колонки: `username`
- **clicks** - колонки: `telegram_id`, `url`, `timestamp`
- **partners** - колонки: `title`, `url`, `category`

### 5. Настройте Google Service Account
1. Создайте проект в [Google Cloud Console](https://console.cloud.google.com)
2. Включите Google Sheets API
3. Создайте Service Account
4. Скачайте JSON ключ
5. Дайте доступ Service Account email к вашей Google таблице (Editor)

### 6. Запустите бота
Нажмите кнопку "Run" в Replit

### 7. Держите бота онлайн
Используйте сервис [UptimeRobot](https://uptimerobot.com) для пинга вашего Repl каждые 5 минут:
- URL для пинга: `https://your-repl-name.your-username.repl.co`

## Команды бота
- `/start` - Запустить бота и открыть Mini App
- `/help` - Показать справку

## Логи
Логи сохраняются в файл `bot.log`

## Возможные проблемы

### Repl засыпает
Используйте UptimeRobot для постоянного пинга

### Ошибка авторизации Google Sheets
Проверьте, что Service Account email добавлен в список редакторов таблицы

### Rate Limit от Telegram
Бот автоматически обрабатывает rate limits с задержками
