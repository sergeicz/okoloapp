import json
import gspread
import os
import logging
from google.oauth2.service_account import Credentials
from aiogram import Bot, Dispatcher, types
from aiogram.utils.exceptions import BotBlocked, ChatNotFound, TelegramAPIError, RetryAfter
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, WebAppInfo
import asyncio
from functools import wraps

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Чтение конфигурации с обработкой ошибок
def load_config():
    """Загрузка конфигурации из файлов или переменных окружения"""
    try:
        # Пытаемся загрузить из переменных окружения (для Replit)
        if os.getenv('CREDENTIALS_JSON'):
            creds_dict = json.loads(os.getenv('CREDENTIALS_JSON'))
        else:
            with open("credentials.json") as f:
                creds_dict = json.load(f)
        
        bot_token = os.getenv('BOT_TOKEN') or open("bot_token.txt").read().strip()
        sheet_id = os.getenv('SHEET_ID') or open("sheet_id.txt").read().strip()
        webapp_url = os.getenv('WEBAPP_URL', 'https://yourusername.github.io/telegram-miniapp')
        
        return creds_dict, bot_token, sheet_id, webapp_url
    except FileNotFoundError as e:
        logger.error(f"Файл конфигурации не найден: {e}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка парсинга JSON: {e}")
        raise
    except Exception as e:
        logger.error(f"Ошибка загрузки конфигурации: {e}")
        raise

# Инициализация
try:
    creds_dict, BOT_TOKEN, SHEET_ID, WEBAPP_URL = load_config()
    creds = Credentials.from_service_account_info(
        creds_dict, 
        scopes=["https://www.googleapis.com/auth/spreadsheets"]
    )
    gc = gspread.authorize(creds)
    sheet = gc.open_by_key(SHEET_ID)
    users_sheet = sheet.worksheet("users")
    
    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher(bot)
    logger.info("Бот успешно инициализирован")
except Exception as e:
    logger.critical(f"Критическая ошибка инициализации: {e}")
    raise

# Декоратор для повторных попыток
def retry_on_rate_limit(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                return await func(*args, **kwargs)
            except RetryAfter as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Rate limit, ожидание {e.timeout}с")
                    await asyncio.sleep(e.timeout)
                else:
                    raise
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Попытка {attempt + 1} провалилась: {e}")
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise
    return wrapper

# Команда /start
@dp.message_handler(commands=['start'])
async def cmd_start(message: types.Message):
    """Обработчик команды /start"""
    try:
        keyboard = InlineKeyboardMarkup()
        keyboard.add(InlineKeyboardButton(
            "🚀 Открыть приложение",
            web_app=WebAppInfo(url=WEBAPP_URL)
        ))
        
        welcome_text = (
            f"👋 Привет, {message.from_user.first_name}!\n\n"
            "Добро пожаловать в наш сервис партнерских ссылок.\n"
            "Нажмите кнопку ниже, чтобы открыть приложение."
        )
        
        await message.answer(welcome_text, reply_markup=keyboard)
        logger.info(f"Пользователь {message.from_user.id} запустил бота")
    except Exception as e:
        logger.error(f"Ошибка в cmd_start: {e}")
        await message.answer("Произошла ошибка. Попробуйте позже.")

# Команда /help
@dp.message_handler(commands=['help'])
async def cmd_help(message: types.Message):
    """Обработчик команды /help"""
    try:
        help_text = (
            "📖 *Помощь*\n\n"
            "Доступные команды:\n"
            "/start - Запустить бота и открыть приложение\n"
            "/help - Показать это сообщение\n\n"
            "Для доступа к партнерским ссылкам используйте приложение."
        )
        await message.answer(help_text, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Ошибка в cmd_help: {e}")

# Функция отправки пушей
@retry_on_rate_limit
async def send_push(message_text, link, title="Новое уведомление"):
    """Рассылка пушей подписанным пользователям"""
    logger.info(f"Начало рассылки: '{title}'")
    success_count = 0
    error_count = 0
    blocked_count = 0
    
    try:
        rows = users_sheet.get_all_records()
        logger.info(f"Найдено пользователей: {len(rows)}")
        
        for i, user in enumerate(rows, start=2):
            if str(user.get('subscribed', 'TRUE')).upper() != 'TRUE':
                continue
            
            try:
                telegram_id = user.get('telegram_id')
                if not telegram_id:
                    logger.warning(f"Пропуск строки {i}: нет telegram_id")
                    continue
                
                keyboard = InlineKeyboardMarkup()
                keyboard.add(InlineKeyboardButton("Перейти", url=link))
                
                full_message = f"*{title}*\n\n{message_text}"
                
                await bot.send_message(
                    telegram_id,
                    full_message,
                    reply_markup=keyboard,
                    parse_mode='Markdown'
                )
                success_count += 1
                
                # Задержка между сообщениями (защита от rate limit)
                await asyncio.sleep(0.05)
                
            except (BotBlocked, ChatNotFound) as e:
                logger.warning(f"Пользователь {telegram_id} заблокировал бота или не найден")
                try:
                    users_sheet.update_cell(i, 5, 'FALSE')
                    blocked_count += 1
                except Exception as sheet_error:
                    logger.error(f"Ошибка обновления таблицы: {sheet_error}")
                    
            except RetryAfter as e:
                logger.warning(f"Rate limit для {telegram_id}, ожидание {e.timeout}с")
                await asyncio.sleep(e.timeout)
                error_count += 1
                
            except TelegramAPIError as e:
                logger.error(f"Telegram API ошибка для {telegram_id}: {e}")
                error_count += 1
                
            except Exception as e:
                logger.error(f"Неизвестная ошибка для {telegram_id}: {e}")
                error_count += 1
        
        logger.info(
            f"Рассылка завершена. Успешно: {success_count}, "
            f"Ошибки: {error_count}, Заблокировали: {blocked_count}"
        )
        return {"success": success_count, "errors": error_count, "blocked": blocked_count}
        
    except Exception as e:
        logger.error(f"Критическая ошибка при рассылке: {e}")
        raise

# Обработчик ошибок
@dp.errors_handler()
async def errors_handler(update, exception):
    """Глобальный обработчик ошибок"""
    logger.error(f"Ошибка при обработке обновления {update}: {exception}", exc_info=True)
    return True

# Запуск бота
async def on_startup(dp):
    """Действия при запуске бота"""
    logger.info("Бот запущен и готов к работе")

async def on_shutdown(dp):
    """Действия при остановке бота"""
    logger.info("Бот остановлен")
    await bot.close()

if __name__ == "__main__":
    from aiogram import executor
    try:
        executor.start_polling(
            dp,
            on_startup=on_startup,
            on_shutdown=on_shutdown,
            skip_updates=True
        )
    except Exception as e:
        logger.critical(f"Критическая ошибка: {e}", exc_info=True)
