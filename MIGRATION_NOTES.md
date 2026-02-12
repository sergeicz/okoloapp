# Migration from Cloudflare Worker to Express Server

## ✅ Completed Migrations in server.js

### 1. **Core Infrastructure**
- ✅ Express.js server setup with CORS
- ✅ Redis connection for KV storage replacement
- ✅ Environment variables via dotenv
- ✅ Global `env` object for compatibility

### 2. **Redis Adapter**
All Cloudflare KV operations have been migrated to Redis:
- `env.BROADCAST_STATE.get(key)` → `redis.get(key)`
- `env.BROADCAST_STATE.put(key, value, {expirationTtl})` → `redis.setex(key, ttl, value)`
- `env.BROADCAST_STATE.delete(key)` → `redis.del(key)`
- `env.BROADCAST_STATE.list({prefix})` → `redis.keys(prefix + '*')`

### 3. **Google Sheets API Functions** ✅
All functions migrated with Node.js crypto instead of Web Crypto API:
- `getAccessToken()` - with Redis caching
- `createJWT()` - using Node.js crypto.sign()
- `getSheetData()`
- `appendSheetRow()`
- `updateSheetRow()`
- `getSheetIdByName()`
- `getAllSheetNames()`
- `deleteSheetRow()`
- `checkUserActive()`

### 4. **Utility Functions** ✅
- `checkRateLimit()` - with Redis
- `validateCredentials()`
- `getCachedAdmins()` - with Redis caching
- `getCachedPartners()` - with Redis caching
- `invalidateCache()`
- `checkAdmin()`
- `checkRepresentative()`
- `getBroadcastState()` - with Redis
- `saveBroadcastState()` - with Redis
- `deleteBroadcastState()` - with Redis

### 5. **Cron Job Functions** ✅
- `deleteOldPromocodes()` - migrated to use Redis
- `checkAllUsers()` - user activity checking
- `sendWeeklyPartnerReports()` - weekly reports to partners
- `sendMonthlyPartnerReports()` - monthly reports to partners

### 6. **Cron Schedules** ✅
Using node-cron:
- `*/5 * * * *` - Every 5 minutes: user checks + promocode cleanup
- `0 10 * * 1` - Monday 10:00 UTC: weekly partner reports
- `0 12 1 * *` - 1st of month 12:00 UTC: monthly partner reports

### 7. **API Endpoints** ✅
All migrated to Express routes:
- `GET /api/health` - Health check with Redis status
- `GET /api/partners` - Get partner list
- `POST /api/click` - Track partner clicks (with promocode sending)
- `POST /api/user` - Register/update user
- `POST /api/me` - Check admin status
- `GET /api/subscribers` - Get subscriber count

### 8. **Bot Webhook** ✅
- `POST /bot{token}` - Telegram webhook using grammy's Express adapter

### 9. **Redirect Handler** ✅
- `GET /r/:broadcastId/*` - Click tracking and redirect

## ⚠️ INCOMPLETE: Bot Handlers

### What's Missing
The `setupBot()` function in server.js is currently a **placeholder**. You need to copy ALL bot command and callback handlers from `worker/index.js` (lines 461-2006).

### Bot Handlers That Need to Be Added
From `worker/index.js`, copy these sections into `setupBot()`:

#### Commands:
- `bot.command('start')` - Line 461

#### Callback Queries:
- `bot.callbackQuery('admin_panel')` - Line 566
- `bot.callbackQuery('admin_stats')` - Line 589
- `bot.callbackQuery('admin_broadcasts_stats')` - Line 613
- `bot.callbackQuery(/^broadcast_detail_(.+)$/)` - Line 685
- `bot.callbackQuery('admin_broadcast')` - Line 766
- `bot.callbackQuery('broadcast_skip_partner')` - Line 803
- `bot.callbackQuery(/^broadcast_partner_(\d+)$/)` - Line 821
- `bot.callbackQuery('broadcast_skip_subtitle')` - Line 851
- `bot.callbackQuery('broadcast_skip_image')` - Line 870
- `bot.callbackQuery('broadcast_skip_button')` - Line 889
- `bot.callbackQuery('broadcast_confirm')` - Line 898
- `bot.callbackQuery('broadcast_cancel')` - Line 907
- `bot.callbackQuery('admin_users')` - Line 917
- `bot.callbackQuery(/^admin_users_by_activity(?:_page_(\d+))?$/)` - Line 938
- `bot.callbackQuery(/^admin_users_by_registration(?:_page_(\d+))?$/)` - Line 1044
- `bot.callbackQuery('admin_users_stats')` - Line 1151
- `bot.callbackQuery('noop')` - Line 1230
- `bot.callbackQuery('admin_partner_reports')` - Line 1239
- `bot.callbackQuery(/^admin_partner_select_(\d+)$/)` - Line 1280
- `bot.callbackQuery(/^admin_partner_period_(\d+)_(week|month|all)$/)` - Line 1318
- `bot.callbackQuery('back_to_start')` - Line 1468
- `bot.callbackQuery('representative_cabinet')` - Line 1500
- `bot.callbackQuery('rep_weekly_report')` - Line 1529
- `bot.callbackQuery('rep_monthly_report')` - Line 1607
- `bot.callbackQuery('rep_broadcasts_stats')` - Line 1704

#### Message Handlers:
- `bot.on('message:text')` - Line 1798
- `bot.on('message:photo')` - Line 1905
- `bot.on('message:video')` - Line 1931
- `bot.on('message:voice')` - Line 1956
- `bot.on('message:video_note')` - Line 1981

### Helper Functions for Broadcasts
These functions need to be added (they're in worker/index.js):
- `showBroadcastPreview()` - Line 2012
- `sendBroadcastToUser()` - Line 2079
- `executeBroadcast()` - Line 2118

## 📝 How to Complete the Migration

### Step 1: Copy Bot Handlers
1. Open `worker/index.js`
2. Copy lines 461-2387 (all bot handlers and helper functions)
3. Paste into `server.js` inside the `setupBot()` function

### Step 2: Copy Helper Functions
Add these helper functions before `setupBot()`:
- `showBroadcastPreview()`
- `sendBroadcastToUser()`
- `executeBroadcast()`

### Step 3: Update Tracked URL
In `executeBroadcast()` function, change the tracked URL from:
```javascript
const trackedUrl = `https://telegram-miniapp-api.worknotdead.workers.dev/r/${state.broadcast_id}/${encodedPartnerUrl}`;
```
to:
```javascript
const trackedUrl = `${process.env.SERVER_URL || 'http://localhost:3000'}/r/${state.broadcast_id}/${encodedPartnerUrl}`;
```

### Step 4: Environment Variables
Create `.env` file with:
```env
# Bot Configuration
BOT_TOKEN=your_bot_token_here
WEBAPP_URL=your_webapp_url_here

# Google Sheets
SHEET_ID=your_sheet_id_here
CREDENTIALS_JSON={"type":"service_account",...}

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Server Configuration
PORT=3000
SERVER_URL=http://localhost:3000
```

### Step 5: Install Dependencies
```bash
npm install express cors dotenv ioredis node-cron grammy
```

### Step 6: Run Server
```bash
node server.js
```

## 🔧 Key Differences from Worker

### 1. Crypto API
- **Worker**: Uses Web Crypto API (`crypto.subtle`)
- **Express**: Uses Node.js crypto module (`crypto.createPrivateKey`, `crypto.sign`)

### 2. Base64 Encoding
- **Worker**: Uses `btoa()` and custom base64 conversion
- **Express**: Uses `Buffer.from().toString('base64url')`

### 3. Webhook Adapter
- **Worker**: `webhookCallback(bot, 'cloudflare-mod')`
- **Express**: `webhookCallback(bot, 'express')`

### 4. Response Handling
- **Worker**: Returns `new Response()`
- **Express**: Uses `res.json()`, `res.send()`, `res.redirect()`

### 5. Storage
- **Worker**: Cloudflare KV via `env.BROADCAST_STATE`
- **Express**: Redis via ioredis

## 📊 File Structure

```
telegram-miniapp v1.1/
├── server.js                 # Express server (INCOMPLETE - needs bot handlers)
├── worker/
│   └── index.js             # Original Cloudflare Worker (COMPLETE)
├── .env                      # Environment variables (create this)
├── package.json             # Dependencies
└── MIGRATION_NOTES.md       # This file
```

## ✅ Testing Checklist

After completing the bot handlers:

- [ ] Bot /start command works
- [ ] Admin panel accessible for admins
- [ ] Partner cabinet accessible for representatives
- [ ] Broadcast creation flow works
- [ ] Broadcast sending works
- [ ] Click tracking works
- [ ] Promocode auto-send works
- [ ] Promocode auto-delete works (after 24h)
- [ ] User activity check cron works
- [ ] Weekly/monthly reports work
- [ ] All API endpoints respond correctly
- [ ] Redis connection is stable
- [ ] Google Sheets integration works

## 🚀 Production Deployment

1. Set up Redis server (Redis Cloud, AWS ElastiCache, etc.)
2. Update `.env` with production values
3. Set `SERVER_URL` to your production domain
4. Configure webhook: `https://api.telegram.org/bot{TOKEN}/setWebhook?url={SERVER_URL}/bot{TOKEN}`
5. Deploy to server (PM2, Docker, etc.)
6. Monitor logs and cron jobs

## 🐛 Known Issues

1. **Bot handlers not included**: The server.js file has a placeholder `setupBot()` function. All bot command handlers must be copied from worker/index.js.

2. **Tracked URL**: The broadcast tracking URL in `executeBroadcast()` is hardcoded to the Cloudflare Worker domain. Update it to use `process.env.SERVER_URL`.

3. **File size**: The complete migration results in a very large file (~3000+ lines). Consider splitting into modules for better maintainability.

## 📚 Suggested Improvements

After completing the migration, consider:

1. **Modularization**: Split into separate files:
   - `routes/api.js` - API routes
   - `routes/bot.js` - Bot handlers
   - `services/sheets.js` - Google Sheets functions
   - `services/cache.js` - Redis/caching functions
   - `cron/jobs.js` - Cron job definitions

2. **Error Handling**: Add global error handlers and logging service

3. **Monitoring**: Add health checks, metrics, and alerting

4. **Rate Limiting**: Add express-rate-limit for API endpoints

5. **Documentation**: Add JSDoc comments for all functions
