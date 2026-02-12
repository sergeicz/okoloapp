# Express Server Migration - Complete Guide

## 📁 What Has Been Created

### 1. `server.js` - Express Server (90% Complete)
A fully functional Express.js server with:

#### ✅ Completed Infrastructure:
- Express app with CORS and JSON parsing
- Redis connection for KV storage replacement
- Environment variables via dotenv
- Global `env` object wrapper for compatibility
- All Google Sheets API functions (with Node.js crypto)
- All caching and admin check functions
- All cron job helper functions (user checks, promocode cleanup, reports)
- All API endpoints (health, partners, click, user, me, subscribers)
- Bot webhook endpoint
- Click tracking and redirect endpoint
- 3 cron schedules configured
- Graceful shutdown handlers

#### ⚠️ Missing Bot Handlers:
The `setupBot()` function is currently a placeholder with only:
- Error handler
- Middleware for admin checks

**You need to copy all bot command/callback/message handlers from `worker/index.js`**

---

## 🚀 Quick Start Guide

### Step 1: Copy Bot Handlers

Open `worker/index.js` and copy **lines 461-2005** (all the bot handlers).

Paste them into `server.js` inside the `setupBot(env)` function, replacing the placeholder comment.

The handlers you need to copy include:

**Commands:**
- `/start` command

**Callback Queries:** (20+ handlers)
- Admin panel
- Statistics
- Broadcast creation and management
- User management
- Partner reports
- Representative cabinet

**Message Handlers:**
- Text messages (for broadcast creation flow)
- Photo messages
- Video messages
- Voice messages
- Video note messages

### Step 2: Copy Helper Functions

Copy these 3 functions from `worker/index.js` and add them BEFORE the `setupBot()` function in `server.js`:

1. `showBroadcastPreview()` (line ~2012)
2. `sendBroadcastToUser()` (line ~2079)
3. `executeBroadcast()` (line ~2118)

### Step 3: Fix Tracked URL

In the `executeBroadcast()` function you just copied, find this line:
```javascript
const trackedUrl = `https://telegram-miniapp-api.worknotdead.workers.dev/r/${state.broadcast_id}/${encodedPartnerUrl}`;
```

Replace it with:
```javascript
const trackedUrl = `${process.env.SERVER_URL || 'http://localhost:3000'}/r/${state.broadcast_id}/${encodedPartnerUrl}`;
```

### Step 4: Create .env File

Create `.env` in the project root:

```env
# Telegram Bot
BOT_TOKEN=your_bot_token_from_botfather
WEBAPP_URL=https://your-webapp-url.com

# Google Sheets
SHEET_ID=your_google_sheet_id
CREDENTIALS_JSON={"type":"service_account","project_id":"..."}

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Server
PORT=3000
SERVER_URL=http://localhost:3000
```

### Step 5: Install Dependencies

```bash
npm install express cors dotenv ioredis node-cron grammy
```

### Step 6: Start Redis

**Option A - Docker:**
```bash
docker run -d --name redis -p 6379:6379 redis:alpine
```

**Option B - Local Install:**
- Windows: Download from https://github.com/microsoftarchive/redis/releases
- Mac: `brew install redis && brew services start redis`
- Linux: `sudo apt-get install redis-server && sudo systemctl start redis`

### Step 7: Run Server

```bash
node server.js
```

You should see:
```
[Redis] ✅ Connected to Redis
═══════════════════════════════════════════════════════════════
🚀 Express Server Started
═══════════════════════════════════════════════════════════════
📡 Server listening on port 3000
🤖 Bot webhook: http://localhost:3000/bot<TOKEN>
🔗 API available at: http://localhost:3000/api/*
📊 Health check: http://localhost:3000/api/health
═══════════════════════════════════════════════════════════════
```

### Step 8: Set Webhook

```bash
curl "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=http://localhost:3000/bot<YOUR_BOT_TOKEN>"
```

For production, use your public domain:
```bash
curl "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=https://yourdomain.com/bot<YOUR_BOT_TOKEN>"
```

---

## 🧪 Testing

### Test API Endpoints

```bash
# Health check
curl http://localhost:3000/api/health

# Get partners
curl http://localhost:3000/api/partners

# Get subscribers
curl http://localhost:3000/api/subscribers
```

### Test Bot

1. Open Telegram
2. Find your bot
3. Send `/start`
4. If admin, you should see admin panel button
5. Try creating a broadcast
6. Check if cron jobs are running (check logs)

---

## 📊 Architecture Comparison

### Cloudflare Worker (Old)
```
Request → Worker → KV Storage
                → Google Sheets
                → Telegram API

Cron Triggers → Scheduled Handler
```

### Express Server (New)
```
Request → Express Router → Redis
                         → Google Sheets
                         → Telegram API

node-cron → Scheduled Functions
```

---

## 🔄 Key Differences

### 1. Storage
- **Before:** Cloudflare KV (key-value storage)
- **After:** Redis (in-memory data store)
- **Migration:** All KV calls replaced with Redis equivalents

### 2. Crypto
- **Before:** Web Crypto API (`crypto.subtle`)
- **After:** Node.js crypto (`crypto.sign`)
- **Migration:** JWT signing rewritten for Node.js

### 3. Base64
- **Before:** `btoa()` + custom Uint8Array conversion
- **After:** `Buffer.from().toString('base64url')`
- **Migration:** All base64 encoding updated

### 4. Webhook
- **Before:** `webhookCallback(bot, 'cloudflare-mod')`
- **After:** `webhookCallback(bot, 'express')`
- **Migration:** Changed adapter type

### 5. Responses
- **Before:** `new Response(JSON.stringify(data), { status, headers })`
- **After:** `res.status(status).json(data)`
- **Migration:** Express response methods

### 6. Cron
- **Before:** Cloudflare Cron Triggers in wrangler.toml
- **After:** node-cron schedules in code
- **Migration:** 3 cron jobs configured

---

## 📝 Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `BOT_TOKEN` | Telegram bot token | ✅ Yes |
| `WEBAPP_URL` | Your Mini App URL | ✅ Yes |
| `SHEET_ID` | Google Sheets spreadsheet ID | ✅ Yes |
| `CREDENTIALS_JSON` | Service account credentials (JSON string) | ✅ Yes |
| `REDIS_HOST` | Redis server host | Optional (default: localhost) |
| `REDIS_PORT` | Redis server port | Optional (default: 6379) |
| `REDIS_PASSWORD` | Redis password | Optional |
| `PORT` | Server port | Optional (default: 3000) |
| `SERVER_URL` | Public server URL for webhooks | Optional (default: http://localhost:3000) |

---

## 🐛 Troubleshooting

### Redis Connection Failed
```
[Redis] ❌ Error: connect ECONNREFUSED 127.0.0.1:6379
```
**Solution:** Start Redis server first

### Bot Not Responding
**Check:**
1. Webhook is set correctly: `curl https://api.telegram.org/bot<TOKEN>/getWebhookInfo`
2. Server is accessible from internet (use ngrok for local testing)
3. Bot handlers are copied into `setupBot()`

### Google Sheets Error
```
Failed to get Google access token
```
**Solution:** Check `CREDENTIALS_JSON` format and permissions

### Cron Jobs Not Running
**Check:**
1. Server is running continuously
2. Check console for cron execution logs: `[CRON] ⏰ Running 5-minute tasks`
3. Verify cron schedule syntax

---

## 🚀 Production Deployment

### 1. Prepare Environment

```bash
# Install PM2 for process management
npm install -g pm2

# Create production .env
cp .env .env.production
# Edit .env.production with production values
```

### 2. Set Up Redis

**Option A - Redis Cloud (Free Tier):**
1. Sign up at https://redis.com/try-free/
2. Create database
3. Get connection details
4. Update `.env` with host/port/password

**Option B - AWS ElastiCache:**
1. Create Redis cluster
2. Get endpoint
3. Update `.env`

**Option C - Docker Compose:**
```yaml
version: '3.8'
services:
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

### 3. Start with PM2

```bash
# Start server
pm2 start server.js --name telegram-bot

# Save PM2 config
pm2 save

# Setup auto-restart on system reboot
pm2 startup
```

### 4. Set Production Webhook

```bash
curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://yourdomain.com/bot<TOKEN>"
```

### 5. Monitor

```bash
# View logs
pm2 logs telegram-bot

# Monitor processes
pm2 monit

# View status
pm2 status
```

---

## 📊 Monitoring & Logs

### Important Log Patterns

**Successful Startup:**
```
[Redis] ✅ Connected to Redis
🚀 Express Server Started
📡 Server listening on port 3000
```

**Cron Jobs:**
```
[CRON] ⏰ Running 5-minute tasks at: 2026-02-12T10:00:00Z
[CRON] 📊 Users check result: { success: true, checked: 150, inactive: 2 }
[CRON] 🗑️ Promocodes cleanup result: { success: true, deleted: 5 }
```

**API Requests:**
```
[2026-02-12T10:05:23.456Z] GET /api/partners
[2026-02-12T10:05:24.123Z] POST /api/click
```

**Errors to Watch:**
```
[Redis] ❌ Error: Connection lost
[BOT ERROR] Update 123456:
[CRON] ❌ Error in 5-minute tasks:
```

---

## 🎯 Next Steps After Migration

### 1. Testing
- [ ] Test all bot commands
- [ ] Test admin panel
- [ ] Test broadcast creation and sending
- [ ] Test click tracking
- [ ] Test API endpoints
- [ ] Test cron jobs
- [ ] Test error handling

### 2. Optimization
- [ ] Add request logging middleware
- [ ] Add rate limiting for API endpoints
- [ ] Set up Redis persistence
- [ ] Configure Redis eviction policies
- [ ] Add health check endpoint monitoring

### 3. Code Quality
- [ ] Split into modules (routes, services, utils)
- [ ] Add JSDoc comments
- [ ] Add unit tests
- [ ] Set up linting (ESLint)
- [ ] Add TypeScript (optional)

### 4. DevOps
- [ ] Set up CI/CD pipeline
- [ ] Configure log aggregation (e.g., Winston + Papertrail)
- [ ] Set up error tracking (e.g., Sentry)
- [ ] Configure monitoring (e.g., Prometheus + Grafana)
- [ ] Set up backups for Redis data

---

## 📚 Additional Resources

- **Grammy Documentation:** https://grammy.dev/
- **Express.js Guide:** https://expressjs.com/
- **Redis Documentation:** https://redis.io/docs/
- **node-cron:** https://github.com/node-cron/node-cron
- **PM2 Guide:** https://pm2.keymetrics.io/docs/

---

## ✅ Migration Checklist

- [ ] Copy bot handlers (lines 461-2005 from worker/index.js)
- [ ] Copy helper functions (showBroadcastPreview, sendBroadcastToUser, executeBroadcast)
- [ ] Fix tracked URL in executeBroadcast
- [ ] Create .env file with all variables
- [ ] Install dependencies
- [ ] Start Redis server
- [ ] Run server.js
- [ ] Set webhook
- [ ] Test /start command
- [ ] Test admin panel
- [ ] Test broadcasts
- [ ] Test API endpoints
- [ ] Verify cron jobs are running
- [ ] Deploy to production
- [ ] Monitor logs and errors

---

## 🎉 Success Indicators

You'll know the migration is successful when:

1. ✅ Server starts without errors
2. ✅ Redis connection is established
3. ✅ Bot responds to `/start`
4. ✅ Admin panel works
5. ✅ Broadcasts can be created and sent
6. ✅ Click tracking works
7. ✅ API endpoints respond correctly
8. ✅ Cron jobs execute on schedule
9. ✅ No errors in logs
10. ✅ All features from worker are working

---

**Need Help?** Check the logs first, then review this guide and MIGRATION_NOTES.md.
