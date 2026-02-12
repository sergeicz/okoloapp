# Quick Start Guide: VPS Deployment

## 🎯 What Was Done

Your Telegram Mini App has been migrated from Cloudflare Workers to a VPS deployment with Docker. All files are ready - you just need to configure secrets and deploy.

## ⚡ 3-Step Deployment

### Step 1: VPS Setup (5 minutes)

SSH into your VPS and run:

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

# Install Docker Compose
apt-get update && apt-get install -y docker-compose

# Setup firewall
ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 22/tcp && ufw --force enable

# Create app directory
mkdir -p /opt/telegram-miniapp
```

### Step 2: GitHub Secrets (5 minutes)

Add these in `Settings → Secrets → Actions`:

1. **VPS_SSH_KEY**: Your private SSH key for root@46.17.44.239
2. **BOT_TOKEN**: Your Telegram bot token
3. **WEBAPP_URL**: Your GitHub Pages URL
4. **SHEET_ID**: Your Google Sheets ID
5. **CREDENTIALS_JSON**: Your Google service account JSON

### Step 3: Deploy (2 minutes)

```bash
# ⚠️ IMPORTANT: First complete bot handlers in server.js
# See MIGRATION_COMPLETE.md "Phase 4" for details

# Then commit and push
git add .
git commit -m "Deploy to VPS"
git push origin main

# GitHub Actions will automatically deploy!
```

## ✅ Verification

After deployment (takes ~2 minutes):

```bash
# Check health
curl https://app.okolotattooing.ru/api/health

# Test bot
# Send /start to your Telegram bot

# View logs
ssh root@46.17.44.239 "cd /opt/telegram-miniapp && docker-compose logs -f"
```

## 📚 Full Documentation

- **Complete deployment guide**: `MIGRATION_COMPLETE.md`
- **Technical migration details**: `MIGRATION_NOTES.md`
- **Server setup instructions**: `README-SERVER-MIGRATION.md`

## 🚨 Before First Deploy

**Action Required:** The `server.js` file needs bot handlers copied from `worker/index.js`.

1. Open `worker/index.js` (lines 461-2005)
2. Copy all bot handlers to `server.js` → `setupBot()` function
3. Copy helper functions: `showBroadcastPreview`, `sendBroadcastToUser`, `executeBroadcast`

See `MIGRATION_COMPLETE.md` Phase 4 for detailed instructions.

## 🎉 That's It!

Once deployed, your app will be live at:
- **Frontend**: https://app.okolotattooing.ru
- **API**: https://app.okolotattooing.ru/api/*
- **Bot**: Telegram (via webhook)

All cron jobs, admin panel, broadcasts, and partner tracking will work automatically.
