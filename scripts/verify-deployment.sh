#!/bin/bash
# Deployment Verification Script

echo "═══════════════════════════════════════════════════════════════"
echo "🔍 Telegram Bot Deployment Verification"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="app.okolotattooing.ru"
BOT_TOKEN="${BOT_TOKEN:-}"

# Test 1: Health Check
echo "1️⃣  Testing Health Endpoint..."
if curl -f -s "https://${DOMAIN}/api/health" > /dev/null; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${RED}❌ Health check failed${NC}"
fi
echo ""

# Test 2: Bot Endpoint (POST)
echo "2️⃣  Testing Bot Webhook Endpoint (POST)..."
response=$(curl -s -X POST -w "\n%{http_code}" "https://${DOMAIN}/bot" -H "Content-Type: application/json" -d '{"test":"data"}')
http_code=$(echo "$response" | tail -n1)

if [ "$http_code" = "200" ] || [ "$http_code" = "401" ] || [ "$http_code" = "400" ]; then
    echo -e "${GREEN}✅ Endpoint accessible (HTTP $http_code)${NC}"
    echo "   (200/400/401 are expected - Telegram signature needed for real requests)"
else
    echo -e "${RED}❌ Endpoint not accessible (HTTP $http_code)${NC}"
fi
echo ""

# Test 3: Redis Port Check
echo "3️⃣  Checking Redis Port Security..."
if command -v ss &> /dev/null; then
    redis_ports=$(ss -tulpn 2>/dev/null | grep :6379 | grep -v 127.0.0.1 || true)
    if [ -z "$redis_ports" ]; then
        echo -e "${GREEN}✅ Redis port NOT exposed externally${NC}"
    else
        echo -e "${RED}❌ Redis port IS exposed - SECURITY RISK!${NC}"
        echo "$redis_ports"
    fi
else
    echo -e "${YELLOW}⚠️  'ss' command not available, skipping...${NC}"
fi
echo ""

# Test 4: SSL Certificate
echo "4️⃣  Checking SSL Certificate..."
if curl -s -I "https://${DOMAIN}" | grep -q "HTTP/2 200\|HTTP/1.1 200"; then
    echo -e "${GREEN}✅ SSL certificate valid${NC}"
else
    echo -e "${RED}❌ SSL certificate issue${NC}"
fi
echo ""

# Test 5: Webhook Status (if BOT_TOKEN provided)
if [ -n "$BOT_TOKEN" ]; then
    echo "5️⃣  Checking Telegram Webhook Status..."
    webhook_info=$(curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo")

    webhook_url=$(echo "$webhook_info" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
    pending_count=$(echo "$webhook_info" | grep -o '"pending_update_count":[0-9]*' | cut -d':' -f2)
    last_error=$(echo "$webhook_info" | grep -o '"last_error_message":"[^"]*"' | cut -d'"' -f4)

    echo "   Webhook URL: $webhook_url"
    echo "   Pending updates: $pending_count"

    if [ "$webhook_url" = "https://${DOMAIN}/bot" ]; then
        echo -e "${GREEN}✅ Webhook configured correctly${NC}"
    else
        echo -e "${RED}❌ Webhook URL mismatch${NC}"
        echo "   Expected: https://${DOMAIN}/bot"
        echo "   Current: $webhook_url"
    fi

    if [ -n "$last_error" ]; then
        echo -e "${YELLOW}⚠️  Last error: $last_error${NC}"
    fi
else
    echo "5️⃣  Skipping webhook check (BOT_TOKEN not provided)"
    echo "   Run: BOT_TOKEN=your_token ./scripts/verify-deployment.sh"
fi
echo ""

# Test 6: Container Status
echo "6️⃣  Checking Docker Containers..."
if command -v docker &> /dev/null; then
    if docker compose ps 2>/dev/null | grep -q "Up"; then
        echo -e "${GREEN}✅ Containers running${NC}"
        docker compose ps
    else
        echo -e "${RED}❌ Containers not running${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Docker not accessible locally${NC}"
    echo "   SSH to VPS and run: cd /opt/telegram-miniapp && docker compose ps"
fi
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo "✨ Verification Complete"
echo "═══════════════════════════════════════════════════════════════"
