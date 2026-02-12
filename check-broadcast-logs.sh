#!/bin/bash
# Check logs for broadcast BR_1770891862501

echo "Checking logs for broadcast BR_1770891862501..."
echo ""

ssh root@46.17.44.239 << 'ENDSSH'
cd /opt/telegram-miniapp
echo "=== Searching for broadcast BR_1770891862501 ==="
docker compose logs app --tail=500 | grep -A 10 -B 5 "BR_1770891862501"
echo ""
echo "=== Searching for broadcast save errors ==="
docker compose logs app --tail=500 | grep -i "сохран\|broadcast\|error" | tail -30
ENDSSH
