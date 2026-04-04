#!/bin/bash
# ============================================================
# safe-shell demo: before vs after
#
# Shows the axios attack simulation running:
#   1. WITHOUT safe-shell (all 5 attacks succeed)
#   2. WITH safe-shell (all 5 attacks blocked)
#
# Uses FAKE credentials — completely safe to run.
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTACK_SCRIPT="$SCRIPT_DIR/axios-attack.sh"

export AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
export STRIPE_SECRET_KEY="sk_live_abcdefghijklmnopqrstuvwx"
export DATABASE_URL="postgres://admin:secret@prod.db.com/mydb"
export ANTHROPIC_API_KEY="sk-ant-api03-fakekey1234567890abcdefg"

echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │          safe-shell demo: axios attack simulation        │"
echo "  │          All credentials below are FAKE                  │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""

# --- BEFORE ---
echo "  ══════════════════════════════════════════════════════════"
echo "  BEFORE: Running WITHOUT safe-shell"
echo "  ══════════════════════════════════════════════════════════"
echo ""

HOME="/tmp/safe-shell-demo" bash "$ATTACK_SCRIPT"

echo ""
read -p "  Press Enter to see the same attack WITH safe-shell..." _

# --- AFTER ---
echo ""
echo "  ══════════════════════════════════════════════════════════"
echo "  AFTER: Running WITH safe-shell (npm profile)"
echo "  ══════════════════════════════════════════════════════════"
echo ""

safe-shell exec --profile npm "bash $ATTACK_SCRIPT > /dev/null 2>&1"
echo ""
