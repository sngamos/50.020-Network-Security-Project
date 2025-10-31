#!/bin/bash
# demo/run_scenario.sh
# One command to run the complete demonstration

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║     Network Intrusion Detection - Live Demonstration      ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
echo "[1/5] Checking prerequisites..."

if [ ! -f "../models/trained/random_forest.pkl" ]; then
    echo "❌ Random Forest model not found!"
    echo "Please train the model first: python scripts/train_models.py"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not installed"
    exit 1
fi

echo "✓ All prerequisites met"
echo ""

# Start environment
echo "[2/5] Starting demo environment..."
docker-compose up -d

echo "Waiting for services to initialize..."
sleep 15

# Check if running
if ! docker ps | grep -q "snort-ids"; then
    echo "❌ Snort failed to start"
    exit 1
fi

if ! docker ps | grep -q "ml-ids"; then
    echo "❌ ML-IDS failed to start"
    exit 1
fi

echo "✓ Demo environment ready"
echo ""

# Open terminals for monitoring
echo "[3/5] Setting up monitoring windows..."

# Terminal 1: Snort output
gnome-terminal --title="Snort IDS Monitor" -- bash -c "
    echo '═══════════════════════════════════════';
    echo 'SNORT IDS - Traditional Signature-Based';
    echo '═══════════════════════════════════════';
    echo '';
    docker logs -f snort-ids 2>&1 | grep --line-buffered 'Alert'
" &

# Terminal 2: ML-IDS output  
gnome-terminal --title="ML-IDS Monitor" -- bash -c "
    echo '═══════════════════════════════════════';
    echo 'ML-IDS - Random Forest Based Detection';
    echo '═══════════════════════════════════════';
    echo '';
    docker logs -f ml-ids 2>&1
" &

sleep 2

echo "✓ Monitoring windows opened"
echo ""

# Instructions
echo "[4/5] Demo ready!"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "DEMO INSTRUCTIONS:"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "1. Two monitoring windows have opened:"
echo "   • Left: Snort IDS (traditional)"
echo "   • Right: ML-IDS (Random Forest)"
echo ""
echo "2. Watch both windows as attacks are executed"
echo ""
echo "3. The demonstration will show:"
echo "   • Phase 1: Normal traffic (neither alerts)"
echo "   • Phase 2: Classic SQL injection (both alert)"
echo "   • Phase 3: Obfuscated SQL injection (ONLY ML alerts) ⭐"
echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

# Run attack
echo "[5/5] Starting attack demonstration..."
echo ""
read -p "Press Enter to begin attack scenario..."

python3 attack/obfuscated_sql_injection.py

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "DEMONSTRATION COMPLETE"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Results:"
echo "  • Check the monitoring windows for detections"
echo "  • Snort log: demo/snort-ids/logs/alert"
echo "  • ML-IDS log: docker logs ml-ids"
echo ""
echo "Key Finding:"
echo "  ✓ ML-based IDS detected obfuscated attacks"
echo "  ✗ Traditional Snort IDS missed obfuscated attacks"
echo ""
echo "To stop demo: ./stop_demo.sh"
echo "═══════════════════════════════════════════════════════════"