#!/bin/bash
# Demo Script for Hackathon Presentation
# Run this during your live demo

echo "🍯 AI Honeypot - Live Demo"
echo "================================"
echo ""

# Get attacker ID (you'll need to replace this after first attack)
ATTACKER_ID="your_attacker_id_here"

echo "Step 1: Launching SQL Injection Attack..."
echo "Command: curl 'http://localhost:8000/search?q=' OR 1=1 UNION SELECT username,password FROM users--'"
echo ""
read -p "Press Enter to execute..."
curl "http://localhost:8000/search?q=' OR 1=1 UNION SELECT username,password FROM users--"
echo ""
echo "✅ Attack logged! Check dashboard at http://localhost:8000/demo"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "Step 2: Getting Attack Prediction..."
echo "Command: curl http://localhost:8000/api/prediction/$ATTACKER_ID"
echo ""
read -p "Press Enter to execute..."
curl http://localhost:8000/api/prediction/$ATTACKER_ID | jq
echo ""
echo "✅ Prediction shows next likely attack vectors!"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "Step 3: MITRE ATT&CK Mapping..."
echo "Command: curl http://localhost:8000/api/mitre/$ATTACKER_ID"
echo ""
read -p "Press Enter to execute..."
curl http://localhost:8000/api/mitre/$ATTACKER_ID | jq
echo ""
echo "✅ Mapped to MITRE framework with APT matching!"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "Step 4: Forensic Timeline..."
echo "Command: curl http://localhost:8000/api/timeline/$ATTACKER_ID/narrative"
echo ""
read -p "Press Enter to execute..."
curl http://localhost:8000/api/timeline/$ATTACKER_ID/narrative | jq
echo ""
echo "✅ Complete attack narrative generated!"
echo ""
read -p "Press Enter to continue..."

echo ""
echo "Step 5: Auto-Generated Incident Playbook..."
echo "Command: curl http://localhost:8000/api/playbook/SQL%20Injection"
echo ""
read -p "Press Enter to execute..."
curl http://localhost:8000/api/playbook/SQL%20Injection -o playbook.md
echo ""
echo "✅ Incident response playbook saved to playbook.md"
echo "Opening file..."
cat playbook.md
echo ""
read -p "Press Enter to continue..."

echo ""
echo "Step 6: Export Threat Intelligence..."
echo "Command: curl http://localhost:8000/api/threat-intel/$ATTACKER_ID/iocs"
echo ""
read -p "Press Enter to execute..."
curl http://localhost:8000/api/threat-intel/$ATTACKER_ID/iocs | jq
echo ""
echo "✅ IOCs generated for threat sharing!"
echo ""

echo ""
echo "================================"
echo "🎉 Demo Complete!"
echo "================================"
echo ""
echo "Key Takeaways:"
echo "✅ Real-time attack prediction"
echo "✅ MITRE ATT&CK mapping"
echo "✅ Auto-generated playbooks"
echo "✅ Complete forensic timeline"
echo "✅ Threat intelligence export"
echo ""
echo "Questions?"
