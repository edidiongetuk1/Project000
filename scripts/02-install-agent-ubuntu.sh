#!/bin/bash
################################################################################
# WAZUH DETECTION LAB — STEP 3: UBUNTU AGENT INSTALLATION
# Run this ON the Ubuntu endpoint EC2 instance (not the manager).
# Usage: sudo bash 02-install-agent-ubuntu.sh <MANAGER_PRIVATE_IP>
################################################################################

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

MANAGER_IP="${1:-10.0.1.10}"
AGENT_NAME="${2:-UBUNTU-TARGET-01}"

echo -e "${YELLOW}================================${NC}"
echo -e "${YELLOW} WAZUH AGENT — UBUNTU ENDPOINT${NC}"
echo -e "${YELLOW} Manager IP: $MANAGER_IP${NC}"
echo -e "${YELLOW} Agent Name: $AGENT_NAME${NC}"
echo -e "${YELLOW}================================${NC}"

echo -e "${YELLOW}[*] Adding Wazuh repository...${NC}"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

echo -e "${YELLOW}[*] Installing Wazuh agent...${NC}"
sudo apt update -y
sudo WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" apt install -y wazuh-agent

echo -e "${YELLOW}[*] Configuring agent...${NC}"
sudo sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_IP</address>|g" /var/ossec/etc/ossec.conf 2>/dev/null || true

echo -e "${YELLOW}[*] Installing auditd for enhanced syscall logging...${NC}"
sudo apt install -y auditd
sudo systemctl enable auditd
sudo systemctl start auditd

echo -e "${YELLOW}[*] Starting Wazuh agent...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

sleep 5
echo -e "${YELLOW}[*] Checking agent status...${NC}"
sudo systemctl status wazuh-agent --no-pager | head -8

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN} UBUNTU AGENT INSTALLED${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Verify from the manager with:"
echo "  sudo /var/ossec/bin/manage_agents -l"
echo ""
echo "Tail agent log for connection status:"
echo "  sudo tail -f /var/ossec/logs/ossec.log"
