#!/bin/bash
################################################################################
# WAZUH DETECTION LAB — STEP 2: MANAGER INSTALLATION
# Run this ON the manager EC2 instance (after SSH-ing in), not on your laptop.
# Installs: Wazuh Manager + Elasticsearch + Kibana + Wazuh Kibana plugin
# Run time: ~15-20 minutes
################################################################################

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}================================${NC}"
echo -e "${YELLOW} WAZUH MANAGER INSTALLATION${NC}"
echo -e "${YELLOW}================================${NC}"

# ---- SYSTEM PREP ----
echo -e "${YELLOW}[*] Updating system...${NC}"
sudo apt update -y
sudo apt install -y curl wget gnupg lsb-release apt-transport-https software-properties-common

# ---- WAZUH MANAGER ----
echo -e "${YELLOW}[*] Adding Wazuh repository...${NC}"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

echo -e "${YELLOW}[*] Installing Wazuh manager...${NC}"
sudo apt update -y
sudo apt install -y wazuh-manager

sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
echo -e "${GREEN}[OK] Wazuh manager installed and started${NC}"

# ---- ELASTICSEARCH (Wazuh's compatible build) ----
echo -e "${YELLOW}[*] Installing Wazuh indexer (Elasticsearch-compatible)...${NC}"
sudo apt install -y wazuh-indexer
sudo systemctl daemon-reload
sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer
echo -e "${GREEN}[OK] Wazuh indexer installed and started${NC}"

# ---- WAZUH DASHBOARD (Kibana-based) ----
echo -e "${YELLOW}[*] Installing Wazuh dashboard...${NC}"
sudo apt install -y wazuh-dashboard
sudo systemctl daemon-reload
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
echo -e "${GREEN}[OK] Wazuh dashboard installed and started${NC}"

# ---- VERIFY ----
echo -e "${YELLOW}[*] Verifying services...${NC}"
sleep 15
sudo systemctl status wazuh-manager --no-pager | head -5
sudo systemctl status wazuh-indexer --no-pager | head -5
sudo systemctl status wazuh-dashboard --no-pager | head -5

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN} MANAGER INSTALLATION COMPLETE${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Access the Wazuh dashboard at:"
echo "  https://<manager-public-ip>"
echo ""
echo "Default login: admin / (check /etc/wazuh-indexer/internal_users.yml or the install output above for generated password)"
echo ""
echo "Next: run 02-install-agent-ubuntu.sh on your Ubuntu endpoint,"
echo "      and 02-install-agent-windows.ps1 on your Windows Server endpoint."
