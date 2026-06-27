#!/bin/bash
################################################################################
# WAZUH DETECTION LAB — TEARDOWN SCRIPT
# Deletes all AWS resources created by 01-deploy-infrastructure.sh
# Run this when you're done for the day/week to avoid ongoing charges.
#
# Usage: bash cleanup.sh
# Reads variables from ~/wazuh-lab-inventory.txt
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INVENTORY="$HOME/wazuh-lab-inventory.txt"

if [ ! -f "$INVENTORY" ]; then
    echo -e "${RED}[ERROR] Inventory file not found at $INVENTORY${NC}"
    echo "Cannot determine which resources to delete. Check AWS console manually."
    exit 1
fi

# Parse inventory file
source <(grep -E '^[A-Z_]+=.*' $INVENTORY)

echo -e "${YELLOW}================================${NC}"
echo -e "${YELLOW} WAZUH LAB — TEARDOWN${NC}"
echo -e "${YELLOW}================================${NC}"
echo "This will DELETE:"
echo "  - EC2 instance: $MANAGER_INSTANCE_ID"
echo "  - Security groups: $MANAGER_SG_ID, $ENDPOINT_SG_ID"
echo "  - Subnets: $PUBLIC_SUBNET_ID, $PRIVATE_SUBNET_ID"
echo "  - Route table: $PUBLIC_RT_ID"
echo "  - Internet gateway: $IGW_ID"
echo "  - VPC: $VPC_ID"
echo ""
read -p "Type YES to confirm deletion: " CONFIRM

if [ "$CONFIRM" != "YES" ]; then
    echo "Aborted. Nothing deleted."
    exit 0
fi

echo -e "${YELLOW}[*] Terminating EC2 instance(s)...${NC}"
aws ec2 terminate-instances --instance-ids $MANAGER_INSTANCE_ID --region $REGION || true
aws ec2 wait instance-terminated --instance-ids $MANAGER_INSTANCE_ID --region $REGION || true
echo -e "${GREEN}[OK] Instance terminated${NC}"

echo -e "${YELLOW}[*] Deleting security groups...${NC}"
aws ec2 delete-security-group --group-id $ENDPOINT_SG_ID --region $REGION || true
aws ec2 delete-security-group --group-id $MANAGER_SG_ID --region $REGION || true
echo -e "${GREEN}[OK] Security groups deleted${NC}"

echo -e "${YELLOW}[*] Disassociating and deleting route table...${NC}"
ASSOC_ID=$(aws ec2 describe-route-tables --route-table-ids $PUBLIC_RT_ID --region $REGION \
  --query 'RouteTables[0].Associations[0].RouteTableAssociationId' --output text 2>/dev/null || echo "")
if [ -n "$ASSOC_ID" ] && [ "$ASSOC_ID" != "None" ]; then
    aws ec2 disassociate-route-table --association-id $ASSOC_ID --region $REGION || true
fi
aws ec2 delete-route-table --route-table-id $PUBLIC_RT_ID --region $REGION || true
echo -e "${GREEN}[OK] Route table removed${NC}"

echo -e "${YELLOW}[*] Detaching and deleting internet gateway...${NC}"
aws ec2 detach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID --region $REGION || true
aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID --region $REGION || true
echo -e "${GREEN}[OK] Internet gateway removed${NC}"

echo -e "${YELLOW}[*] Deleting subnets...${NC}"
aws ec2 delete-subnet --subnet-id $PUBLIC_SUBNET_ID --region $REGION || true
aws ec2 delete-subnet --subnet-id $PRIVATE_SUBNET_ID --region $REGION || true
echo -e "${GREEN}[OK] Subnets deleted${NC}"

echo -e "${YELLOW}[*] Deleting VPC...${NC}"
aws ec2 delete-vpc --vpc-id $VPC_ID --region $REGION || true
echo -e "${GREEN}[OK] VPC deleted${NC}"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN} TEARDOWN COMPLETE${NC}"
echo -e "${GREEN}================================${NC}"
echo "All billable resources have been removed."
echo "Note: The SSH key pair (wazuh-lab-key) was NOT deleted. Remove manually if desired:"
echo "  aws ec2 delete-key-pair --key-name wazuh-lab-key --region $REGION"
