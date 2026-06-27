#!/bin/bash
################################################################################
# WAZUH DETECTION LAB — STEP 1: AWS INFRASTRUCTURE DEPLOYMENT
# Creates VPC, subnets, security groups, and the Wazuh Manager EC2 instance.
# Run time: ~5 minutes
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}================================${NC}"
echo -e "${YELLOW} WAZUH LAB — INFRASTRUCTURE SETUP${NC}"
echo -e "${YELLOW}================================${NC}"

# ---- CONFIG ----
REGION="eu-north-1"
AZ="eu-north-1a"
VPC_CIDR="10.0.0.0/16"
PUBLIC_SUBNET_CIDR="10.0.1.0/24"
PRIVATE_SUBNET_CIDR="10.0.2.0/24"
MANAGER_PRIVATE_IP="10.0.1.10"
KEY_NAME="wazuh-lab-key"
KEY_PATH="$HOME/wazuh-lab-key.pem"

echo -e "${YELLOW}[*] Detecting your public IP...${NC}"
YOUR_IP=$(curl -s https://checkip.amazonaws.com | xargs echo)
echo -e "${GREEN}[OK] Your public IP: $YOUR_IP${NC}"

# ---- SSH KEY ----
echo -e "${YELLOW}[*] Creating SSH key pair...${NC}"
if aws ec2 describe-key-pairs --key-names $KEY_NAME --region $REGION &>/dev/null; then
  echo -e "${GREEN}[OK] Key pair already exists${NC}"
else
  aws ec2 create-key-pair --key-name $KEY_NAME --region $REGION \
    --query 'KeyMaterial' --output text > $KEY_PATH
  chmod 400 $KEY_PATH
  echo -e "${GREEN}[OK] Key created at $KEY_PATH${NC}"
fi

# ---- VPC ----
echo -e "${YELLOW}[*] Creating VPC...${NC}"
VPC_ID=$(aws ec2 create-vpc --cidr-block $VPC_CIDR --region $REGION \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=wazuh-vpc}]' \
  --query 'Vpc.VpcId' --output text)
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames --region $REGION
echo -e "${GREEN}[OK] VPC: $VPC_ID${NC}"

# ---- SUBNETS ----
echo -e "${YELLOW}[*] Creating subnets...${NC}"
PUBLIC_SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PUBLIC_SUBNET_CIDR \
  --availability-zone $AZ --region $REGION \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=wazuh-public-subnet}]' \
  --query 'Subnet.SubnetId' --output text)

PRIVATE_SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PRIVATE_SUBNET_CIDR \
  --availability-zone $AZ --region $REGION \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=wazuh-private-subnet}]' \
  --query 'Subnet.SubnetId' --output text)

aws ec2 modify-subnet-attribute --subnet-id $PUBLIC_SUBNET_ID --map-public-ip-on-launch --region $REGION
echo -e "${GREEN}[OK] Public subnet: $PUBLIC_SUBNET_ID${NC}"
echo -e "${GREEN}[OK] Private subnet: $PRIVATE_SUBNET_ID${NC}"

# ---- INTERNET GATEWAY + ROUTES ----
echo -e "${YELLOW}[*] Setting up internet gateway + routing...${NC}"
IGW_ID=$(aws ec2 create-internet-gateway --region $REGION \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=wazuh-igw}]' \
  --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID --region $REGION

PUBLIC_RT_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --region $REGION \
  --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=wazuh-public-rt}]' \
  --query 'RouteTable.RouteTableId' --output text)
aws ec2 create-route --route-table-id $PUBLIC_RT_ID --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW_ID --region $REGION
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_ID --route-table-id $PUBLIC_RT_ID --region $REGION
echo -e "${GREEN}[OK] IGW: $IGW_ID, Route table: $PUBLIC_RT_ID${NC}"

# ---- SECURITY GROUPS ----
echo -e "${YELLOW}[*] Creating security groups...${NC}"
MANAGER_SG_ID=$(aws ec2 create-security-group --group-name wazuh-manager-sg \
  --description "Wazuh Manager rules" --vpc-id $VPC_ID --region $REGION \
  --query 'GroupId' --output text)

ENDPOINT_SG_ID=$(aws ec2 create-security-group --group-name wazuh-endpoint-sg \
  --description "Wazuh Endpoint rules" --vpc-id $VPC_ID --region $REGION \
  --query 'GroupId' --output text)

# Manager inbound
aws ec2 authorize-security-group-ingress --group-id $MANAGER_SG_ID --protocol tcp --port 1514 --cidr 10.0.0.0/16 --region $REGION
aws ec2 authorize-security-group-ingress --group-id $MANAGER_SG_ID --protocol tcp --port 1515 --cidr 10.0.0.0/16 --region $REGION
aws ec2 authorize-security-group-ingress --group-id $MANAGER_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 --region $REGION
aws ec2 authorize-security-group-ingress --group-id $MANAGER_SG_ID --protocol tcp --port 22 --cidr "$YOUR_IP/32" --region $REGION

# Endpoint egress (replace default allow-all with explicit rules)
aws ec2 revoke-security-group-egress --group-id $ENDPOINT_SG_ID --protocol -1 --cidr 0.0.0.0/0 --region $REGION
aws ec2 authorize-security-group-egress --group-id $ENDPOINT_SG_ID --protocol tcp --port 1514 --cidr 10.0.0.0/16 --region $REGION
aws ec2 authorize-security-group-egress --group-id $ENDPOINT_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 --region $REGION
aws ec2 authorize-security-group-egress --group-id $ENDPOINT_SG_ID --protocol tcp --port 53 --cidr 0.0.0.0/0 --region $REGION
aws ec2 authorize-security-group-egress --group-id $ENDPOINT_SG_ID --protocol udp --port 53 --cidr 0.0.0.0/0 --region $REGION

echo -e "${GREEN}[OK] Manager SG: $MANAGER_SG_ID${NC}"
echo -e "${GREEN}[OK] Endpoint SG: $ENDPOINT_SG_ID${NC}"

# ---- AMI LOOKUP ----
echo -e "${YELLOW}[*] Finding latest Ubuntu 22.04 LTS AMI...${NC}"
UBUNTU_AMI=$(aws ec2 describe-images --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text --region $REGION)
echo -e "${GREEN}[OK] AMI: $UBUNTU_AMI${NC}"

# ---- LAUNCH MANAGER ----
echo -e "${YELLOW}[*] Launching Wazuh Manager EC2 instance (m7i-flex.large)...${NC}"
MANAGER_INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $UBUNTU_AMI --instance-type m7i-flex.large --key-name $KEY_NAME \
  --security-group-ids $MANAGER_SG_ID --subnet-id $PUBLIC_SUBNET_ID \
  --private-ip-address $MANAGER_PRIVATE_IP \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=60,VolumeType=gp3,DeleteOnTermination=true}" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=wazuh-manager}]' \
  --region $REGION --query 'Instances[0].InstanceId' --output text)

echo -e "${YELLOW}[*] Waiting for public IP assignment...${NC}"
sleep 30
MANAGER_PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $MANAGER_INSTANCE_ID --region $REGION \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo -e "${GREEN}[OK] Manager public IP: $MANAGER_PUBLIC_IP${NC}"

# ---- WAIT FOR BOOT ----
echo -e "${YELLOW}[*] Waiting for instance status checks (up to 5 min)...${NC}"
for i in {1..30}; do
  STATUS=$(aws ec2 describe-instance-status --instance-ids $MANAGER_INSTANCE_ID --region $REGION \
    --query 'InstanceStatuses[0].InstanceStatus.Status' --output text 2>/dev/null || echo "initializing")
  if [ "$STATUS" = "ok" ]; then
    echo -e "${GREEN}[OK] Status checks passed${NC}"
    break
  fi
  echo -ne "\r[*] Status: $STATUS (attempt $i/30)"
  sleep 10
done
echo ""

# ---- TEST SSH ----
echo -e "${YELLOW}[*] Testing SSH...${NC}"
sleep 10
for i in {1..5}; do
  if ssh -i $KEY_PATH -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    ubuntu@$MANAGER_PUBLIC_IP "echo OK" 2>/dev/null; then
    echo -e "${GREEN}[OK] SSH access verified${NC}"
    break
  fi
  echo -e "${YELLOW}[*] Retry $i/5...${NC}"
  sleep 10
done

# ---- SAVE INVENTORY ----
INVENTORY="$HOME/wazuh-lab-inventory.txt"
cat > $INVENTORY << EOF
WAZUH LAB INVENTORY — $(date)
================================
VPC_ID=$VPC_ID
PUBLIC_SUBNET_ID=$PUBLIC_SUBNET_ID
PRIVATE_SUBNET_ID=$PRIVATE_SUBNET_ID
IGW_ID=$IGW_ID
PUBLIC_RT_ID=$PUBLIC_RT_ID
MANAGER_SG_ID=$MANAGER_SG_ID
ENDPOINT_SG_ID=$ENDPOINT_SG_ID
MANAGER_INSTANCE_ID=$MANAGER_INSTANCE_ID
MANAGER_PUBLIC_IP=$MANAGER_PUBLIC_IP
MANAGER_PRIVATE_IP=$MANAGER_PRIVATE_IP
KEY_PATH=$KEY_PATH
REGION=$REGION

SSH command:
ssh -i $KEY_PATH ubuntu@$MANAGER_PUBLIC_IP
EOF

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN} INFRASTRUCTURE DEPLOYMENT DONE${NC}"
echo -e "${GREEN}================================${NC}"
cat $INVENTORY
