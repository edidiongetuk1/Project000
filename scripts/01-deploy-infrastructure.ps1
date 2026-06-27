# =============================================================================
# WAZUH DETECTION LAB — STEP 1: AWS INFRASTRUCTURE DEPLOYMENT (PowerShell)
# Creates VPC, subnets, security groups, and the Wazuh Manager EC2 instance.
# Run from Windows PowerShell. Requires AWS CLI v2 configured (aws configure).
# =============================================================================

$ErrorActionPreference = "Stop"

function Write-Ok($msg)   { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Yellow }

Write-Host "================================" -ForegroundColor Yellow
Write-Host " WAZUH LAB - INFRASTRUCTURE SETUP" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Yellow

# ---- CONFIG ----
$REGION = "us-east-1"
$AZ = "us-east-1a"
$VPC_CIDR = "10.0.0.0/16"
$PUBLIC_SUBNET_CIDR = "10.0.1.0/24"
$PRIVATE_SUBNET_CIDR = "10.0.2.0/24"
$MANAGER_PRIVATE_IP = "10.0.1.10"
$KEY_NAME = "wazuh-lab-key"
$KEY_PATH = "$HOME\wazuh-lab-key.pem"

Write-Info "Detecting your public IP..."
$YOUR_IP = (Invoke-WebRequest -Uri "https://checkip.amazonaws.com" -UseBasicParsing).Content.Trim()
Write-Ok "Your public IP: $YOUR_IP"

# ---- SSH KEY ----
Write-Info "Creating SSH key pair..."
$existingKey = aws ec2 describe-key-pairs --key-names $KEY_NAME --region $REGION 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Key pair already exists"
} else {
    $keyMaterial = aws ec2 create-key-pair --key-name $KEY_NAME --region $REGION --query 'KeyMaterial' --output text
    $keyMaterial | Out-File -FilePath $KEY_PATH -Encoding ascii
    Write-Ok "Key created at $KEY_PATH"
}

# ---- VPC ----
Write-Info "Creating VPC..."
$VPC_ID = aws ec2 create-vpc --cidr-block $VPC_CIDR --region $REGION `
  --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=wazuh-vpc}]" `
  --query 'Vpc.VpcId' --output text
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames --region $REGION
Write-Ok "VPC: $VPC_ID"

# ---- SUBNETS ----
Write-Info "Creating subnets..."
$PUBLIC_SUBNET_ID = aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PUBLIC_SUBNET_CIDR `
  --availability-zone $AZ --region $REGION `
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=wazuh-public-subnet}]" `
  --query 'Subnet.SubnetId' --output text

$PRIVATE_SUBNET_ID = aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PRIVATE_SUBNET_CIDR `
  --availability-zone $AZ --region $REGION `
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=wazuh-private-subnet}]" `
  --query 'Subnet.SubnetId' --output text

aws ec2 modify-subnet-attribute --subnet-id $PUBLIC_SUBNET_ID --map-public-ip-on-launch --region $REGION
Write-Ok "Public subnet: $PUBLIC_SUBNET_ID"
Write-Ok "Private subnet: $PRIVATE_SUBNET_ID"

# ---- INTERNET GATEWAY + ROUTES ----
Write-Info "Setting up internet gateway + routing..."
$IGW_ID = aws ec2 create-internet-gateway --region $REGION `
  --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=wazuh-igw}]" `
  --query 'InternetGateway.InternetGatewayId' --output text
aws ec2 attach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID --region $REGION

$PUBLIC_RT_ID = aws ec2 create-route-table --vpc-id $VPC_ID --region $REGION `
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=wazuh-public-rt}]" `
  --query 'RouteTable.RouteTableId' --output text
aws ec2 create-route --route-table-id $PUBLIC_RT_ID --destination-cidr-block 0.0.0.0/0 `
  --gateway-id $IGW_ID --region $REGION
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_ID --route-table-id $PUBLIC_RT_ID --region $REGION
Write-Ok "IGW: $IGW_ID, Route table: $PUBLIC_RT_ID"

# ---- SECURITY GROUPS ----
Write-Info "Creating security groups..."
$MANAGER_SG_ID = aws ec2 create-security-group --group-name wazuh-manager-sg `
  --description "Wazuh Manager rules" --vpc-id $VPC_ID --region $REGION `
  --query 'GroupId' --output text

$ENDPOINT_SG_ID = aws ec2 create-security-group --group-name wazuh-endpoint-sg `
  --description "Wazuh Endpoint rules" --vpc-id $VPC_ID --region $REGION `
  --query 'GroupId' --output text

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

Write-Ok "Manager SG: $MANAGER_SG_ID"
Write-Ok "Endpoint SG: $ENDPOINT_SG_ID"

# ---- AMI LOOKUP ----
Write-Info "Finding latest Ubuntu 22.04 LTS AMI..."
$UBUNTU_AMI = aws ec2 describe-images --owners 099720109477 `
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" `
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text --region $REGION
Write-Ok "AMI: $UBUNTU_AMI"

# ---- LAUNCH MANAGER ----
Write-Info "Launching Wazuh Manager EC2 instance (t3.large)..."
$MANAGER_INSTANCE_ID = aws ec2 run-instances `
  --image-id $UBUNTU_AMI --instance-type t3.large --key-name $KEY_NAME `
  --security-group-ids $MANAGER_SG_ID --subnet-id $PUBLIC_SUBNET_ID `
  --private-ip-address $MANAGER_PRIVATE_IP `
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=60,VolumeType=gp3,DeleteOnTermination=true}" `
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=wazuh-manager}]" `
  --region $REGION --query 'Instances[0].InstanceId' --output text

Write-Info "Waiting for public IP assignment..."
Start-Sleep -Seconds 30
$MANAGER_PUBLIC_IP = aws ec2 describe-instances --instance-ids $MANAGER_INSTANCE_ID --region $REGION `
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text
Write-Ok "Manager public IP: $MANAGER_PUBLIC_IP"

# ---- WAIT FOR BOOT ----
Write-Info "Waiting for instance status checks (up to 5 min)..."
for ($i = 1; $i -le 30; $i++) {
    $STATUS = aws ec2 describe-instance-status --instance-ids $MANAGER_INSTANCE_ID --region $REGION `
      --query 'InstanceStatuses[0].InstanceStatus.Status' --output text 2>$null
    if ($STATUS -eq "ok") {
        Write-Ok "Status checks passed"
        break
    }
    Write-Host "`r[*] Status: $STATUS (attempt $i/30)" -NoNewline
    Start-Sleep -Seconds 10
}
Write-Host ""

# ---- SAVE INVENTORY ----
$INVENTORY = "$HOME\wazuh-lab-inventory.txt"
@"
WAZUH LAB INVENTORY - $(Get-Date)
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

SSH command (use PuTTY or Git Bash / WSL):
ssh -i "$KEY_PATH" ubuntu@$MANAGER_PUBLIC_IP
"@ | Out-File -FilePath $INVENTORY -Encoding utf8

Write-Host "================================" -ForegroundColor Green
Write-Host " INFRASTRUCTURE DEPLOYMENT DONE" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Get-Content $INVENTORY

Write-Host ""
Write-Host "NOTE: Windows PowerShell does not have a native SSH client by default on older systems." -ForegroundColor Yellow
Write-Host "If 'ssh' is not recognized, install it via: Settings > Apps > Optional Features > OpenSSH Client" -ForegroundColor Yellow
Write-Host "Or use Git Bash / WSL2 to run the ssh command above." -ForegroundColor Yellow
