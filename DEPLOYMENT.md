# Deployment Runbook

This is the actual step-by-step order to deploy this lab. For deeper background
on *why* each piece exists, see `documentation/architecture-and-deployment-guide.md`.

## Prerequisites

- AWS account with permission to create VPCs, EC2 instances, and security groups
- AWS CLI v2 installed and configured (`aws configure`)
- A terminal: Git Bash, WSL2, or PowerShell on Windows; native terminal on Mac/Linux
- Basic comfort copy-pasting commands and reading error messages

## Step 1 — Deploy AWS Infrastructure

From your **local machine** (not inside any cloud instance yet):

**Linux/Mac/WSL2/Git Bash:**
```bash
chmod +x scripts/01-deploy-infrastructure.sh
bash scripts/01-deploy-infrastructure.sh
```

**Windows PowerShell:**
```powershell
powershell -ExecutionPolicy Bypass -File scripts\01-deploy-infrastructure.ps1
```

This creates:
- VPC (10.0.0.0/16) with public + private subnets
- Security groups with the exact firewall rules from the architecture doc
- The Wazuh Manager EC2 instance (Ubuntu 22.04, t3.large)

Output is saved to `~/wazuh-lab-inventory.txt` — **keep this file**, every later step needs the IPs and IDs in it.

## Step 2 — Install Wazuh Manager

SSH into the manager using the command from your inventory file:

```bash
ssh -i ~/wazuh-lab-key.pem ubuntu@<MANAGER_PUBLIC_IP>
```

Once connected, copy `scripts/02-install-manager.sh` onto the instance (or paste its
contents directly into a new file there) and run:

```bash
chmod +x 02-install-manager.sh
bash 02-install-manager.sh
```

This installs Wazuh Manager + Wazuh Indexer (Elasticsearch-compatible) + Wazuh
Dashboard (Kibana-based), all on the single manager instance. Takes 15-20 minutes.

When done, access the dashboard at `https://<MANAGER_PUBLIC_IP>` from your browser.

## Step 3 — Launch Endpoint Instances

You'll need two more EC2 instances (not created by step 1, since endpoint OS/AMI
choices vary by what you want to test):

- **Ubuntu 22.04** endpoint — launch as `t3.medium`, in the **private subnet**,
  using the **wazuh-endpoint-sg** security group created in step 1
- **Windows Server 2022** endpoint — same instance type and subnet/SG

```bash
# Example: launching the Ubuntu endpoint (adjust AMI/SG/subnet IDs from your inventory)
aws ec2 run-instances \
  --image-id <ubuntu-2204-ami-id> \
  --instance-type t3.medium \
  --key-name wazuh-lab-key \
  --security-group-ids <ENDPOINT_SG_ID> \
  --subnet-id <PRIVATE_SUBNET_ID> \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ubuntu-target}]'
```

For the Windows instance, use the AWS Console (easier for picking the right
Windows Server 2022 AMI) or `aws ec2 run-instances` with a Windows AMI ID.

Since these endpoints are in the **private subnet**, you'll need either:
- A bastion host / Session Manager to reach them, or
- A temporary SSH/RDP rule added to `wazuh-endpoint-sg` for setup only (remove after)

## Step 4 — Install Agents

**On the Ubuntu endpoint:**
```bash
chmod +x 02-install-agent-ubuntu.sh
sudo bash 02-install-agent-ubuntu.sh <MANAGER_PRIVATE_IP> UBUNTU-TARGET-01
```

**On the Windows endpoint (PowerShell as Administrator):**
```powershell
.\02-install-agent-windows.ps1 -ManagerIp "10.0.1.10" -AgentName "WIN-TARGET-01"
```

Verify both agents registered, from the manager:
```bash
sudo /var/ossec/bin/manage_agents -l
```

## Step 5 — Load Custom Detection Rules

On the manager:
```bash
sudo cp configs/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

## Step 6 — Run Attack Simulations

On the Windows endpoint (PowerShell as Administrator):
```powershell
.\03-run-atomic-tests.ps1
```

Then check the Wazuh dashboard for alerts matching rule IDs 100100-100141.

## Step 7 — Tear Down (when done for the day/week)

```bash
bash scripts/cleanup.sh
```

This deletes the EC2 instance, security groups, subnets, route table, IGW, and
VPC created in Step 1 — but does **not** delete the endpoint instances you
launched manually in Step 3, since those weren't tracked in the inventory file.
Terminate those separately:

```bash
aws ec2 terminate-instances --instance-ids <ubuntu-endpoint-id> <windows-endpoint-id>
```

---

## Troubleshooting

See `documentation/architecture-and-deployment-guide.md` for detailed
troubleshooting of agent registration, Elasticsearch health, and common errors.
