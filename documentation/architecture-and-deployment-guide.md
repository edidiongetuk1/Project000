# Cloud-Native SIEM & EDR Detection Engineering
## Blue Team Detection Lab — Architecture & Deployment Guide

---

## 1. ARCHITECTURE DIAGRAM (Text-Based)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            INTERNET / ATTACKER SIMULATION                    │
│                                (Atomic Red Team)                             │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
        ┌───────────▼───────────┐  ┌────────▼────────────┐
        │  WINDOWS SERVER 2022  │  │   UBUNTU 22.04     │
        │  (Target Endpoint 1)  │  │  (Target Endpoint 2)│
        │                       │  │                    │
        │  ┌─────────────────┐  │  │  ┌──────────────┐  │
        │  │ Wazuh Agent 4.x │  │  │  │ Wazuh Agent  │  │
        │  │ + Sysmon 14.x   │  │  │  │ + Auditd     │  │
        │  └────────┬────────┘  │  │  └──────┬───────┘  │
        │           │           │  │         │          │
        └───────────┼───────────┘  └─────────┼──────────┘
                    │                         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   AWS SECURITY GROUP    │
                    │  (Ingress Rule)         │
                    │  Port: 1514/TCP (agent) │
                    │  Port: 1515/TCP (agents)│
                    │  CIDR: 10.0.0.0/16      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────────────────┐
                    │   AWS EC2 Instance (t3.large)       │
                    │   WAZUH MANAGER - CENTRAL SIEM      │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │ Wazuh Manager 4.x           │   │
                    │  │ (Log Aggregation + Rules)   │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │ Elasticsearch (Backend DB)  │   │
                    │  │ (Full-text search indexing) │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │ Kibana Dashboard (Frontend) │   │
                    │  │ (Security visualizations)   │   │
                    │  └─────────────────────────────┘   │
                    │                                     │
                    │  ┌─────────────────────────────┐   │
                    │  │ Alert Rules Engine          │   │
                    │  │ (Custom Sigma/Yara rules)   │   │
                    │  └─────────────────────────────┘   │
                    └───────────┬────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   EGRESS RULES          │
                    │  Port: 443/TCP (HTTPS)  │
                    │  For: External logging  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  TELEMETRY FLOW         │
                    │                         │
                    │  1. Agent → Manager     │
                    │     (1514/TCP encrypted)│
                    │  2. Logs Indexed in ES  │
                    │  3. Rules Evaluate      │
                    │  4. Alerts Generated    │
                    │  5. Dashboards Update   │
                    └─────────────────────────┘
```

### **Telemetry Flow Description**

1. **Endpoint Collection (Windows + Ubuntu)**
   - Wazuh agent collects: process execution, file integrity, authentication events, network connections
   - Sysmon (Windows) / Auditd (Linux) generates low-level system events
   - Agent encrypts and buffers logs locally

2. **Agent-to-Manager Communication (1514/TCP)**
   - Secure TLS 1.2+ connection
   - Agent authenticates via certificate exchange
   - Logs transmitted in real-time (default: 100ms latency)
   - Manager decompresses and validates event structure

3. **Elasticsearch Indexing**
   - Manager forwards logs to Elasticsearch cluster
   - Index template maps fields (process_name, user, src_ip, dst_ip, etc.)
   - Events searchable within 2-5 seconds

4. **Detection Rule Evaluation**
   - Custom Sigma/Yara rules match against indexed logs
   - MITRE ATT&CK tactics/techniques tagged for context
   - False positive filters applied (e.g., exclude known whitelisted processes)

5. **Alert Generation & Escalation**
   - High-fidelity alerts written to /var/ossec/logs/alerts/ (JSON format)
   - Kibana dashboard updates in real-time
   - Optional: Webhook integration for Slack/email notifications

---

## 2. NETWORK & FIREWALL CONFIGURATION

### **AWS Security Group Rules**

#### **Inbound Rules (Wazuh Manager Security Group)**

| Rule # | Protocol | Port(s)  | Source CIDR    | Description                              |
|--------|----------|----------|----------------|------------------------------------------|
| 1      | TCP      | 1514     | 10.0.0.0/16    | Wazuh agents (encrypted data)           |
| 2      | TCP      | 1515     | 10.0.0.0/16    | Wazuh agent registration                |
| 3      | TCP      | 514      | 10.0.0.0/16    | Syslog (optional, for legacy endpoints) |
| 4      | TCP      | 9200     | 10.0.0.0/16    | Elasticsearch (internal only)           |
| 5      | TCP      | 443      | 0.0.0.0/0      | Kibana Web UI (HTTPS)                   |
| 6      | TCP      | 22       | <YOUR_IP>/32   | SSH Admin access (restrict to you)      |

#### **Outbound Rules (Wazuh Manager Security Group)**

| Rule # | Protocol | Port(s)  | Destination    | Description                        |
|--------|----------|----------|----------------|------------------------------------|
| 1      | TCP      | 443      | 0.0.0.0/0      | HTTPS (external threat feeds, OS updates) |
| 2      | TCP      | 53       | 0.0.0.0/0      | DNS                                |
| 3      | UDP      | 53       | 0.0.0.0/0      | DNS                                |

#### **Endpoint Security Group Rules (Windows/Ubuntu)**

**Outbound Only (they initiate to Manager):**

| Rule # | Protocol | Port(s)  | Destination    | Description                  |
|--------|----------|----------|----------------|------------------------------|
| 1      | TCP      | 1514     | 10.0.X.X/32    | Wazuh Manager IP (required)  |
| 2      | TCP      | 443      | 0.0.0.0/0      | HTTPS for OS updates         |
| 3      | TCP      | 53       | 0.0.0.0/0      | DNS resolution               |
| 4      | UDP      | 53       | 0.0.0.0/0      | DNS resolution               |

---

### **Network Diagram (Security Groups)**

```
┌───────────────────────────────────────────────────────────────────┐
│                    AWS VPC: 10.0.0.0/16                           │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Public Subnet: 10.0.1.0/24                               │    │
│  │ (Wazuh Manager + Kibana exposed)                         │    │
│  │                                                           │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │ SG: wazuh-manager-sg                            │    │    │
│  │  │ ├─ IN:  1514/TCP (agents)                       │    │    │
│  │  │ ├─ IN:  1515/TCP (agent-auth)                   │    │    │
│  │  │ ├─ IN:  443/TCP (Kibana - HTTPS only)           │    │    │
│  │  │ ├─ IN:  22/TCP (SSH from admin IP)              │    │    │
│  │  │ ├─ OUT: 443/TCP (any)                           │    │    │
│  │  │ └─ OUT: 53/TCP+UDP (any)                        │    │    │
│  │  │                                                  │    │    │
│  │  │  EC2: wazuh-manager (t3.large)                 │    │    │
│  │  │  IP: 10.0.1.10                                  │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  │                                                           │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ Private Subnet: 10.0.2.0/24                              │    │
│  │ (Endpoints with outbound-only rules)                     │    │
│  │                                                           │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │ SG: wazuh-endpoint-sg                           │    │    │
│  │  │ ├─ IN:  None (all blocked)                      │    │    │
│  │  │ ├─ OUT: 1514/TCP → 10.0.1.10                    │    │    │
│  │  │ ├─ OUT: 443/TCP (any)                           │    │    │
│  │  │ └─ OUT: 53/TCP+UDP (any)                        │    │    │
│  │  │                                                  │    │    │
│  │  │  EC2: windows-target (t3.medium)               │    │    │
│  │  │  IP: 10.0.2.20                                  │    │    │
│  │  │                                                  │    │    │
│  │  │  EC2: ubuntu-target (t3.medium)                │    │    │
│  │  │  IP: 10.0.2.21                                  │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  │                                                           │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                    │
└───────────────────────────────────────────────────────────────────┘
```

---

### **TLS Certificate Configuration**

Wazuh agents and manager communicate via **self-signed TLS certificates**:

```
Manager generates:
├─ /var/ossec/etc/ssl/certs/manager.crt (public)
├─ /var/ossec/etc/ssl/private_key/manager.key (private)
└─ /var/ossec/etc/ssl/certs/ca.crt (CA certificate)

Agent receives:
├─ /var/ossec/etc/ssl/certs/ca.crt (to verify manager)
├─ /var/ossec/etc/ssl/certs/agent.crt (own certificate)
└─ /var/ossec/etc/ssl/private_key/agent.key (own key)

Verification flow:
1. Agent initiates TLS handshake on 1514/TCP
2. Manager presents certificate
3. Agent validates against ca.crt
4. Mutual authentication confirmed
5. Encrypted channel established (AES-256-GCM)
```

---

## 3. WEEK 1 DEPLOYMENT PLAN

### **Timeline: 5 Business Days**

#### **Day 1: Infrastructure Setup (Monday)**

**Objectives:**
- Provision AWS VPC and security groups
- Launch Wazuh manager EC2 instance
- Configure network connectivity

**Tasks:**

```bash
# 1. Create VPC and Subnets (AWS Console or CLI)
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --region us-east-1
aws ec2 create-subnet --vpc-id vpc-xxxxx --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id vpc-xxxxx --cidr-block 10.0.2.0/24 --availability-zone us-east-1a

# 2. Create Security Groups
aws ec2 create-security-group --group-name wazuh-manager-sg \
  --description "Wazuh Manager inbound/outbound" --vpc-id vpc-xxxxx

aws ec2 create-security-group --group-name wazuh-endpoint-sg \
  --description "Endpoint outbound only" --vpc-id vpc-xxxxx

# 3. Add ingress rules to manager SG
aws ec2 authorize-security-group-ingress --group-id sg-xxxxx \
  --protocol tcp --port 1514 --cidr 10.0.0.0/16

aws ec2 authorize-security-group-ingress --group-id sg-xxxxx \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# 4. Launch Wazuh Manager EC2 (AMI: Ubuntu 22.04 LTS t3.large)
aws ec2 run-instances --image-id ami-xxxxx --instance-type t3.large \
  --key-name your-key --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=wazuh-manager}]'
```

**Deliverables:**
- [ ] VPC created (10.0.0.0/16)
- [ ] Security groups configured (wazuh-manager-sg, wazuh-endpoint-sg)
- [ ] Wazuh manager EC2 running (record public IP for step 2)
- [ ] SSH access verified (ssh -i key.pem ubuntu@<public-ip>)

**Documentation:**
- Screenshot of AWS VPC dashboard
- Screenshot of security group rules

---

#### **Day 2: Wazuh Manager Installation (Tuesday)**

**Objectives:**
- Install Wazuh manager + Elasticsearch + Kibana on single EC2 instance
- Configure TLS certificates for agent communication
- Verify manager health

**Tasks:**

```bash
# SSH into manager instance
ssh -i your-key.pem ubuntu@<manager-public-ip>

# 1. Update system and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget gnupg lsb-release apt-transport-https

# 2. Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list

# 3. Install Wazuh manager
sudo apt update
sudo apt install -y wazuh-manager

# 4. Start and enable Wazuh service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# 5. Verify manager is running
sudo systemctl status wazuh-manager
sudo /var/ossec/bin/wazuh-control status

# 6. Generate SSL certificates for agent communication
sudo /var/ossec/certs/certbot.sh -a

# 7. Display certificate fingerprint (for agent verification)
sudo cat /var/ossec/etc/ssl/certs/manager.crt | openssl x509 -text -noout | grep -A1 "Subject:"

# 8. Install Elasticsearch
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.14.0-amd64.deb
sudo dpkg -i elasticsearch-7.14.0-amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# 9. Install Kibana
wget https://artifacts.elastic.co/downloads/kibana/kibana-7.14.0-amd64.deb
sudo dpkg -i kibana-7.14.0-amd64.deb
sudo systemctl daemon-reload
sudo systemctl enable kibana
sudo systemctl start kibana

# 10. Configure Wazuh dashboard (Kibana plugin)
cd /opt/kibana
sudo bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuh-7.14.0-oss-7.14.0.zip

# 11. Restart Kibana
sudo systemctl restart kibana

# 12. Verify all services are running
sudo systemctl status wazuh-manager elasticsearch kibana
```

**Verify Installation:**

```bash
# Check Wazuh manager API
curl -u wazuh:wazuh https://localhost:55000/manager/info -k

# Check Elasticsearch cluster health
curl -k -u elastic:changeme https://localhost:9200/_cluster/health

# Access Kibana (browser)
# https://<manager-public-ip>:5601
# Default credentials: elastic / changeme (change immediately!)
```

**Deliverables:**
- [ ] Wazuh manager running (systemctl status)
- [ ] Elasticsearch cluster healthy
- [ ] Kibana dashboard accessible (screenshot)
- [ ] SSL certificates generated (/var/ossec/etc/ssl/certs/)
- [ ] Manager API responding

**Documentation:**
- Screenshot of Kibana landing page
- Output of `/var/ossec/bin/wazuh-control status`
- Certificate fingerprint recorded

---

#### **Day 3: Endpoint Preparation (Windows Target) (Wednesday)**

**Objectives:**
- Launch Windows Server 2022 EC2 instance
- Install Sysmon for enhanced logging
- Prepare for Wazuh agent installation (Day 4)

**Tasks:**

```bash
# 1. Launch Windows Server 2022 EC2 (from AWS Console)
# Instance type: t3.medium
# AMI: Windows Server 2022 Base
# Security Group: wazuh-endpoint-sg (outbound only to 10.0.1.10:1514)
# Subnet: 10.0.2.0/24 (private subnet)

# 2. Once launched, RDP into instance
# Administrator: Get password from EC2 console
# mstsc.exe (Remote Desktop Client)
# IP: <instance-private-ip> or use Systems Manager Session Manager

# 3. Disable Windows Defender (for lab purposes only - re-enable in production!)
# Or whitelist Wazuh installation path

# 4. Download and install Sysmon (PowerShell as Administrator)
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonPath = "C:\Tools\Sysmon"
mkdir $sysmonPath -Force
Invoke-WebRequest $sysmonUrl -OutFile "$sysmonPath\sysmon.zip"
Expand-Archive "$sysmonPath\sysmon.zip" -DestinationPath $sysmonPath

# 5. Download Sysmon config (SwiftOnSecurity recommended config)
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
Invoke-WebRequest $configUrl -OutFile "$sysmonPath\sysmonconfig.xml"

# 6. Install Sysmon with config
cd $sysmonPath
.\Sysmon.exe -i sysmonconfig.xml -accepteula

# 7. Verify Sysmon is running
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Select-Object -First 1 | Format-List

# 8. Download Wazuh agent (for Windows)
$wazuhUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x-1.msi"
Invoke-WebRequest $wazuhUrl -OutFile "C:\wazuh-agent-4.x.x-1.msi"
```

**Deliverables:**
- [ ] Windows Server 2022 EC2 running
- [ ] RDP access confirmed
- [ ] Sysmon installed and running
- [ ] Event logs generating (sample events visible in Event Viewer)
- [ ] Wazuh agent MSI downloaded

**Documentation:**
- Screenshot of Sysmon event logs in Event Viewer
- Screenshot of task manager showing Sysmon.exe running

---

#### **Day 4: Agent Installation & Registration (Thursday)**

**Objectives:**
- Install Wazuh agent on Windows and Ubuntu endpoints
- Register agents with manager
- Verify telemetry flowing to Elasticsearch

**Tasks - Windows:**

```powershell
# PowerShell as Administrator

# 1. Install Wazuh agent MSI
msiexec.exe /i "C:\wazuh-agent-4.x.x-1.msi" /q WAZUH_MANAGER="10.0.1.10" WAZUH_AGENT_GROUP="windows" WAZUH_AGENT_NAME="WINDOWS-TARGET-01"

# 2. Modify agent config (ossec.conf)
# C:\Program Files (x86)\ossec-agent\ossec.conf
# Verify <manager_ip> is 10.0.1.10
# Verify <agent_name> is set

# 3. Start Wazuh agent service
net start WazuhSvc

# 4. Verify agent status
# Check logs: C:\Program Files (x86)\ossec-agent\logs\ossec.log
```

**Tasks - Ubuntu:**

```bash
# SSH into Ubuntu target instance
ssh -i your-key.pem ubuntu@<ubuntu-private-ip>

# 1. Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list

# 2. Install Wazuh agent
sudo apt update
sudo apt install -y wazuh-agent

# 3. Configure agent
sudo nano /var/ossec/etc/ossec.conf
# Verify: <manager_ip>10.0.1.10</manager_ip>
# Add: <agent_name>UBUNTU-TARGET-01</agent_name>
# Add: <log_alert_level>3</log_alert_level>

# 4. Enable and start agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# 5. Verify agent status
sudo systemctl status wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log | grep -i "connected\|Active"

# 6. Install Auditd for enhanced audit logging
sudo apt install -y auditd
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Verify Agent Registration (from Manager):**

```bash
# SSH into manager
ssh -i your-key.pem ubuntu@<manager-public-ip>

# 1. Check agent connections
sudo /var/ossec/bin/manage_agents -l

# Expected output:
# ID: 001 Name: WINDOWS-TARGET-01 IP: 10.0.2.20
# ID: 002 Name: UBUNTU-TARGET-01 IP: 10.0.2.21
# Status: Active

# 2. Verify agents are forwarding logs
sudo tail -f /var/ossec/logs/ossec.log | grep "agent connecting\|Received from"

# 3. Check Elasticsearch indices (logs indexed)
curl -k -u elastic:changeme https://localhost:9200/_cat/indices?v | grep wazuh

# Expected indices: wazuh-alerts-4.x-*, wazuh-logs-*
```

**Deliverables:**
- [ ] Windows agent installed and started
- [ ] Ubuntu agent installed and started
- [ ] Both agents showing as "Active" in manager
- [ ] Elasticsearch indices created (wazuh-* indices visible)
- [ ] Sample logs indexed (searchable via Kibana)

**Documentation:**
- Screenshot of `manage_agents -l` output showing both agents active
- Screenshot of Kibana Discover tab showing agent logs

---

#### **Day 5: Kibana Dashboard Setup & Documentation (Friday)**

**Objectives:**
- Create custom Kibana dashboard
- Set up index patterns for easy querying
- Document the architecture for GitHub

**Tasks:**

```bash
# 1. Access Kibana
# https://<manager-public-ip>:5601

# 2. Create Index Pattern
# Stack Management > Index Patterns > Create index pattern
# Pattern name: wazuh-*
# Timestamp field: timestamp

# 3. Create Visualization: "Process Execution Timeline"
# Visualize > Create > Line Chart
# Index: wazuh-*
# Metric: Count
# Bucket: X-axis = timestamp, Y-axis = process.name
# Filters: data.win.eventdata.image exists

# 4. Create Visualization: "Top Source IPs (Network Connections)"
# Visualize > Create > Bar Chart
# Index: wazuh-*
# Metric: Count
# Bucket: source.ip
# Size: 10

# 5. Create Visualization: "Failed Authentication Attempts"
# Visualize > Create > Table
# Index: wazuh-*
# Metric: Count
# Bucket: destination.user, source.ip
# Filter: data.win.eventdata.eventID:4625 OR data.linux.audit.type:USER_ACCT

# 6. Create Main Dashboard
# Dashboards > Create > Add visualizations from above
# Add: Process Timeline, Top IPs, Failed Auth
# Save as: "Blue Team Detection Lab - Overview"

# 7. Export dashboard JSON for GitHub documentation
# Dashboard > Share > Export dashboard as JSON
# Save to: /tmp/wazuh-dashboard-export.json
```

**Documentation Tasks:**

```bash
# 1. Generate architecture diagram (text + visual)
# Already covered in Section 1

# 2. Document network topology
# Already covered in Section 2

# 3. Create deployment runbook
# Already covered in Section 3

# 4. Record system information for GitHub
cat /etc/os-release  # Manager OS
aws ec2 describe-instances --instance-ids <manager-id> # Infrastructure details
wazuh-control status  # Manager version
curl -u wazuh:wazuh https://localhost:55000/manager/info -k  # Full info

# 5. Create inventory file (for reproducibility)
# Documented below
```

**Week 1 Inventory Document:**

```
WEEK 1 DEPLOYMENT INVENTORY
===========================

Infrastructure:
├─ Manager EC2: t3.large (10.0.1.10) — Ubuntu 22.04 LTS
├─ Windows Target: t3.medium (10.0.2.20) — Windows Server 2022
└─ Ubuntu Target: t3.medium (10.0.2.21) — Ubuntu 22.04 LTS

Services (Manager):
├─ Wazuh Manager 4.6.0
├─ Elasticsearch 7.14.0
├─ Kibana 7.14.0
└─ SSL/TLS certificates (self-signed, valid 365 days)

Agents:
├─ Windows Agent: 4.6.0 + Sysmon 14.x
├─ Ubuntu Agent: 4.6.0 + Auditd
└─ Status: Both Active, forwarding logs

Network:
├─ VPC: 10.0.0.0/16
├─ Public Subnet: 10.0.1.0/24 (Manager)
├─ Private Subnet: 10.0.2.0/24 (Endpoints)
├─ SG Rules: Configured per section 2
└─ Agent ↔ Manager: 1514/TCP encrypted

Elasticsearch:
├─ Indices: wazuh-alerts-4.x-*, wazuh-logs-*
├─ Shards: 1 (can scale up Week 3)
├─ Retention: Default 30 days
└─ Total docs indexed: 15,000+ (sample logs)

Kibana:
├─ Index patterns: wazuh-*
├─ Visualizations: 3 (Process Timeline, Top IPs, Failed Auth)
├─ Dashboard: "Blue Team Detection Lab - Overview"
└─ Access: https://<manager-public-ip>:5601

Costs (Est. Week 1):
├─ t3.large (manager, 168 hrs): $12.00
├─ t3.medium x2 (endpoints, 168 hrs): $16.00
├─ Data transfer (minimal): $0.50
└─ Total: ~$28.50 (free tier may cover)

Next Steps (Week 2-3):
1. Deploy Atomic Red Team attack scenarios
2. Write custom Sigma detection rules
3. Tune false positive filters
4. Document detection playbooks
5. Create LinkedIn + Reddit content
```

**Deliverables:**
- [ ] Kibana dashboard created with 3+ visualizations
- [ ] Index patterns configured
- [ ] Dashboard JSON exported
- [ ] Architecture documentation complete
- [ ] Inventory document created

**Documentation:**
- Screenshot of Kibana dashboard
- Exported JSON dashboard (for GitHub)
- Complete Week 1 inventory

---

## WEEK 1 SUMMARY CHECKLIST

- [ ] **Day 1**: VPC + Security groups + EC2 infrastructure ready
- [ ] **Day 2**: Wazuh + Elasticsearch + Kibana installed and healthy
- [ ] **Day 3**: Windows Server 2022 target with Sysmon installed
- [ ] **Day 4**: Both agents registered, actively forwarding logs
- [ ] **Day 5**: Kibana dashboard created, architecture documented

---

## COST OPTIMIZATION (Week 1+)

| Item | Cost/Month | Notes |
|------|-----------|-------|
| t3.large (manager) | $28.00 | Could use t3.medium ($16/mo) for light load |
| t3.medium x2 (endpoints) | $32.00 | Can remove during idle weeks |
| Data transfer (inter-AZ) | $5-10 | Minimize by using same AZ |
| **Total** | **~$65-75/month** | Free tier covers $12/mo. Budget accordingly. |

**Cost Reduction Strategy:**
- Stop instances on weekends (reduce to ~$35/month)
- Use smaller instance types during initial dev
- Clean old logs (don't keep 30-day retention)
- Monitor via AWS Cost Explorer

---

## NEXT: WEEKS 2-7 ROADMAP (Brief)

| Week | Focus | Deliverables |
|------|-------|--------------|
| 2 | Atomic Red Team attacks (T1566.002 phishing, T1003.001 lsass dump) | Attack logs, evidence |
| 3 | Sigma rule writing (process whitelisting, EDR tuning) | 5-10 custom rules |
| 4 | MITRE ATT&CK mapping + detection logic | Playbook draft |
| 5 | Dashboard optimization + FP reduction | Tuned dashboard |
| 6-7 | Documentation + GitHub publication + LinkedIn post | Polished repo + portfolio |

