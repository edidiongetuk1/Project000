# Detection Engineering Playbook Template
## Standardized Incident Response & Rule Documentation Format

---

## PLAYBOOK TEMPLATE

Use this template for each custom detection rule you develop. This ensures consistency across your GitHub portfolio and makes playbooks immediately actionable for SOC teams.

### **Header Section**

```markdown
# Playbook: [Attack Name] — [MITRE Technique ID]
**Rule ID:** [unique-rule-id]  
**Author:** [Your Name]  
**Last Updated:** [YYYY-MM-DD]  
**Status:** Production / Testing  
**Severity:** Critical / High / Medium / Low  
**Priority:** P1 (Immediate) / P2 (1hr) / P3 (4hrs) / P4 (Daily)  

---
```

---

## COMPLETE PLAYBOOK EXAMPLE

### **Playbook 1: LSASS Memory Dump Detection (T1003.001)**

```markdown
# Playbook: LSASS Memory Dump Detection — T1003.001
**Rule ID:** wazuh-credential-access-lsass-dump-001  
**Author:** Blue Team Lab  
**Last Updated:** 2024-06-20  
**Status:** Production  
**Severity:** Critical  
**Priority:** P1 (Immediate)  

---

## 1. THREAT PROFILE

### Attack Overview
**Tactic:** Credential Access  
**Technique:** OS Credential Dumping (LSASS Memory)  
**Sub-Technique:** T1003.001

**Threat Description:**
Adversaries use LSASS.exe (Local Security Authority Subsystem Service) memory dumps to extract NTLM hashes, Kerberos tickets, and plaintext credentials. This is a **critical** technique because:
- Requires only user-level or System-level privileges
- Enables horizontal movement (pass-the-hash attacks)
- Allows vertical escalation (Domain Admin credential extraction)
- Often undetected by legacy EDR tools

**Real-World Examples:**
- Mimikatz (T1040 - Network Sniffing via lsass dumping)
- ProcDump (sysinternals legitimate tool, abused for dumping)
- Comsvcs.dll + rundll32.exe (living-off-the-land technique)

### Attack Chain Context
```
Initial Compromise
    ↓
Privilege Escalation (UAC bypass)
    ↓
LSASS Memory Access ← [YOU DETECT HERE]
    ↓
Credential Extraction (Mimikatz offline)
    ↓
Lateral Movement (Pass-the-Hash to DC)
    ↓
Domain Controller Compromise
```

---

## 2. LOG SOURCES REQUIRED

| Log Source | Sysmon Event | Windows Log | Purpose |
|-----------|--------------|------------|---------|
| Process Creation | EventID 1 | System/Application | Detect rundll32, comsvcs.dll usage |
| Network Connection | EventID 3 | Security | Detect SMB/Kerberos lateral movement post-dump |
| File Created | EventID 11 | System | Detect .dmp file creation (memory dump artifacts) |
| Registry | EventID 12/13 | Security | Detect UAC bypass registry changes |
| Sysmon Registry Object | EventID 13 | N/A | MiniDump parameter registration |

**Configuration Required on Endpoints:**
```xml
<!-- Sysmon config.xml - Process Creation Rules -->
<RuleGroup name="Process Creation" groupRelation="or">
  <EventFilter onmatch="include">
    <Image>C:\Windows\System32\rundll32.exe</Image>
    <Image>C:\Windows\System32\comsvcs.dll</Image>
    <Image>C:\Program Files\Windows NT\Accessories\wordpad.exe</Image> <!-- UAC bypass vector -->
  </EventFilter>
</RuleGroup>

<!-- Windows Audit Policy - Advanced Audit Configuration -->
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
```

---

## 3. DETECTION LOGIC

### Sigma Rule (YAML Format)

```yaml
title: Suspicious Process Execution for LSASS Dump (T1003.001)
id: wazuh-credential-access-lsass-dump-001
status: production
description: |
  Detects suspicious process execution patterns consistent with LSASS memory dumping.
  Uses rundll32.exe, comsvcs.dll (MiniDump function), or werfault.exe.
author: Blue Team Lab
date: 2024-06-20
modified: 2024-06-20

logsource:
  product: windows
  service: sysmon

detection:
  selection_rundll32:
    EventID: 1  # Process Creation
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  
  selection_werfault:
    EventID: 1
    Image|endswith: '\werfault.exe'
    CommandLine|contains: 'lsass.exe'
  
  selection_procdump:
    EventID: 1
    Image|endswith: '\procdump.exe'
    CommandLine|contains: 'lsass'
  
  filter_legitimate:
    Image|contains:
      - 'C:\Program Files\Windows Defender\' # Windows Defender antimalware
      - 'C:\Program Files\Sentry\' # Sentry EDR
  
  condition: (selection_rundll32 or selection_werfault or selection_procdump) and not filter_legitimate

falsepositives:
  - Legitimate memory dump tools (procdump) used by Microsoft/vendor support
  - Authorized backup/archival tools accessing lsass memory
  - Windows error reporting legitimate crashes (werfault)

level: critical

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003  # OS Credential Dumping (parent)
  - detection.endpoint
  - severity.critical

references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://www.microsoft.com/security/blog/2015/08/03/windows-10-to-offer-protection-from-credential-theft-and-pass-the-hash/
```

### Elasticsearch Query (for raw log analysis)

```json
{
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "EventID": 1  // Process Creation
          }
        },
        {
          "bool": {
            "should": [
              {
                "query_string": {
                  "query": "Image:*rundll32.exe AND CommandLine:comsvcs.dll"
                }
              },
              {
                "query_string": {
                  "query": "Image:*werfault.exe AND CommandLine:lsass.exe"
                }
              }
            ]
          }
        }
      ],
      "must_not": [
        {
          "query_string": {
            "query": "Image:(\"Windows Defender\" OR \"Sentry\")"
          }
        }
      ]
    }
  }
}
```

---

## 4. FALSE POSITIVE ANALYSIS & MITIGATION

### Identified False Positive Sources

| Scenario | Root Cause | Mitigation | Impact |
|----------|-----------|-----------|--------|
| Windows Update Medic Service | WaaSMedicSvc uses procdump legitimately | Whitelist service.exe parent process | Eliminated 23 daily FP |
| Microsoft Crash Reporting | werfault.exe handles legitimate crashes | Require lsass.exe in command line (not just parent) | Eliminated 12 daily FP |
| AV/EDR Tools (Sentry) | Legitimate memory scanning | Whitelist vendor paths (C:\Program Files\Sentry\) | Eliminated 8 daily FP |
| Autoruns Utility | IT admin monitoring scheduled tasks | Require elevated privileges + unsigned binary | Eliminated 5 daily FP |

### False Positive Reduction Timeline

```
Day 1 (Initial Deployment):
  Total FP/Day: 48
  Fine-tuning: None
  
Day 2-3 (Rule Tuning):
  Added: Whitelist WaaSMedicSvc
  FP/Day: 25 (↓48%)
  
Day 4-5 (Vendor Whitelisting):
  Added: Exclude Windows Defender, Sentry paths
  FP/Day: 6 (↓76%)
  
Day 6-7 (Process Parent Analysis):
  Added: Parent process must not be explorer.exe (user interactive)
  FP/Day: 2 (↓96%)
  
FINAL: 2 FP/Day (98.3% reduction from initial)
```

### Whitelist Configuration

```yaml
# Apply to Wazuh manager: /var/ossec/etc/rules/local_rules.xml
<rule id="100101" level="0">
  <if_sid>100100</if_sid>
  <program_name>WaaSMedicSvc.exe</program_name>
  <description>Legitimate Windows Update service using procdump</description>
</rule>

<rule id="100102" level="0">
  <if_sid>100100</if_sid>
  <path>C:\Program Files\Windows Defender\</path>
  <description>Windows Defender antimalware engine</description>
</rule>
```

---

## 5. INCIDENT RESPONSE WORKFLOW

### Detection → Response Timeline

```
T+0s:    Alert generated in Kibana
T+5s:    SOC analyst receives Slack notification
T+30s:   Analyst reviews raw Sysmon event + process tree
T+1m:    Analyst isolates endpoint (if confirmed malicious)
T+5m:    Threat hunter acquires forensic data
T+15m:  Incident response playbook executed
T+30m:  Root cause determined + lateral movement hunting begins
```

### Step-by-Step Response Procedure

#### **Step 1: Alert Verification (1-2 minutes)**

```bash
# From Kibana, export the alert JSON
{
  "timestamp": "2024-06-20T14:32:15.123Z",
  "rule.id": "wazuh-credential-access-lsass-dump-001",
  "rule.level": "15",  # Critical
  "host.name": "WIN-ENDPOINT-01",
  "process.executable": "C:\\Windows\\System32\\rundll32.exe",
  "process.args": ["rundll32.exe", "C:\\Windows\\System32\\comsvcs.dll", "MiniDump", "lsass.exe"],
  "process.parent.executable": "C:\\Windows\\explorer.exe"  # User-initiated (HIGH RISK)
}

# Verification questions:
# 1. Is parent process explorer.exe or cmd.exe? (malicious)
#    OR is parent WaaSMedicSvc/scheduled task? (benign)
# 2. Is rundll32 unsigned or from unusual path?
# 3. Does timestamp correlate with known maintenance window?

# VERDICT: This is MALICIOUS (user initiated via explorer.exe)
# ACTION: Escalate to Incident Response Team
```

#### **Step 2: Endpoint Isolation (Immediate)**

```powershell
# RDP into Windows endpoint OR use Systems Manager Session Manager

# Disable network interfaces (prevents lateral movement)
ipconfig /all  # Record current config
netsh interface set interface name="Ethernet" admin=disabled

# Verify isolation (should fail)
ping 8.8.8.8  # Should timeout
nslookup google.com  # Should timeout

# DO NOT reboot (may clear volatile memory)
# DO NOT restart services (may overwrite evidence)
```

#### **Step 3: Live Forensic Data Acquisition (5-10 minutes)**

```powershell
# 1. Capture memory dump (must be done BEFORE shutdown)
# Download Belkasoft RAM Capturer or DumpIt
# Run: C:\Tools\DumpIt.exe
# Output: C:\Tools\memdump_<hostname>_<date>.bin

# 2. Collect artifact files
mkdir C:\IR-Evidence\
copy C:\Windows\System32\winevt\Logs C:\IR-Evidence\Windows-Logs\ /S
copy C:\Windows\Temp\*.tmp C:\IR-Evidence\Temp-Files\ /Y
copy C:\Users\*\AppData\Local\Temp\*.tmp C:\IR-Evidence\AppData\ /Y

# 3. Export Sysmon event log
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 10000 | Export-Csv C:\IR-Evidence\sysmon-events.csv

# 4. List running processes at time of alert
tasklist /v > C:\IR-Evidence\tasklist.txt
Get-Process | Export-Csv C:\IR-Evidence\get-process.csv

# 5. Check for credential dumping artifacts
dir C:\Users\*\AppData\Local\*.dmp /S  # .dmp files created by Mimikatz offline
dir C:\Temp\*.dmp /S
dir C:\Windows\Temp\*.dmp /S

# 6. Export evidence to external drive (DO NOT transmit over network yet)
# Use USB 3.0 drive: copy C:\IR-Evidence E:\Backup-Evidence\ /S
```

#### **Step 4: Credential Compromise Assessment (10-15 minutes)**

```bash
# From Domain Controller (or Wazuh manager with DC log access)

# 1. Identify compromised user account (from Windows 4624 logs)
# 4624 = Successful logon
# Look for:
#   - Source IP: <compromised endpoint>
#   - Account Name: <user who ran rundll32>
#   - Logon Type: 2 (interactive) or 3 (network)
#   - Time: Within 5 minutes of lsass dump

# Query in Kibana:
# winlog.event_id:4624 AND host.name:"WIN-ENDPOINT-01" AND timestamp:[2024-06-20T14:30:00 TO 2024-06-20T14:40:00]

# 2. Force immediate password reset for compromised user
# From Domain Controller:
Set-ADUser -Identity <username> -ChangePasswordAtLogon $true

# 3. Check for credential-stuffing via DC logs (4771, 4768 Kerberos events)
# 4771 = Kerberos pre-authentication failed (brute force pattern?)
# 4768 = Kerberos ticket-granting ticket (TGT) requested

# High-risk pattern: TGT requested immediately after lsass dump
# Query: winlog.event_id:(4768 OR 4771) AND timestamp:[T+5min AFTER dump]

# 4. Force re-authentication across all endpoints (optional, disruptive)
# If suspected widespread Mimikatz activity on network
```

#### **Step 5: Lateral Movement Hunting (15-30 minutes)**

```bash
# Hunt for evidence of lateral movement using compromised credentials

# 1. Check for pass-the-hash (PTH) attacks
# PTH uses NTLM authentication without plaintext password
# Event ID: 4624 (Logon Type 3 = Network Logon)
# Look for:
#   - Source IP: Unusual (not user's normal workstation)
#   - Unusual destination (DC, file server, admin workstation)
#   - Time: Immediately after lsass dump (within 5-30 minutes)

# Kibana query:
# winlog.event_id:4624 AND logon_type:3 AND 
# user.name:<compromised_user> AND 
# timestamp:[<dump_time> TO <dump_time>+30min]

# 2. Check for Golden Ticket attacks (forged Kerberos TGT)
# Event ID: 4768 (TGT requested) or 4769 (Service Ticket requested)
# Look for:
#   - Requests from unusual source IP
#   - Requests for high-value targets (DC$, Exchange$, SQL$)
#   - Requests with suspicious encryption types (DES, RC4 from non-legacy systems)

# 3. Check for new account creation (T1136.001 Domain Account)
# Event ID: 4720 (User account created)
# Look for accounts created within 1 hour after lsass dump

# Kibana query:
# winlog.event_id:4720 AND timestamp:[<dump_time> TO <dump_time>+1h]
# Review: Account properties, creator account, creation time

# 4. Check for Group Policy modifications (T1484 Domain Policy Modification)
# Event ID: 5136 (Directory Service Object modified)
# Look for: GPO changes, domain policy changes, Group membership changes

# 5. Summary Report
# If lateral movement detected:
#   - ESCALATE to CSIRT (incident response team)
#   - BEGIN active hunt for backdoors/persistence mechanisms
#   - Consider full network segmentation + endpoint isolation strategy
# If NO lateral movement detected:
#   - Incident may be contained
#   - Complete post-incident review in 24-48 hours
```

#### **Step 6: Evidence Preservation & Chain of Custody**

```bash
# Store forensic evidence securely for potential legal proceedings

# 1. Hash all evidence files (SHA256)
Get-FileHash C:\IR-Evidence\* -Algorithm SHA256 | Export-Csv C:\IR-Evidence\file-hashes.csv

# 2. Create evidence manifest
cat > C:\IR-Evidence\MANIFEST.txt << EOF
INCIDENT: LSASS Memory Dump (T1003.001)
Date Occurred: 2024-06-20T14:32:15Z
Endpoint: WIN-ENDPOINT-01 (10.0.2.20)
Affected User: domain\jsmith
Collected: 2024-06-20T14:45:00Z
Collected By: [Your Name] - Blue Team SOC
Evidence Location: C:\IR-Evidence\
Chain of Custody: Stored on encrypted USB, physically locked

Files:
- memdump.bin (3.2 GB) - SHA256: <hash>
- windows-logs/ (collected via Get-WinEvent)
- sysmon-events.csv (45,000 rows)
- tasklist.txt (process snapshot)
- file-hashes.csv (integrity verification)
EOF

# 3. Encrypt and secure evidence
# Use BitLocker or 7-zip with AES-256
7z a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -p<password> C:\IR-Evidence.7z C:\IR-Evidence\

# 4. Store on encrypted, physically secured USB drive
# Label: "INCIDENT EVIDENCE - CONFIDENTIAL"
# Location: Physical evidence locker (logged access)
```

---

## 6. RECOVERY & HARDENING

### Immediate Actions (24 hours)

```
☑ Force password reset for affected user
☑ Revoke all active Kerberos tickets
☑ Review Domain Admin group membership (remove unauthorized accounts)
☑ Scan all endpoints for Mimikatz/credential dumping tools
☑ Enable LSA Credential Guard on affected endpoints
☑ Review and strengthen audit logging configuration
☑ Notify affected users of potential credential compromise
```

### Short-term Hardening (1 week)

```bash
# 1. Enable LSA Protection (Windows 8.1+)
# Prevents non-system processes from accessing lsass.exe memory
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 1

# 2. Implement Remote Credential Guard (if using RDP)
# Prevents credential forwarding to compromised RDP target
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0

# 3. Enable Audit Credential Validation (Domain Admin accounts only)
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# 4. Increase Kerberos ticket encryption from RC4 to AES-256
# Group Policy > Computer Config > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Network Security: Configure encryption types allowed for Kerberos"
# Set to: AES128_HMAC_SHA1, AES256_HMAC_SHA1 (DISABLE RC4, DES)

# 5. Restrict LSASS access to only system processes
# AppLocker rule or WDAC (Windows Defender Application Control)
# Block: rundll32.exe, werfault.exe, procdump.exe access to lsass.exe
```

### Long-term Mitigations (ongoing)

| Mitigation | Implementation | Effort | Effectiveness |
|-----------|-----------------|--------|----------------|
| **Credential Guard** | Windows Device Guard feature | Medium | High (prevents credential theft) |
| **Tiered Access Model** | Separate admin tiers (T0/T1/T2) | High | Critical (limits lateral movement) |
| **Privileged Access Workstation (PAW)** | Isolated admin workstations | High | Critical (prevents user interaction compromise) |
| **EDR with Behavior Heuristics** | Deploy advanced EDR (Crowdstrike/Sentinel One) | Medium | High (detects memory access patterns) |
| **Network Segmentation** | Micro-segmentation of critical systems | High | High (limits lateral movement reach) |
| **Password Policy Hardening** | Disable NTLM, enforce kerberos only | Medium | Medium (prevents pass-the-hash, but requires AES) |

---

## 7. VALIDATION & TESTING

### Sigma Rule Testing

```bash
# Use Sigma CLI to validate rule syntax
sigma check rules/credential-access/lsass-dump.yml
# Output: Valid YAML, 1 detection pattern, 1 filter

# Convert to other SIEM formats
sigma convert -t sysmon rules/credential-access/lsass-dump.yml
sigma convert -t es-qs rules/credential-access/lsass-dump.yml

# Test against sample dataset
sigma backend -t wazuh -r rules/credential-access/lsass-dump.yml sample-logs/windows-sysmon.json
# Output: 3/5 test events matched (expected: 5/5)
# Action: Refine rule to catch all variants
```

### Live Fire Testing (Safe Lab Environment)

```powershell
# IMPORTANT: Only run in isolated lab environment, never on production systems

# Test 1: Rundll32 + Comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID> C:\Temp\lsass.dmp
# Expected: Alert fires with severity=critical

# Test 2: Procdump (Sysinternals legitimate tool, abused)
procdump.exe -ma lsass.exe C:\Temp\lsass.dmp
# Expected: Alert fires with severity=critical

# Test 3: Werfault (Windows error reporting)
werfault.exe -u -p <PID> -s <errorCode>
# Expected: Alert MAY fire (depends on filter tuning)
# Verify: Manual review shows benign (can whitelist if desired)

# Results Documentation
# ✓ Test 1: PASSED (alert fired, severity=critical)
# ✓ Test 2: PASSED (alert fired, severity=critical)
# ⚠ Test 3: FALSE POSITIVE (alert fired, but benign - add to whitelist)
```

---

## 8. ALERT DASHBOARD & MONITORING

### Kibana Dashboard Example

```json
{
  "dashboard_id": "wazuh-lsass-dump-overview",
  "title": "LSASS Dump Detection - Threat Overview",
  "panels": [
    {
      "title": "Alert Timeline",
      "visualization_type": "time_series",
      "query": "rule.id:wazuh-credential-access-lsass-dump-001",
      "time_range": "24h"
    },
    {
      "title": "Top Affected Endpoints",
      "visualization_type": "bar_chart",
      "query": "rule.id:wazuh-credential-access-lsass-dump-001 | stats count by host.name",
      "top_results": 10
    },
    {
      "title": "Alert Severity Distribution",
      "visualization_type": "pie_chart",
      "query": "rule.id:wazuh-credential-access-lsass-dump-001 | stats count by rule.level"
    },
    {
      "title": "Raw Alert Details (Recent 10)",
      "visualization_type": "table",
      "columns": ["timestamp", "host.name", "user.name", "process.command_line", "rule.level"]
    }
  ]
}
```

### Alert Noise & Tuning Metrics

```
Week 1 Deployment:
  Total Alerts: 48/day
  FP Rate: 97.9% (47 false positives)
  TP Rate: 2.1% (1 true positive - test event)
  Action: Implement whitelisting
  
After Tuning (Week 2):
  Total Alerts: 3/day
  FP Rate: 33% (1 false positive)
  TP Rate: 67% (2 true positives - confirmed malicious)
  Effectiveness: 96% FP reduction
  
Production Baseline (Week 4+):
  Expected: 1-2 alerts/week (legitimate tools)
  Alert Response Time: <5 minutes
  Confirmation Time: <15 minutes
```

---

## 9. ARTIFACTS & INDICATORS OF COMPROMISE (IOCs)

### File-Based Indicators

```
Dumped Credentials Files:
  - *.dmp files in Temp directories
  - mimikatz.exe output files (*_sekurlsa.txt)
  - registry hive dumps (SAM, SYSTEM, SECURITY)

Location Patterns:
  - C:\Temp\
  - C:\Users\*\AppData\Local\Temp\
  - C:\Windows\Temp\
  - C:\Windows\System32\config\
```

### Process-Based Indicators

```
Suspicious Parent-Child Relationships:
  explorer.exe → cmd.exe → rundll32.exe (USER INTERACTION)
  svchost.exe → cmd.exe (SYSTEM SERVICE misuse)
  dwm.exe → rundll32.exe (UNUSUAL)

Suspicious Command Line Parameters:
  rundll32.exe ... comsvcs.dll, MiniDump
  procdump.exe ... lsass.exe
  werfault.exe -u <PID>
  reg query HKLM\SAM
  reg query HKLM\SYSTEM
```

### Network-Based Indicators

```
Post-Compromise Lateral Movement:
  Event ID: 4624 (Logon Type 3 = Network)
  Source: Compromised endpoint
  Destination: DC, file servers, admin workstations
  Time: <30 min after lsass dump
  
Kerberos Anomalies:
  4768 (TGT requested from unusual IP)
  4769 (Service ticket requested for unusual targets)
  4771 (Pre-auth failed - brute force pattern)
```

---

## 10. DOCUMENTATION & LINKS

### References
- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft Security Blog - Credential Theft](https://www.microsoft.com/security/blog/)
- [OWASP — Credential Dumping](https://cheatsheetseries.owasp.org/)
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma)

### Related Playbooks (in this repo)
- [Brute Force Detection (T1110.001)](./brute-force-detection-t1110.001.md)
- [Lateral Movement - WMI (T1047)](./lateral-movement-wmi-t1047.md)
- [Privilege Escalation (T1548.002)](./privilege-escalation-uac-bypass-t1548.md)

### Tools & Skills Required
- Sysmon Event Log Analysis
- Elasticsearch Query Language (EQL)
- Windows Event ID Interpretation
- Kerberos Protocol Understanding
- Active Directory Security Assessment

---

## END OF PLAYBOOK TEMPLATE

---

# HOW TO USE THIS TEMPLATE

For each detection rule you create during Weeks 2-7:

1. **Copy this template** to `playbooks/<rule_name>-<ttps>.md`
2. **Fill out all 10 sections** (adjust detail level to your environment)
3. **Test against sample attack logs** (included in `atomic-red-team/` folder)
4. **Document false positives** with remediation timeline
5. **Create Kibana dashboard** visualizing alerts
6. **Store JSON export** for reproducibility
7. **Link in GitHub README** for easy discovery
8. **Submit as PR** for peer review

---

## PLAYBOOK NAMING CONVENTION

```
Format: <tactic>-<technique>-<subtechnique>.md
Examples:
  - credential-access-lsass-dump-t1003.001.md
  - credential-access-brute-force-t1110.001.md
  - persistence-registry-run-keys-t1547.001.md
  - privilege-escalation-uac-bypass-t1548.002.md
  - lateral-movement-wmi-process-creation-t1047.md
```

---

## QUICK REFERENCE CHECKLIST

For each playbook, ensure:

- [ ] Threat profile section explains attack motivation + real-world examples
- [ ] Log sources specified with exact event IDs + configuration needed
- [ ] Sigma rule included (YAML formatted, validated syntax)
- [ ] False positive analysis documented with timeline
- [ ] Incident response steps numbered, actionable, time-estimated
- [ ] Credential compromise assessment section (if applicable)
- [ ] Lateral movement hunting queries provided
- [ ] Recovery steps concrete + testable
- [ ] Validation/testing section with live-fire results
- [ ] Kibana dashboard JSON exported
- [ ] Related playbooks cross-linked

---

**Total Time to Complete One Playbook:** 4-6 hours  
**Target for Weeks 2-7:** 1-2 playbooks per week (15 playbooks total)  
**Publication Value:** Each playbook = 1-2 hours of SOC research saved per implementation

