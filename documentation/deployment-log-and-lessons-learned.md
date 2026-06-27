# Deployment Log — Live Build Session

This document records what actually happened during deployment, including
real problems encountered and how they were fixed. Unlike the planning
documents elsewhere in this repo, this is a ground-truth account — useful
for the "Lessons Learned" section of the README and for anyone repeating
this build.

## Environment

- **Region:** AWS eu-north-1 (Stockholm)
- **Manager:** m7i-flex.large (8GB RAM), Ubuntu 22.04.5 LTS, private IP 10.0.1.10
- **Endpoint 1:** t3.micro, Ubuntu 26.04 LTS ("UBUNTU-TARGET-01"), 10.0.1.251
  - Note: intended 22.04, AMI selector defaulted to 26.04 on relaunch. Documented
    here rather than silently treated as 22.04 — see Lesson 3 below.
- **Endpoint 2:** c7i-flex.large (4GB RAM), Windows Server 2022 Datacenter
  ("WIN-TARGET-01"), 10.0.1.138

## What's Confirmed Working

- Wazuh Manager, Indexer, and Dashboard installed and running on a single node
- TLS certificates generated via `wazuh-certs-tool.sh` and correctly placed for
  manager, indexer, and dashboard
- Indexer security initialized (`indexer-security-init.sh`), cluster health GREEN
- Both agents registered, auto-enrolled, and showing `Active` status
- Sysmon installed on the Windows endpoint with the SwiftOnSecurity config
- Custom Sigma-derived rules (9 rules, IDs 100100–100141) loaded into
  `local_rules.xml`, confirmed `enabled` via the Wazuh API, and confirmed
  matching correctly against realistic event structures in `wazuh-logtest`
- **Filebeat → Indexer pipeline**, once fixed (see Lesson 2), is shipping real
  alerts into a genuine `wazuh-alerts-4.x-*` index, browsable in the dashboard
- Built-in Wazuh/Sysmon rules are firing on real attacker-relevant behavior from
  the Windows endpoint, with correct MITRE ATT&CK tagging, for example:
  - Rule 92217 — "Executable dropped in Windows root folder" — **T1570
    Lateral Tool Transfer**
  - Rule 92066 — "Suspicious binary location launched by PowerShell" —
    **T1059.001 PowerShell**
  - Rule 92031 — "Discovery activity executed" — **T1087 Account Discovery**
  - Rule 510 — rootcheck "Trojaned version of file detected" (Ubuntu)
  - Rule 5402 — "Successful sudo to ROOT executed" — **T1548.003**

This is real, end-to-end, MITRE-mapped detection working in the live
environment — confirmed via direct Elasticsearch queries and the dashboard UI.

## Known Open Issue

The **custom rules (100100–100141)** pass `wazuh-logtest` cleanly against both
synthetic and realistic event payloads, including the exact raw Sysmon message
captured from a live LSASS-dump attempt. However, repeated live attempts to
trigger rule 100100 (LSASS dump via rundll32+comsvcs.dll) and rule 100130
(rundll32 proxy execution via `javascript:`) did not produce a matching alert
in the live system, despite:

- Sysmon logging the real event locally on the endpoint (confirmed via
  `Get-WinEvent`)
- The agent actively monitoring the Sysmon operational channel (confirmed in
  `ossec.conf` and agent logs)
- The agent being connected and actively forwarding *other* Sysmon EventID 1
  events successfully (confirmed via real alerts for `net.exe`, `SecEdit.exe`,
  `wmiprvse.exe` reaching the manager and triggering built-in rules)
- The custom rules being loaded, enabled, and confirmed live via the Wazuh API

This was investigated extensively (certificate paths, indexer connector
config, Sysmon log channel registration, rule group dependencies, rule ID
collisions, EPS limits were considered) without a conclusive root cause.
**This is flagged as a genuine open item, not papered over.** The most likely
remaining hypothesis is a subtlety in how `wazuh-analysisd` evaluates custom
field-based rules against live `windows_eventchannel` events versus how
`wazuh-logtest` replays them — worth revisiting with a packet-level capture
of agent-to-manager traffic, or by testing whether the same rule fires for a
non-rundll32 process to isolate whether the issue is process-specific or
field-specific.

## Real Bugs Found and Fixed (worth documenting in the main README)

### Lesson 1 — Sysmon events never reach the manager without an explicit `<localfile>` block

The default `ossec.conf` shipped by the Windows MSI agent only monitors the
`Application`, `Security`, and `System` Windows Event Log channels. Sysmon
writes to its own separate channel, `Microsoft-Windows-Sysmon/Operational`,
which must be added explicitly:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Without this, Sysmon can be fully installed and logging correctly, and the
Wazuh agent can be connected and "Active," while zero Sysmon telemetry ever
reaches the SIEM. This is an easy, common mistake when integrating Sysmon
with Wazuh and deserves a callout in any deployment guide.

### Lesson 2 — The Filebeat shipper is a separate package the Wazuh installer does not pull in automatically

Installing `wazuh-manager` gets you local alert generation
(`/var/ossec/logs/alerts/alerts.json`) and a correctly pre-filled
`<indexer>` block in `ossec.conf` referencing `/etc/filebeat/certs/...` — but
the actual `filebeat` package, its Wazuh-specific module, and the
`wazuh-template.json` index template are **not installed automatically**.
The manager will run, generate real alerts, and *look* healthy, while the
alerts silently never reach Elasticsearch, because nothing is reading
`alerts.json` and shipping it.

Fix sequence:
```bash
sudo apt install -y filebeat
sudo curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/<major.minor>/tpl/wazuh/filebeat/filebeat.yml
sudo curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz -o /tmp/wazuh-filebeat-module.tar.gz
sudo tar -xzf /tmp/wazuh-filebeat-module.tar.gz -C /usr/share/filebeat/module
sudo curl -s https://raw.githubusercontent.com/wazuh/wazuh/v<version>/extensions/elasticsearch/7.x/wazuh-template.json -o /etc/filebeat/wazuh-template.json
echo "admin" | sudo filebeat keystore add username --stdin --force
echo "admin" | sudo filebeat keystore add password --stdin --force
sudo chmod 600 /etc/filebeat/filebeat.yml
sudo systemctl enable --now filebeat
```

Two additional gotchas hit during this fix:
- The packages.wazuh.com path uses the **exact minor version** (e.g. `/4.14/`),
  not the generic `/4.x/`, for the filebeat.yml template — a generic path
  returned a silent S3 "Access Denied" XML response that looked superficially
  like a valid download.
- The downloaded `filebeat.yml` defaults to connecting to `127.0.0.1:9200`,
  but the TLS certificate generated by `wazuh-certs-tool.sh` is only valid for
  the node's real IP (e.g. `10.0.1.10`), causing a `x509: certificate is valid
  for X, not 127.0.0.1` failure. Point Filebeat's `hosts:` entry at the real
  IP, not localhost.

### Lesson 3 — AWS Console's AMI Quick-Start selector can silently revert OS version on relaunch

Multiple times during this build, re-opening the EC2 launch wizard reset the
AMI selection back to the newest available LTS release instead of preserving
a previously chosen older version (e.g., 22.04 → 26.04 for Ubuntu). This is
easy to miss since the tile still says "Ubuntu" and looks correct at a
glance. **Always verify the exact AMI/version string in the final review step
before clicking Launch**, not just the OS family.

### Lesson 4 — `m7i-flex.large` / `c7i-flex.large` can be free-tier eligible even when `t3.large` is not

Account-specific free tier eligibility doesn't always map to the "obvious"
instance family. Running `aws ec2 describe-instance-types --filters
"Name=free-tier-eligible,Values=true"` revealed `m7i-flex.large` (8GB RAM)
and `c7i-flex.large` (4GB RAM) were both free-tier eligible on this account,
while `t3.large` was not — letting the manager run with adequate RAM (8GB)
for Wazuh+Indexer+Dashboard at zero cost, instead of falling back to the
1GB `t3.micro`, which would not have been sufficient.

### Lesson 5 — Security groups need explicit rules for *both* enrollment (1515) and data (1514) ports, in *both* directions

A common oversight: allowing outbound 1514/TCP from the endpoint security
group is not sufficient for first-time agent enrollment, which happens over
1515/TCP. An agent can appear to "hang" on `Unable to connect to enrollment
service` indefinitely if only the data port is open. Both ports need
explicit outbound rules from the endpoint SG and inbound rules on the
manager SG.

### Lesson 6 — EC2 Instance Connect needs its own inbound/outbound SSH allowance, distinct from your own IP's SSH access

For private-subnet instances, EC2 Instance Connect Endpoint requires the
target security group to explicitly allow **outbound** TCP 22 to the VPC CIDR
— a rule easy to forget when a security group was designed around "agents
only need outbound 1514/443/53." The error surfaced as a generic "endpoint
security group has no outbound rules to support TCP:22" message from the
AWS console, which is a clear, specific, actionable signal once you know
where to look.

## Cost Notes

Running m7i-flex.large + t3.micro + c7i-flex.large simultaneously, all
free-tier eligible on this account, kept this entire multi-hour build session
at effectively $0 in EC2 compute cost. Worth highlighting in the README's
cost section as a more realistic alternative to the original t3.large-based
estimate, contingent on checking actual free-tier eligibility per AWS account
rather than assuming standard `t3.*` defaults.
