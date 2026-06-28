# Playbook: WMI-Spawned Executable Drop in Windows Root Folder — T1570

**Rule ID:** 92217 (Wazuh built-in Sysmon ruleset)
**Author:** Blue Team Lab
**Date Detected:** 2026-06-27
**Status:** Production — confirmed firing on live traffic
**Severity:** Medium (Wazuh level 6)
**Priority:** P3 (review within 4 hours)

---

## 1. Threat Profile

### Attack Overview

**Tactic:** Lateral Movement
**Technique:** T1570 — Lateral Tool Transfer

**Threat Description:**

Adversaries who have already gained a foothold on one host often need to move
tools, payloads, or staging files onto that host (or onward to another host)
to continue their operation — installing a backdoor, staging exfiltration
tooling, or dropping a second-stage payload. When this file-drop activity
originates from `WmiPrvSE.exe` (the Windows Management Instrumentation
provider host process) and lands in a sensitive system directory rather
than a normal user-writable location, it is a meaningful signal: legitimate
user-initiated downloads rarely originate from WMI, and legitimate WMI
activity rarely needs to write executables into a Windows root-level
system path.

This is not, by itself, proof of compromise — Windows itself uses WMI
heavily for legitimate inventory, patching, and management tasks (as seen
in this very detection, detailed below). The value of this rule is as a
**triage signal**: every hit deserves a quick look at what was actually
written and by what parent process chain, rather than being dismissed or
treated as a confirmed incident by default.

**Real-World Context:**

T1570 is commonly observed in: post-exploitation toolkits transferring
Mimikatz/Cobalt Strike beacons between hosts; ransomware operators staging
encryptors across a network after initial access; and legitimate IT/SCCM
tooling, which is exactly the false-positive case this lab's live detection
demonstrates (see Section 4).

---

## 2. Log Sources Required

| Log Source | Sysmon Event | Purpose |
|---|---|---|
| Process Creation | EventID 1 | Identify the parent process spawning the file write (WmiPrvSE.exe) |
| File Create | EventID 11 | Captures the actual file write — path, filename, timestamp |
| Sysmon Operational Channel | `Microsoft-Windows-Sysmon/Operational` | The channel both event types are sourced from |

**Configuration required on the endpoint** (already applied in this lab):

```xml
<!-- Wazuh agent ossec.conf -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Without this `<localfile>` block, Sysmon can be fully installed and logging
locally while zero of its telemetry ever reaches the SIEM — this was a real
gap found and fixed during this lab's build (see
`documentation/deployment-log-and-lessons-learned.md`, Lesson 1).

---

## 3. Detection Logic

This is a **Wazuh built-in rule** (part of the default Sysmon ruleset
shipped with Wazuh 4.14.5, file `0830-sysmon_id_11.xml`), not a custom rule
written for this lab. It is documented here because it is the first
detection in this lab to be **confirmed firing on real, live traffic** with
correct MITRE tagging — making it the strongest available evidence of the
pipeline working end-to-end.

**Underlying logic (built-in rule, paraphrased):**

```
EventID: 11 (File Create)
Image: WmiPrvSE.exe (or similar WMI provider host)
TargetFilename: matches a Windows root-level system path pattern
  (e.g. C:\Windows\Temp\..., C:\Windows\...)
condition: file creation event where the writing process is the
  WMI provider host AND the target path falls in a root-level
  system directory
```

**Actual fired alert (real data from this lab, 2026-06-27):**

```json
{
  "rule": {
    "level": 6,
    "description": "Executable dropped in Windows root folder",
    "id": "92217",
    "mitre": {
      "id": ["T1570"],
      "tactic": ["Lateral Movement"],
      "technique": ["Lateral Tool Transfer"]
    }
  },
  "agent": { "id": "002", "name": "WIN-TARGET-01", "ip": "10.0.1.138" },
  "data": {
    "win": {
      "eventdata": {
        "image": "C:\\Windows\\system32\\wbem\\wmiprvse.exe",
        "targetFilename": "C:\\Windows\\Temp\\4B7544E2-91D0-4928-9421-208F22642BD4\\SysprepProvider.dll",
        "user": "NT AUTHORITY\\SYSTEM"
      }
    }
  }
}
```

---

## 4. False Positive Analysis (Real, Observed)

This is the genuinely interesting part of this playbook: the alert above is
a **confirmed false positive**, and walking through why illustrates exactly
the kind of triage judgment this rule exists to prompt.

**What actually happened:** the Windows Server 2022 instance's built-in
**Sysprep** and **Windows Update** machinery periodically extracts a batch
of provider DLLs (`SysprepProvider.dll`, `TransmogProvider.dll`,
`UnattendProvider.dll`, `VhdProvider.dll`, `WimProvider.dll`, and others)
into a temporary working directory under `C:\Windows\Temp\` as part of
routine OS servicing. This legitimately runs **through WMI** (`wmiprvse.exe`
is the parent), and the destination is technically under `C:\Windows\`,
which matches this rule's "root folder" pattern.

| Indicator | Value | Verdict |
|---|---|---|
| Parent process | `wmiprvse.exe`, `NT AUTHORITY\SYSTEM` | Expected for OS servicing tasks |
| File names | `SysprepProvider.dll`, `UnattendProvider.dll`, etc. | Recognizable Microsoft component names, not arbitrary/random |
| Destination | `C:\Windows\Temp\{GUID}\` | A GUID-named temp subdirectory — typical of installer/servicing staging, not a typical attacker drop location |
| Volume | 6+ similar file creates within under 1 second | Consistent with a batch extraction operation, not a single deliberate drop |
| Timing | 08:41:16–08:41:17, shortly after agent install | Consistent with normal post-install OS housekeeping |

**Verdict: Benign.** This is routine Windows servicing activity, not an
attacker staging tools.

**Recommended whitelist refinement** (not yet applied in this lab — flagged
as a next step):

```xml
<rule id="100150" level="0">
  <if_sid>92217</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)(SysprepProvider|TransmogProvider|UnattendProvider|VhdProvider|WimProvider)\.dll$</field>
  <description>Whitelisted: known Windows Sysprep/servicing provider DLL extraction (suppressed)</description>
</rule>
```

This single whitelist rule, once added, would eliminate this specific class
of false positive while leaving the underlying T1570 detection intact for
genuinely suspicious file drops (arbitrary executable names, non-system
destination paths, or non-SYSTEM user context).

---

## 5. Incident Response Workflow

### If a future T1570 alert does NOT match the whitelisted Sysprep pattern above:

#### Step 1 — Triage (2–5 minutes)

Pull the full event and check, in order:
1. **Parent process and user context** — is it `wmiprvse.exe` running as
   `SYSTEM`, or something else (a user-spawned PowerShell session calling
   WMI, for instance, is a very different risk profile)
2. **Filename** — does it match a known Microsoft component, or is it an
   arbitrary/random-looking name?
3. **Destination path** — `C:\Windows\Temp\{GUID}\` (low risk pattern, as
   seen here) versus `C:\Windows\System32\` directly or
   `C:\Windows\debug\` (higher risk — direct system32 writes deserve more
   scrutiny)
4. **File hash** (if available from a paired EventID 1) — check against
   VirusTotal or internal allowlists

#### Step 2 — If suspicious, isolate and collect (5–10 minutes)

```powershell
# Capture the dropped file before further action, if it still exists
Copy-Item "<TargetFilename>" -Destination "C:\IR-Evidence\" -Force
Get-FileHash "<TargetFilename>" -Algorithm SHA256

# Check what else WmiPrvSE.exe has done recently
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 |
  Where-Object {$_.Message -like "*wmiprvse*"} |
  Select-Object TimeCreated, Id, Message
```

#### Step 3 — Hunt for lateral movement context (10–15 minutes)

Since T1570 implies tooling moved *between* hosts, check:
- Network logon events (4624, Logon Type 3) around the same timestamp, on
  this host and any host it has recently authenticated to
- Whether the dropped file was subsequently executed (a follow-up EventID 1
  with the same `TargetFilename` as the `Image` field)

#### Step 4 — Document and close

Log the verdict (benign servicing activity vs. confirmed lateral tool
transfer) and, if benign, add the specific filename pattern to the
whitelist rule above rather than leaving the noise unaddressed.

---

## 6. Validation Performed

| Check | Result |
|---|---|
| Sysmon EventID 11 logged locally on Windows endpoint | ✅ Confirmed via `Get-WinEvent` |
| Event forwarded by Wazuh agent to manager | ✅ Confirmed — agent actively connected, other EventID 1/11 events reaching manager |
| Manager rule engine matched built-in rule 92217 | ✅ Confirmed in `alerts.json` |
| MITRE ATT&CK tagging correct (T1570, Lateral Movement, Lateral Tool Transfer) | ✅ Confirmed |
| Alert shipped to indexer via Filebeat | ✅ Confirmed — visible in `wazuh-alerts-4.x-2026.06.27` index |
| Alert visible in Wazuh Dashboard UI | ✅ Confirmed — 80 total hits for WIN-TARGET-01 at time of writing, including multiple instances of this rule |

This is the most thoroughly end-to-end-validated detection in this lab to
date — useful as the reference example for what a "fully working" pipeline
artifact looks like when documenting other rules.

---

## 7. Related Findings (Cross-Reference)

- See `documentation/deployment-log-and-lessons-learned.md` for the full
  build log, including the Filebeat pipeline gap that initially prevented
  *any* alert (including this one) from reaching the indexer, and how it
  was diagnosed and fixed.
- The lab's **custom** Sigma-derived rules (T1003.001 LSASS dump,
  T1218.014 rundll32 proxy execution — see `rules/credential-access/` and
  `rules/defense-evasion/`) pass `wazuh-logtest` validation against
  realistic event payloads but have not yet been confirmed firing on live
  traffic, despite the underlying Sysmon events being confirmed reaching
  the manager successfully for other processes. This is documented as an
  open investigation, not a resolved success — see the deployment log for
  the full diagnostic trail attempted so far.
