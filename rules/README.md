# Detection Rules

This directory contains custom Sigma detection rules, organized by MITRE ATT&CK tactic.

## Structure

```
rules/
├── credential-access/
│   ├── lsass-dump-t1003.001.yml
│   └── brute-force-t1110.001.yml
├── persistence/
│   └── registry-run-keys-t1547.001.yml
├── defense-evasion/
│   └── rundll32-proxy-t1218.014.yml
├── lateral-movement/
│   └── wmi-process-creation-t1047.yml
└── process-execution/
    └── (add new rules here as you write them)
```

## Naming Convention

```
<tactic>-<short-description>-<technique-id>.yml
```

Examples:
- `credential-access/lsass-dump-t1003.001.yml`
- `persistence/registry-run-keys-t1547.001.yml`

## Rule Status

Each rule has a `status` field:
- `experimental` — newly written, not yet validated against live traffic
- `test` — validated against Atomic Red Team simulation, watching for false positives
- `production` — tuned, false-positive rate measured and accepted

## Converting Sigma to Wazuh Rules

Sigma rules are vendor-neutral. To actually run them in Wazuh, convert with `sigma-cli`:

```bash
pip install sigma-cli
sigma convert -t wazuh rules/credential-access/lsass-dump-t1003.001.yml
```

Or hand-translate critical rules into Wazuh's native `local_rules.xml` format
(see `configs/local_rules.xml` in this repo for examples already converted).

## Testing a Rule

1. Deploy the rule (Sigma → Wazuh conversion, or native XML)
2. Trigger the matching Atomic Red Team test (see `atomic-red-team/` folder)
3. Confirm the alert fires in the Wazuh dashboard
4. Document false positive rate over 48-72 hours before marking `production`

## Adding a New Rule

1. Copy an existing rule as a template
2. Fill in `title`, `id` (generate a new UUID), `description`, `detection` logic
3. Add `falsepositives` — be honest about what will trigger this incorrectly
4. Set `level` based on real risk (not everything is `critical`)
5. Add MITRE ATT&CK `tags`
6. Write a matching playbook in `/playbooks` (see playbook template)
