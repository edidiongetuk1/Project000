# Contributing

Contributions are welcome — new Sigma rules, playbook improvements, bug fixes
in the deployment scripts, or better false-positive tuning.

## How to Contribute

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/new-detection-rule`
3. Make your changes
4. Test your changes (see below)
5. Submit a pull request describing what you changed and why

## Adding a New Detection Rule

1. Add the Sigma YAML file under the correct `rules/<tactic>/` folder
2. Follow the naming convention in `rules/README.md`
3. If converting to a native Wazuh rule, add it to `configs/local_rules.xml`
   using a rule ID in the 100100-100199 range (or the next free block)
4. Test the rule against a real or simulated attack (Atomic Red Team if possible)
5. Document false positive behavior honestly
6. Add a playbook in `/playbooks` using `PLAYBOOK_TEMPLATE.md` as a starting point

## Reporting Issues

If you find a bug in a deployment script or a rule that doesn't fire as
expected, open an issue with:
- What you expected to happen
- What actually happened
- Relevant logs (`/var/ossec/logs/ossec.log`, alert JSON, etc.)
- Your environment (Wazuh version, OS versions)

## Code of Conduct

Be respectful. This is a learning-focused project — questions from beginners
are welcome, not just polished PRs.
