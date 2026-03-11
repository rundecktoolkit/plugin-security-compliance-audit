# Security & Compliance Scanner Framework

## 1. Framework Architecture
- `JobSecurityAuditService` is the scanning orchestrator.
- Rule metadata (`RULE_DEFS`) is modular and drives detection, severity defaults, remediation, descriptions, and why-it-matters text.
- Scan flow:
  1. Load job definitions.
  2. Collect script/config/targeting contexts.
  3. Execute rule checks.
  4. Execute policy-as-code checks from YAML.
  5. Score and classify risk.
  6. Persist findings to execution metadata and logs.
- UI split:
  - `Security & Compliance` scan page: run scan + findings + notify.
  - Project Configure `Security & Compliance` tab: policy/rules/notification settings.

## 2. Rule Engine Design
- Rule definitions are map entries keyed by `ruleId`.
- Each rule contains:
  - `defaultSeverity`
  - `group`
  - `description`
  - `whyMatters`
  - `remediation`
- Rule toggles and severity overrides are loaded from project properties:
  - `project.plugin.JobSecurityAudit.rules.enabled.<group>`
  - `project.plugin.JobSecurityAudit.rules.severity.<ruleId>`
- Implemented checks include:
  - `RUN_AS_ROOT`
  - `SUDO_WITHOUT_RESTRICTIONS`
  - `UNSAFE_SHELL_PIPE_EXECUTION`
  - `WILDCARD_DESTRUCTIVE_COMMAND`
  - `EXPOSED_ENVIRONMENT_VARIABLE_SECRET`
  - `PLAINTEXT_FILE_CREDENTIALS`
  - `UNPINNED_GIT_REPOSITORY`
  - `UNRESTRICTED_NODE_TARGETING`
  - plus legacy secret checks and policy checks.

## 3. Example Rule Implementation
- `WILDCARD_DESTRUCTIVE_COMMAND`
  - Detection: regex over command/script context for destructive wildcard patterns.
  - Example match: `rm -rf *`, `rm -rf /var/*`.
  - Severity: default `CRITICAL` (configurable).
  - Output includes masked snippet, description, why-it-matters, remediation.

## 4. Policy-as-Code Engine Design
- Policy YAML stored in project property:
  - `project.plugin.JobSecurityAudit.policyYaml`
- Parsed using YAML parser into `policy` object.
- Supported policy checks:
  - Privilege Policy
  - Execution Scope Policy
  - Secrets Management Policy
  - Change Control Policy
  - Supply Chain Policy
  - Logging and Audit Policy
  - Input Validation Policy
  - Environment Segmentation Policy
  - Blast Radius Policy
  - Script Integrity Policy
- Example YAML:

```yaml
policy:
  max_nodes: 20
  allow_root_execution: false
  require_vault_secrets: true
  require_git_pinning: true
```

## 5. Risk Scoring Algorithm
- Severity points:
  - `CRITICAL = 25`
  - `HIGH = 15`
  - `MEDIUM = 8`
  - `LOW = 3`
- Aggregate score is capped at `100`.
- Risk levels:
  - `0-30: Low`
  - `31-60: Medium`
  - `61-85: High`
  - `86-100: Critical`
- Summary includes `riskScore`, `riskLevel`, and per-severity counts.

## 6. API / Scanning Workflow
- Scan workflow:
  - `POST /project/{project}/jobSecurity/scan`
  - `GET /project/{project}/jobSecurity/results/latest`
  - `GET /project/{project}/jobSecurity/results/{executionId}`
- Settings workflow:
  - `GET /project/{project}/jobSecurity/settings`
  - `POST /project/{project}/jobSecurity/settings`
  - `GET /project/{project}/jobSecurity/users`
- Notify workflow:
  - `POST /project/{project}/jobSecurity/notify`

## 7. Suggested UI Output Format
Each finding displays:
- Rule name
- Severity
- Description
- Why it matters
- Detected code snippet (masked)
- Recommended remediation

Summary block displays:
- Per-severity counts (including Critical)
- Risk score (`x/100`)
- Risk level (`Low/Medium/High/Critical`)
- Risky job count
- Execution reference
