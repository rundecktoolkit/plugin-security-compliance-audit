## Release Notes

### v1.0.0

Initial public release of the Rundeck Security & Compliance Audit Plugin.

### Included

- Security & Compliance project navigation entry
- Activity-backed manual scan runs
- Rule-driven findings and risk scoring
- Project-level rule groups and severity overrides
- Policy-as-code YAML configuration
- Custom admin-defined regex rules
- Webhook and email notification flow
- AI report generation with preview and markdown/text downloads
- AI diagnostics: model discovery, test connection, key diagnostics
- Two project configuration tabs:
  - Security & Compliance
  - AI Connection
- AI provider support for:
  - OpenAI
  - Anthropic
  - Google AI
  - Custom endpoints

## Installation

1. Download `plugin-security-compliance-audit-1.0.0.jar` from this release.
2. Upload it via **System Menu -> Plugins -> Upload Plugin**.
3. Restart Rundeck if your deployment does not hot-load UI plugins.

## Uninstall

1. Remove the plugin JAR.
2. Restart Rundeck if required.
