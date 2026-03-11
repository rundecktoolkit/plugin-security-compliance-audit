package jobsecurityaudit

import com.dtolabs.rundeck.core.authorization.AuthContext
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.rundeck.core.auth.AuthConstants
import org.yaml.snakeyaml.Yaml
import rundeck.data.report.SaveReportRequestImpl

import java.util.regex.Pattern

class JobSecurityAuditService {
    private static final String CUSTOM_RULES_PROP = 'project.plugin.JobSecurityAudit.customRulesJson'
    private static final List<String> SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    private static final Map<String, Integer> SEVERITY_POINTS = [CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3]
    private static final List<String> SECRET_HINTS = ['password', 'passwd', 'secret', 'token', 'apikey', 'api_key', 'accesskey', 'auth']

    private static final Map<String, Map> RULE_DEFS = [
        RUN_AS_ROOT: [
            defaultSeverity: 'HIGH',
            group: 'execution-privileges',
            remediation: 'Use least-privilege execution accounts and avoid root-level automation.',
            description: 'Job appears to execute as root or privileged account.',
            whyMatters: 'Root-level execution increases blast radius for mistakes and malicious behavior.'
        ],
        SUDO_WITHOUT_RESTRICTIONS: [
            defaultSeverity: 'HIGH',
            group: 'execution-privileges',
            remediation: 'Restrict sudoers policy to explicit command allow-lists.',
            description: 'Unrestricted sudo invocation detected.',
            whyMatters: 'Broad sudo usage allows privilege escalation and unsafe command execution.'
        ],
        UNSAFE_SHELL_PIPE_EXECUTION: [
            defaultSeverity: 'HIGH',
            group: 'script-steps',
            remediation: 'Avoid eval and unsafe bash -c patterns with untrusted inputs.',
            description: 'Potentially unsafe shell execution construct found.',
            whyMatters: 'Unsafe shell interpolation can lead to command injection.'
        ],
        WILDCARD_DESTRUCTIVE_COMMAND: [
            defaultSeverity: 'CRITICAL',
            group: 'destructive-commands',
            remediation: 'Use explicit paths and safeguards instead of wildcard destructive commands.',
            description: 'Destructive wildcard command detected.',
            whyMatters: 'Wildcard destructive commands can cause large accidental data loss.'
        ],
        EXPOSED_ENVIRONMENT_VARIABLE_SECRET: [
            defaultSeverity: 'HIGH',
            group: 'credential-handling',
            remediation: 'Never print secret environment variables; mask or remove from output.',
            description: 'Secret-like environment variable appears to be printed.',
            whyMatters: 'Printed environment secrets leak into execution logs and external systems.'
        ],
        PLAINTEXT_FILE_CREDENTIALS: [
            defaultSeverity: 'HIGH',
            group: 'credential-handling',
            remediation: 'Use secure secret stores instead of plaintext credential files.',
            description: 'Script appears to read credentials from plaintext file.',
            whyMatters: 'Plaintext credentials are easy to exfiltrate and difficult to audit.'
        ],
        UNPINNED_GIT_REPOSITORY: [
            defaultSeverity: 'MEDIUM',
            group: 'supply-chain',
            remediation: 'Pin script sources to commit SHA or immutable release tags.',
            description: 'Git source appears unpinned to commit or release tag.',
            whyMatters: 'Unpinned upstream code introduces supply-chain drift and tampering risk.'
        ],
        UNRESTRICTED_NODE_TARGETING: [
            defaultSeverity: 'HIGH',
            group: 'node-targeting',
            remediation: 'Restrict node filters to specific tags, groups, or host patterns.',
            description: 'Job appears to target all nodes without restrictions.',
            whyMatters: 'Broad node targeting increases operational blast radius.'
        ],
        INLINE_SECRET_LITERAL: [
            defaultSeverity: 'HIGH',
            group: 'credential-handling',
            remediation: 'Move secret literals into secure options or Key Storage references.',
            description: 'Inline secret literal detected in job data.',
            whyMatters: 'Inline secrets are hard to rotate and easy to expose accidentally.'
        ],
        OPTION_SECRET_NOT_SECURE: [
            defaultSeverity: 'HIGH',
            group: 'credential-handling',
            remediation: 'Mark secret options as secure input and remove plaintext defaults.',
            description: 'Secret-like option is not configured as secure.',
            whyMatters: 'Non-secure options can disclose sensitive values in job definitions and logs.'
        ],
        OPTION_SECURE_EXPOSED: [
            defaultSeverity: 'MEDIUM',
            group: 'credential-handling',
            remediation: 'Avoid exposing secure option values unless explicitly required.',
            description: 'Secure option output exposure enabled.',
            whyMatters: 'Exposed secure options can leak values to logs and downstream systems.'
        ],
        URL_EMBEDDED_CREDENTIALS: [
            defaultSeverity: 'HIGH',
            group: 'credential-handling',
            remediation: 'Remove credentials from URLs and use secure references.',
            description: 'Embedded credentials found in URL.',
            whyMatters: 'Credential-bearing URLs can leak through logs, history, and metrics.'
        ],
        AUTH_HEADER_LITERAL: [
            defaultSeverity: 'HIGH',
            group: 'credential-handling',
            remediation: 'Do not hardcode Authorization headers. Use secure inputs.',
            description: 'Literal Authorization header value detected.',
            whyMatters: 'Hardcoded auth headers expose long-lived credentials in config/script text.'
        ],
        POLICY_PRIVILEGE: [
            defaultSeverity: 'HIGH',
            group: 'policy',
            remediation: 'Update job to use least privilege or relax policy explicitly.',
            description: 'Privilege Policy violation.',
            whyMatters: 'Least privilege is required to limit compromise impact.'
        ],
        POLICY_EXECUTION_SCOPE: [
            defaultSeverity: 'HIGH',
            group: 'policy',
            remediation: 'Restrict node targeting to approved scopes.',
            description: 'Execution Scope Policy violation.',
            whyMatters: 'Over-broad scope can impact too many nodes during failures.'
        ],
        POLICY_SECRETS_MANAGEMENT: [
            defaultSeverity: 'HIGH',
            group: 'policy',
            remediation: 'Retrieve secrets from approved secure store references.',
            description: 'Secrets Management Policy violation.',
            whyMatters: 'Improper secret handling leads to direct credential exposure.'
        ],
        POLICY_CHANGE_CONTROL: [
            defaultSeverity: 'MEDIUM',
            group: 'policy',
            remediation: 'Apply additional change controls for destructive operations.',
            description: 'Change Control Policy violation.',
            whyMatters: 'Uncontrolled infra-modifying jobs increase production risk.'
        ],
        POLICY_SUPPLY_CHAIN: [
            defaultSeverity: 'MEDIUM',
            group: 'policy',
            remediation: 'Pin and validate script sources against trusted artifacts.',
            description: 'Supply Chain Policy violation.',
            whyMatters: 'Untrusted script sources create integrity and tampering risks.'
        ],
        POLICY_LOGGING_AUDIT: [
            defaultSeverity: 'MEDIUM',
            group: 'policy',
            remediation: 'Ensure secrets are masked and log handling follows audit controls.',
            description: 'Logging and Audit Policy violation.',
            whyMatters: 'Sensitive data in logs breaks compliance and incident response hygiene.'
        ],
        POLICY_INPUT_VALIDATION: [
            defaultSeverity: 'MEDIUM',
            group: 'policy',
            remediation: 'Constrain inputs using regex/enforced values where possible.',
            description: 'Input Validation Policy violation.',
            whyMatters: 'Unchecked inputs can trigger command/script injection paths.'
        ],
        POLICY_ENV_SEGMENTATION: [
            defaultSeverity: 'LOW',
            group: 'policy',
            remediation: 'Constrain jobs to intended environment tags or project scope.',
            description: 'Environment Segmentation Policy warning.',
            whyMatters: 'Weak segmentation increases cross-environment impact risk.'
        ],
        POLICY_BLAST_RADIUS: [
            defaultSeverity: 'HIGH',
            group: 'policy',
            remediation: 'Reduce target scope or raise policy limits intentionally.',
            description: 'Blast Radius Policy violation.',
            whyMatters: 'Jobs with broad target scope can cause large outages quickly.'
        ],
        POLICY_SCRIPT_INTEGRITY: [
            defaultSeverity: 'MEDIUM',
            group: 'policy',
            remediation: 'Use only approved repositories and trusted script sources.',
            description: 'Script Integrity Policy violation.',
            whyMatters: 'Unknown script sources weaken software supply chain trust.'
        ]
    ]

    def grailsApplication
    def rundeckAuthContextProcessor
    def frameworkService
    def logFileStorageService
    def reportService
    JobSecurityAuditCacheService jobSecurityAuditCacheService

    List<Map> listUsers() {
        Class userClass = domainClass('rundeck.User')
        List users = (List) userClass.list(sort: 'login', order: 'asc')
        return users.collect { Object u ->
            String login = u.login?.toString()
            String email = u.email?.toString()
            String firstName = u.firstName?.toString()
            String lastName = u.lastName?.toString()
            String display = [firstName, lastName].findAll { it }?.join(' ')
            if (!display) {
                display = login
            }
            [
                login: login,
                email: email ?: '',
                display: email ? "${display} (${email})" : display
            ]
        }
    }

    Map settingsForProject(final String project) {
        Map<String, String> props = loadProjectProps(project)
        List<Map> customRules = loadCustomRulesFromProps(props)
        Map<String, Boolean> groups = [:]
        Map<String, String> severities = [:]

        String selectedUser = props.get('project.plugin.JobSecurityAudit.emailRecipientUser') ?: ''
        if (!selectedUser) {
            List<String> legacyUsers = (props.get('project.plugin.JobSecurityAudit.emailRecipientUsers') ?: '')
                .split(',')
                .collect { it?.trim() }
                .findAll { it }
            selectedUser = legacyUsers ? legacyUsers[0] : ''
        }

        Set<String> groupNames = RULE_DEFS.values().collect { (String) it.group } as Set<String>
        groupNames.each { String group ->
            groups[group] = props.get("project.plugin.JobSecurityAudit.rules.enabled.${group}") != 'false'
        }
        RULE_DEFS.each { String ruleId, Map defn ->
            String sev = props.get("project.plugin.JobSecurityAudit.rules.severity.${ruleId}") ?: (String) defn.defaultSeverity
            severities[ruleId] = SEVERITIES.contains(sev) ? sev : (String) defn.defaultSeverity
        }

        return [
            webhookUrl: props.get('project.plugin.JobSecurityAudit.webhookUrl') ?: '',
            emailRecipients: props.get('project.plugin.JobSecurityAudit.emailRecipients') ?: '',
            emailRecipientUser: selectedUser,
            policyYaml: props.get('project.plugin.JobSecurityAudit.policyYaml') ?: defaultPolicyYaml(),
            llm: [
                enabled: (props.get('project.plugin.JobSecurityAudit.llm.enabled') ?: 'false').equalsIgnoreCase('true'),
                provider: props.get('project.plugin.JobSecurityAudit.llm.provider') ?: '',
                endpointUrl: props.get('project.plugin.JobSecurityAudit.llm.endpointUrl') ?: '',
                model: props.get('project.plugin.JobSecurityAudit.llm.model') ?: '',
                username: props.get('project.plugin.JobSecurityAudit.llm.username') ?: '',
                vaultApiKeyPath: props.get('project.plugin.JobSecurityAudit.llm.vaultApiKeyPath') ?: '',
                promptTemplate: props.get('project.plugin.JobSecurityAudit.llm.promptTemplate') ?: JobSecurityAuditLlmService.defaultPromptTemplate()
            ],
            rules: [
                groups: groups,
                severities: severities,
                defaults: RULE_DEFS.collectEntries { String ruleId, Map defn ->
                    [(ruleId): [
                        group: defn.group,
                        defaultSeverity: defn.defaultSeverity,
                        remediation: defn.remediation,
                        description: defn.description,
                        whyMatters: defn.whyMatters
                    ]]
                }
            ],
            customRules: customRules
        ]
    }

    Map saveSettingsForProject(final String project, final Map body) {
        Map cfg = body ?: [:]
        Properties projProps = new Properties()

        String webhookUrl = (cfg.webhookUrl ?: '').toString().trim()
        String selectedUser = (cfg.emailRecipientUser ?: '').toString().trim()

        Map<String, String> userEmailByLogin = listUsers().collectEntries { Map row ->
            [(row.login?.toString()): (row.email?.toString())]
        }
        String selectedEmail = selectedUser ? (userEmailByLogin[selectedUser] ?: '') : ''
        if (selectedUser && !selectedEmail) {
            throw new IllegalArgumentException("Selected notification user '${selectedUser}' does not have an email address.")
        }

        String policyYaml = (cfg.policyYaml ?: '').toString().trim()
        if (!policyYaml) {
            policyYaml = defaultPolicyYaml()
        }
        Map llmCfg = cfg.llm instanceof Map ? (Map) cfg.llm : [:]
        String llmEnabled = ((llmCfg.enabled ?: false) as Boolean) ? 'true' : 'false'
        String llmProvider = (llmCfg.provider ?: '').toString().trim().toLowerCase(Locale.ROOT)
        String llmEndpointUrl = (llmCfg.endpointUrl ?: '').toString().trim()
        String llmModel = (llmCfg.model ?: '').toString().trim()
        String llmUsername = (llmCfg.username ?: '').toString().trim()
        String llmVaultApiKeyPath = (llmCfg.vaultApiKeyPath ?: '').toString().trim()
        String llmPromptTemplate = (llmCfg.promptTemplate ?: '').toString().trim()
        if (!llmPromptTemplate) {
            llmPromptTemplate = JobSecurityAuditLlmService.defaultPromptTemplate()
        }
        List<Map> customRules = normalizeCustomRules(cfg.customRules)

        if (webhookUrl) {
            projProps.setProperty('project.plugin.JobSecurityAudit.webhookUrl', webhookUrl)
        }
        if (selectedEmail) {
            projProps.setProperty('project.plugin.JobSecurityAudit.emailRecipients', selectedEmail)
        }
        if (selectedUser) {
            projProps.setProperty('project.plugin.JobSecurityAudit.emailRecipientUser', selectedUser)
        }
        projProps.setProperty('project.plugin.JobSecurityAudit.policyYaml', policyYaml)
        projProps.setProperty('project.plugin.JobSecurityAudit.llm.enabled', llmEnabled)
        if (llmProvider) {
            projProps.setProperty('project.plugin.JobSecurityAudit.llm.provider', llmProvider)
        }
        if (llmEndpointUrl) {
            projProps.setProperty('project.plugin.JobSecurityAudit.llm.endpointUrl', llmEndpointUrl)
        }
        if (llmModel) {
            projProps.setProperty('project.plugin.JobSecurityAudit.llm.model', llmModel)
        }
        if (llmUsername) {
            projProps.setProperty('project.plugin.JobSecurityAudit.llm.username', llmUsername)
        }
        if (llmVaultApiKeyPath) {
            projProps.setProperty('project.plugin.JobSecurityAudit.llm.vaultApiKeyPath', llmVaultApiKeyPath)
        }
        projProps.setProperty('project.plugin.JobSecurityAudit.llm.promptTemplate', llmPromptTemplate)
        projProps.setProperty(CUSTOM_RULES_PROP, JsonOutput.toJson(customRules))

        Map groupCfg = (cfg.rules instanceof Map && ((Map) cfg.rules).groups instanceof Map) ? (Map) ((Map) cfg.rules).groups : [:]
        Set<String> groupNames = RULE_DEFS.values().collect { (String) it.group } as Set<String>
        groupNames.each { String group ->
            Object enabledRaw = groupCfg.get(group)
            boolean enabled = enabledRaw == null ? true : enabledRaw.toString() == 'true'
            projProps.setProperty("project.plugin.JobSecurityAudit.rules.enabled.${group}", enabled ? 'true' : 'false')
        }

        Map severityCfg = (cfg.rules instanceof Map && ((Map) cfg.rules).severities instanceof Map) ? (Map) ((Map) cfg.rules).severities : [:]
        RULE_DEFS.each { String ruleId, Map defn ->
            String severity = (severityCfg.get(ruleId) ?: defn.defaultSeverity).toString().trim().toUpperCase(Locale.ROOT)
            if (!SEVERITIES.contains(severity)) {
                severity = (String) defn.defaultSeverity
            }
            projProps.setProperty("project.plugin.JobSecurityAudit.rules.severity.${ruleId}", severity)
        }

        frameworkService.updateFrameworkProjectConfig(project, projProps, ['project.plugin.JobSecurityAudit.'] as Set<String>)
        return settingsForProject(project)
    }

    Map runScan(final String project, final String user, final AuthContext authContext) {
        Date started = new Date()

        Class seClass = domainClass('rundeck.ScheduledExecution')
        List jobs = (List) seClass.findAllByProject(project)
        List<Map> findings = []
        Map<String, Map> ruleConfig = loadRuleConfig(project)
        Map policy = loadPolicy(project)
        List<Map> customRules = loadCustomRules(project)

        for (Object job : jobs) {
            if (!isJobVisible(authContext, project, job)) {
                continue
            }
            findings.addAll(scanJob(job, ruleConfig, policy, customRules))
        }

        findings = dedupeFindings(findings)

        Map riskCounts = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
        findings.each { Map finding ->
            String sev = (String) finding.severity
            if (riskCounts.containsKey(sev)) {
                riskCounts[sev] = ((Integer) riskCounts[sev]) + 1
            }
        }

        int riskScoreRaw = findings.collect { Map f -> SEVERITY_POINTS[(String) f.severity] ?: 0 }.sum() as int
        int riskScore = Math.min(100, riskScoreRaw)
        String riskLevel = riskLevelForScore(riskScore)

        Set<String> riskyJobs = findings.collect { (String) it.jobUuid }.findAll { it } as Set<String>
        Date completed = new Date()

        Map summary = [
            project: project,
            scannedAt: completed.format("yyyy-MM-dd'T'HH:mm:ssXXX"),
            status: 'succeed',
            jobCount: jobs.size(),
            riskyJobs: riskyJobs.size(),
            riskCounts: riskCounts,
            riskScore: riskScore,
            riskLevel: riskLevel
        ]

        String status = 'succeeded'
        String message = "Scan complete: score ${riskScore}/100 (${riskLevel}), ${riskCounts.CRITICAL ?: 0} critical, ${riskCounts.HIGH ?: 0} high, ${riskCounts.MEDIUM ?: 0} medium, ${riskCounts.LOW ?: 0} low"

        Object execution = createAuditExecution(project, user, started, completed, status, message, summary, findings)
        saveAuditReport(execution, project, user, status, message)

        Long executionId = execution.id as Long
        Map payload = [summary: summary + [executionId: executionId], findings: findings, byJob: buildByJobSummary(findings)]
        jobSecurityAuditCacheService.save(project, executionId, payload)
        return payload
    }

    Map latestForProject(final String project, final AuthContext authContext) {
        Map payload = jobSecurityAuditCacheService.latest(project)
        if (!payload) {
            return null
        }
        return filterPayloadByAuth(project, authContext, payload)
    }

    Map byExecutionId(final String project, final Long executionId, final AuthContext authContext) {
        Map payload = jobSecurityAuditCacheService.byExecutionId(executionId)
        if (!payload) {
            Class executionClass = domainClass('rundeck.Execution')
            Object exec = executionClass.get(executionId)
            if (!exec || exec.project != project) {
                return null
            }
            Map extra = (Map) exec.extraMetadataMap
            payload = extra?.jobSecurityAudit instanceof Map ? (Map) extra.jobSecurityAudit : null
        }
        if (!payload) {
            return null
        }
        return filterPayloadByAuth(project, authContext, payload)
    }

    private Map filterPayloadByAuth(final String project, final AuthContext authContext, final Map payload) {
        List<Map> sourceFindings = ((List<Map>) payload.findings) ?: []
        Class seClass = domainClass('rundeck.ScheduledExecution')
        List<Map> filteredFindings = sourceFindings.findAll { Map finding ->
            String jobUuid = (String) finding.jobUuid
            Object se = jobUuid ? seClass.findByUuid(jobUuid) : null
            se && isJobVisible(authContext, project, se)
        }

        Map riskCounts = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0]
        filteredFindings.each { Map finding ->
            String sev = (String) finding.severity
            if (riskCounts.containsKey(sev)) {
                riskCounts[sev] = ((Integer) riskCounts[sev]) + 1
            }
        }
        int riskScore = Math.min(100, filteredFindings.collect { Map f -> SEVERITY_POINTS[(String) f.severity] ?: 0 }.sum() as int)
        Set<String> riskyJobs = filteredFindings.collect { (String) it.jobUuid } as Set<String>

        Map summary = new LinkedHashMap((Map) payload.summary)
        summary.riskCounts = riskCounts
        summary.riskyJobs = riskyJobs.size()
        summary.riskScore = riskScore
        summary.riskLevel = riskLevelForScore(riskScore)

        return [summary: summary, findings: filteredFindings, byJob: buildByJobSummary(filteredFindings)]
    }

    private boolean isJobVisible(final AuthContext authContext, final String project, final Object job) {
        return rundeckAuthContextProcessor.authorizeProjectJobAny(
            authContext,
            job,
            [AuthConstants.ACTION_READ, AuthConstants.ACTION_VIEW],
            project
        )
    }

    private List<Map> scanJob(final Object job, final Map<String, Map> ruleConfig, final Map policy, final List<Map> customRules) {
        List<Map> findings = []
        String groupPath = valueOf(job, 'groupPath')
        String jobName = valueOf(job, 'jobName')
        String jobRef = groupPath ? "${groupPath}/${jobName}" : jobName

        for (Object option : (job.options ?: [])) {
            String optName = (option.name ?: '').toString().toLowerCase(Locale.ROOT)
            boolean secretLike = SECRET_HINTS.any { String hint -> optName.contains(hint) }
            String defaultValue = option.defaultValue?.toString()

            if (ruleEnabled(ruleConfig, 'OPTION_SECRET_NOT_SECURE') && secretLike && !(option.secureInput ?: false) && defaultValue) {
                findings << finding(job, jobRef, 'OPTION_SECRET_NOT_SECURE', "Secret-like option '${option.name}' has plaintext default value.", defaultValue, resolveSeverity(ruleConfig, 'OPTION_SECRET_NOT_SECURE'), 0.95d)
            }

            if (ruleEnabled(ruleConfig, 'OPTION_SECURE_EXPOSED') && (option.secureInput ?: false) && (option.secureExposed ?: false)) {
                findings << finding(job, jobRef, 'OPTION_SECURE_EXPOSED', "Secure option '${option.name}' is configured with exposed value output.", option.name?.toString(), resolveSeverity(ruleConfig, 'OPTION_SECURE_EXPOSED'), 0.70d)
            }

            if (ruleEnabled(ruleConfig, 'INLINE_SECRET_LITERAL') && defaultValue && secretLike && isLiteralSecret(defaultValue)) {
                findings << finding(job, jobRef, 'INLINE_SECRET_LITERAL', "Option '${option.name}' default appears to contain an inline secret literal.", defaultValue, resolveSeverity(ruleConfig, 'INLINE_SECRET_LITERAL'), 0.92d)
            }
        }

        List<Map<String, String>> namedValues = collectNamedValues(job)
        String joined = namedValues.collect { it.value ?: '' }.join('\n')

        for (Map<String, String> entry : namedValues) {
            String key = (entry.key ?: '').toLowerCase(Locale.ROOT)
            String value = entry.value
            if (!value) {
                continue
            }

            if (ruleEnabled(ruleConfig, 'URL_EMBEDDED_CREDENTIALS') && containsEmbeddedCredentialsUrl(value)) {
                findings << finding(job, jobRef, 'URL_EMBEDDED_CREDENTIALS', "Embedded URL credentials were found in '${entry.key}'.", value, resolveSeverity(ruleConfig, 'URL_EMBEDDED_CREDENTIALS'), 0.99d)
            }

            if (ruleEnabled(ruleConfig, 'AUTH_HEADER_LITERAL') && looksLikeLiteralAuthorizationHeader(value)) {
                findings << finding(job, jobRef, 'AUTH_HEADER_LITERAL', "Literal Authorization header value found in '${entry.key}'.", value, resolveSeverity(ruleConfig, 'AUTH_HEADER_LITERAL'), 0.98d)
            }

            boolean keySecretLike = SECRET_HINTS.any { String hint -> key.contains(hint) }
            if (ruleEnabled(ruleConfig, 'INLINE_SECRET_LITERAL') && keySecretLike && isLiteralSecret(value)) {
                findings << finding(job, jobRef, 'INLINE_SECRET_LITERAL', "Secret-like key '${entry.key}' contains a literal secret value.", value, resolveSeverity(ruleConfig, 'INLINE_SECRET_LITERAL'), 0.90d)
            }

            if (ruleEnabled(ruleConfig, 'INLINE_SECRET_LITERAL') && looksLikeSensitiveLiteralInText(value)) {
                findings << finding(job, jobRef, 'INLINE_SECRET_LITERAL', "Potential inline credential detected in '${entry.key}'.", value, resolveSeverity(ruleConfig, 'INLINE_SECRET_LITERAL'), 0.78d)
            }
        }

        if (ruleEnabled(ruleConfig, 'RUN_AS_ROOT') && looksLikeRunAsRoot(job, joined)) {
            findings << finding(job, jobRef, 'RUN_AS_ROOT', 'Privileged/root execution context detected.', joined, resolveSeverity(ruleConfig, 'RUN_AS_ROOT'), 0.93d)
        }

        if (ruleEnabled(ruleConfig, 'SUDO_WITHOUT_RESTRICTIONS') && (joined =~ /(?mi)\bsudo\s+(bash|sh|su\b|\-s|\-i|\/.+)/).find()) {
            findings << finding(job, jobRef, 'SUDO_WITHOUT_RESTRICTIONS', 'Unrestricted sudo invocation detected in script/command.', joined, resolveSeverity(ruleConfig, 'SUDO_WITHOUT_RESTRICTIONS'), 0.88d)
        }

        if (ruleEnabled(ruleConfig, 'UNSAFE_SHELL_PIPE_EXECUTION') && (joined =~ /(?mi)(eval\s+\$|bash\s+\-c\s+["']?\$|sh\s+\-c\s+["']?\$)/).find()) {
            findings << finding(job, jobRef, 'UNSAFE_SHELL_PIPE_EXECUTION', 'Unsafe shell execution construct detected.', joined, resolveSeverity(ruleConfig, 'UNSAFE_SHELL_PIPE_EXECUTION'), 0.89d)
        }

        if (ruleEnabled(ruleConfig, 'WILDCARD_DESTRUCTIVE_COMMAND') && (joined =~ /(?mi)\brm\s+\-rf\s+(\*|\/\w+\/\*)/).find()) {
            findings << finding(job, jobRef, 'WILDCARD_DESTRUCTIVE_COMMAND', 'Destructive wildcard command detected.', joined, resolveSeverity(ruleConfig, 'WILDCARD_DESTRUCTIVE_COMMAND'), 0.97d)
        }

        if (ruleEnabled(ruleConfig, 'EXPOSED_ENVIRONMENT_VARIABLE_SECRET') && (joined =~ /(?mi)\becho\s+\$[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|ACCESS_KEY|API_KEY)/).find()) {
            findings << finding(job, jobRef, 'EXPOSED_ENVIRONMENT_VARIABLE_SECRET', 'Secret-like environment variable is echoed.', joined, resolveSeverity(ruleConfig, 'EXPOSED_ENVIRONMENT_VARIABLE_SECRET'), 0.95d)
        }

        if (ruleEnabled(ruleConfig, 'PLAINTEXT_FILE_CREDENTIALS') && (joined =~ /(?mi)\b(cat|grep|awk|sed)\s+[^\n]*(password|secret|credential)[^\n]*(\.txt|\.conf|\.ini|\/tmp\/)/).find()) {
            findings << finding(job, jobRef, 'PLAINTEXT_FILE_CREDENTIALS', 'Possible plaintext credentials file access detected.', joined, resolveSeverity(ruleConfig, 'PLAINTEXT_FILE_CREDENTIALS'), 0.83d)
        }

        if (ruleEnabled(ruleConfig, 'UNPINNED_GIT_REPOSITORY') && containsUnpinnedGitCheckout(joined)) {
            findings << finding(job, jobRef, 'UNPINNED_GIT_REPOSITORY', 'Git repository usage appears unpinned to commit/tag.', joined, resolveSeverity(ruleConfig, 'UNPINNED_GIT_REPOSITORY'), 0.82d)
        }

        if (ruleEnabled(ruleConfig, 'UNRESTRICTED_NODE_TARGETING') && hasUnrestrictedNodeTargeting(job, joined)) {
            findings << finding(job, jobRef, 'UNRESTRICTED_NODE_TARGETING', 'Node targeting appears unrestricted/all-nodes.', joined, resolveSeverity(ruleConfig, 'UNRESTRICTED_NODE_TARGETING'), 0.86d)
        }

        findings.addAll(applyCustomRules(job, jobRef, joined, customRules))
        findings.addAll(policyFindings(job, jobRef, findings, policy, joined, ruleConfig))
        return findings
    }

    private List<Map> policyFindings(final Object job, final String jobRef, final List<Map> currentFindings, final Map policy, final String contextText, final Map<String, Map> ruleConfig) {
        List<Map> out = []

        boolean hasRoot = currentFindings.any { it.ruleId == 'RUN_AS_ROOT' }
        boolean hasUnrestrictedNodes = currentFindings.any { it.ruleId == 'UNRESTRICTED_NODE_TARGETING' }
        boolean hasInlineSecrets = currentFindings.any { ['INLINE_SECRET_LITERAL', 'OPTION_SECRET_NOT_SECURE', 'PLAINTEXT_FILE_CREDENTIALS', 'EXPOSED_ENVIRONMENT_VARIABLE_SECRET'].contains(it.ruleId) }
        boolean hasDestructive = currentFindings.any { ['WILDCARD_DESTRUCTIVE_COMMAND'].contains(it.ruleId) }
        boolean hasSupplyChain = currentFindings.any { it.ruleId == 'UNPINNED_GIT_REPOSITORY' }
        boolean hasUnsafeInputPattern = currentFindings.any { it.ruleId == 'UNSAFE_SHELL_PIPE_EXECUTION' }

        int maxNodes = ((policy.max_nodes ?: 20) as Integer)
        boolean allowRoot = ((policy.allow_root_execution ?: false) as Boolean)
        boolean requireVaultSecrets = ((policy.require_vault_secrets ?: false) as Boolean)
        boolean requireGitPinning = ((policy.require_git_pinning ?: false) as Boolean)
        List<String> approvedRepos = policy.approved_repositories instanceof Collection ? ((Collection) policy.approved_repositories).collect { it.toString() } : []

        if (!allowRoot && hasRoot && ruleEnabled(ruleConfig, 'POLICY_PRIVILEGE')) {
            out << finding(job, jobRef, 'POLICY_PRIVILEGE', 'Privilege Policy: root execution is not allowed by policy.', contextText, resolveSeverity(ruleConfig, 'POLICY_PRIVILEGE'), 0.96d)
        }
        if (hasUnrestrictedNodes && ruleEnabled(ruleConfig, 'POLICY_EXECUTION_SCOPE')) {
            out << finding(job, jobRef, 'POLICY_EXECUTION_SCOPE', 'Execution Scope Policy: unrestricted node targeting violates policy.', contextText, resolveSeverity(ruleConfig, 'POLICY_EXECUTION_SCOPE'), 0.90d)
        }
        if (requireVaultSecrets && hasInlineSecrets && ruleEnabled(ruleConfig, 'POLICY_SECRETS_MANAGEMENT')) {
            out << finding(job, jobRef, 'POLICY_SECRETS_MANAGEMENT', 'Secrets Management Policy: secure store usage required, inline/plaintext secret patterns found.', contextText, resolveSeverity(ruleConfig, 'POLICY_SECRETS_MANAGEMENT'), 0.90d)
        }
        if (hasDestructive && ruleEnabled(ruleConfig, 'POLICY_CHANGE_CONTROL')) {
            out << finding(job, jobRef, 'POLICY_CHANGE_CONTROL', 'Change Control Policy: destructive command patterns require additional controls.', contextText, resolveSeverity(ruleConfig, 'POLICY_CHANGE_CONTROL'), 0.80d)
        }
        if (requireGitPinning && hasSupplyChain && ruleEnabled(ruleConfig, 'POLICY_SUPPLY_CHAIN')) {
            out << finding(job, jobRef, 'POLICY_SUPPLY_CHAIN', 'Supply Chain Policy: git sources must be pinned to commit/tag.', contextText, resolveSeverity(ruleConfig, 'POLICY_SUPPLY_CHAIN'), 0.89d)
        }
        if (hasInlineSecrets && ruleEnabled(ruleConfig, 'POLICY_LOGGING_AUDIT')) {
            out << finding(job, jobRef, 'POLICY_LOGGING_AUDIT', 'Logging and Audit Policy: potential secret exposure threatens log hygiene.', contextText, resolveSeverity(ruleConfig, 'POLICY_LOGGING_AUDIT'), 0.74d)
        }
        if (hasUnsafeInputPattern && ruleEnabled(ruleConfig, 'POLICY_INPUT_VALIDATION')) {
            out << finding(job, jobRef, 'POLICY_INPUT_VALIDATION', 'Input Validation Policy: unsafe input execution path detected.', contextText, resolveSeverity(ruleConfig, 'POLICY_INPUT_VALIDATION'), 0.84d)
        }
        if (hasUnrestrictedNodes && ruleEnabled(ruleConfig, 'POLICY_ENV_SEGMENTATION')) {
            out << finding(job, jobRef, 'POLICY_ENV_SEGMENTATION', 'Environment Segmentation Policy: target scope appears broad/unsegmented.', contextText, resolveSeverity(ruleConfig, 'POLICY_ENV_SEGMENTATION'), 0.68d)
        }
        if (hasUnrestrictedNodes && maxNodes > 0 && ruleEnabled(ruleConfig, 'POLICY_BLAST_RADIUS')) {
            out << finding(job, jobRef, 'POLICY_BLAST_RADIUS', "Blast Radius Policy: job may exceed max_nodes=${maxNodes} due to unrestricted targeting.", contextText, resolveSeverity(ruleConfig, 'POLICY_BLAST_RADIUS'), 0.88d)
        }
        if (!approvedRepos.isEmpty() && containsGitRepoOutsideApproved(contextText, approvedRepos) && ruleEnabled(ruleConfig, 'POLICY_SCRIPT_INTEGRITY')) {
            out << finding(job, jobRef, 'POLICY_SCRIPT_INTEGRITY', 'Script Integrity Policy: script source repository is not in approved list.', contextText, resolveSeverity(ruleConfig, 'POLICY_SCRIPT_INTEGRITY'), 0.81d)
        }

        out
    }

    private List<Map<String, String>> collectNamedValues(final Object job) {
        List<Map<String, String>> rows = []

        addNamed(rows, 'job.argString', valueOf(job, 'argString'))
        addNamed(rows, 'job.notifySuccessUrl', valueOf(job, 'notifySuccessUrl'))
        addNamed(rows, 'job.notifyFailureUrl', valueOf(job, 'notifyFailureUrl'))
        addNamed(rows, 'job.notifyStartUrl', valueOf(job, 'notifyStartUrl'))
        addNamed(rows, 'job.nodeFilterEditable', valueOf(job, 'nodeFilterEditable'))
        addNamed(rows, 'job.nodeFilterEnabled', valueOf(job, 'nodeFilterEnabled'))
        addNamed(rows, 'job.nodeFilterInclude', valueOf(job, 'nodeFilterInclude'))
        addNamed(rows, 'job.nodeFilterExclude', valueOf(job, 'nodeFilterExclude'))
        addNamed(rows, 'job.nodeInclude', valueOf(job, 'nodeInclude'))
        addNamed(rows, 'job.nodeExclude', valueOf(job, 'nodeExclude'))
        addNamed(rows, 'job.nodeThreadcount', valueOf(job, 'nodeThreadcount'))
        addNamed(rows, 'job.nodeKeepgoing', valueOf(job, 'nodeKeepgoing'))
        addNamed(rows, 'job.serverNodeUUID', valueOf(job, 'serverNodeUUID'))

        if (job.workflow?.commands) {
            int idx = 0
            job.workflow.commands.each { command ->
                idx++
                String cls = command?.getClass()?.name
                if (cls == 'rundeck.CommandExec') {
                    addNamed(rows, "workflow.${idx}.exec", command.adhocRemoteString?.toString())
                    addNamed(rows, "workflow.${idx}.script", command.adhocLocalString?.toString())
                    addNamed(rows, "workflow.${idx}.scriptFile", command.adhocFilepath?.toString())
                    addNamed(rows, "workflow.${idx}.args", command.argString?.toString())
                } else if (cls == 'rundeck.PluginStep') {
                    Map cfg = (Map) (command.configuration ?: [:])
                    flattenMap(rows, "workflow.${idx}.configuration", cfg)
                } else {
                    addNamed(rows, "workflow.${idx}", command?.toMap()?.toString())
                }
            }
        }
        return rows
    }

    private void flattenMap(final List<Map<String, String>> rows, final String prefix, final Object data) {
        if (data instanceof Map) {
            ((Map) data).each { k, v -> flattenMap(rows, "${prefix}.${k}", v) }
        } else if (data instanceof Collection) {
            int i = 0
            ((Collection) data).each { v ->
                i++
                flattenMap(rows, "${prefix}[${i}]", v)
            }
        } else {
            addNamed(rows, prefix, data?.toString())
        }
    }

    private void addNamed(final List<Map<String, String>> rows, final String key, final String value) {
        if (value != null && value.trim()) {
            rows << [key: key, value: value]
        }
    }

    private List<Map> dedupeFindings(final List<Map> findings) {
        Set<String> seen = new HashSet<>()
        List<Map> out = []
        findings.each { Map finding ->
            String key = "${finding.jobUuid}|${finding.ruleId}|${finding.evidenceSnippetMasked}"
            if (!seen.contains(key)) {
                seen << key
                out << finding
            }
        }
        out
    }

    private List<Map> applyCustomRules(final Object job, final String jobRef, final String joined, final List<Map> customRules) {
        if (!customRules) {
            return []
        }
        List<Map> out = []
        customRules.each { Map rule ->
            if (!(rule.enabled as Boolean)) {
                return
            }
            Pattern pattern
            try {
                pattern = Pattern.compile((rule.pattern ?: '').toString(), Pattern.CASE_INSENSITIVE | Pattern.MULTILINE)
            } catch (Exception ignored) {
                return
            }
            def matcher = pattern.matcher(joined ?: '')
            if (!matcher.find()) {
                return
            }
            String match = matcher.groupCount() >= 1 ? matcher.group(1) : matcher.group()
            out << customFinding(job, jobRef, rule, match ?: (joined ?: ''), 0.75d)
        }
        out
    }

    private Map finding(final Object job, final String jobRef, final String ruleId, final String message, final String evidence, final String severity, final double confidence) {
        Map defn = RULE_DEFS.get(ruleId) ?: [:]
        return [
            id: UUID.randomUUID().toString(),
            jobId: valueOf(job, 'id'),
            jobUuid: valueOf(job, 'uuid'),
            jobName: valueOf(job, 'jobName'),
            jobGroup: valueOf(job, 'groupPath'),
            jobRef: jobRef,
            ruleId: ruleId,
            ruleName: ruleId,
            severity: severity,
            message: message,
            description: (String) (defn.description ?: message),
            whyMatters: (String) (defn.whyMatters ?: ''),
            evidenceSnippetMasked: maskEvidence(evidence),
            remediation: defn.remediation,
            confidence: confidence
        ]
    }

    private Map customFinding(final Object job, final String jobRef, final Map rule, final String evidence, final double confidence) {
        String ruleId = (rule.id ?: 'CUSTOM_RULE').toString()
        String message = (rule.message ?: "Custom rule '${ruleId}' matched job content.").toString()
        String remediation = (rule.remediation ?: 'Review this custom finding and apply organization-specific remediation guidance.').toString()
        String severity = (rule.severity ?: 'MEDIUM').toString().toUpperCase(Locale.ROOT)
        if (!SEVERITIES.contains(severity)) {
            severity = 'MEDIUM'
        }
        String description = "Admin-defined custom rule: ${ruleId}."
        return [
            id: UUID.randomUUID().toString(),
            jobId: valueOf(job, 'id'),
            jobUuid: valueOf(job, 'uuid'),
            jobName: valueOf(job, 'jobName'),
            jobGroup: valueOf(job, 'groupPath'),
            jobRef: jobRef,
            ruleId: ruleId,
            ruleName: ruleId,
            severity: severity,
            message: message,
            description: description,
            whyMatters: 'This finding comes from an organization-defined custom detection rule.',
            evidenceSnippetMasked: maskEvidence(evidence),
            remediation: remediation,
            confidence: confidence
        ]
    }

    private String maskEvidence(final String input) {
        if (!input) {
            return ''
        }
        String stripped = input.trim().replaceAll('[\r\n]+', ' ')
        if (stripped.size() <= 8) {
            return '****'
        }
        int end = Math.min(stripped.size(), 80)
        String cut = stripped.substring(0, end)
        return cut.substring(0, Math.min(2, cut.size())) + '****' + cut.substring(Math.max(cut.size() - 2, 0))
    }

    private boolean looksLikeSensitiveLiteralInText(final String value) {
        String v = value.toLowerCase(Locale.ROOT)
        return (v =~ /(?s).*(password\s*[=:]\s*[^\s\$\{]{4,}|token\s*[=:]\s*[^\s\$\{]{8,}|api[_-]?key\s*[=:]\s*[^\s\$\{]{8,}).*/).matches()
    }

    private boolean containsEmbeddedCredentialsUrl(final String value) {
        return (value =~ /https?:\/\/[^\s:@\/]+:[^\s@\/]+@/).find()
    }

    private boolean looksLikeLiteralAuthorizationHeader(final String value) {
        String v = value.trim()
        if (!v.toLowerCase(Locale.ROOT).contains('authorization')) {
            return false
        }
        return (v =~ /(?i)authorization\s*[:=]\s*(bearer|basic)\s+[A-Za-z0-9._\-+=\/:]{8,}/).find()
    }

    private boolean isLiteralSecret(final String value) {
        String v = value?.trim() ?: ''
        if (!v || v.contains('${')) {
            return false
        }
        if (v.toLowerCase(Locale.ROOT).startsWith('keys/')) {
            return false
        }
        if (v in ['******', '********', '<redacted>', 'changeme', 'replace_me']) {
            return false
        }
        return v.length() >= 8
    }

    private boolean looksLikeRunAsRoot(final Object job, final String joined) {
        String runAs = valueOf(job, 'runAsUser') ?: valueOf(job, 'username') ?: valueOf(job, 'user')
        if (runAs?.trim()?.equalsIgnoreCase('root')) {
            return true
        }
        return (joined =~ /(?mi)\b(runAsUser\s*[:=]\s*root|sudo\s+su\s*-|\bsu\s*-\s*root\b)/).find()
    }

    private boolean containsUnpinnedGitCheckout(final String text) {
        def clone = (text =~ /(?mi)git\s+clone\s+([^\s]+)/)
        if (!clone.find()) {
            return false
        }
        boolean hasCheckoutPin = (text =~ /(?mi)git\s+checkout\s+([a-f0-9]{7,40}|v?\d+\.\d+\.\d+|[\w\-\.]+)$/).find()
        boolean clonePinned = (text =~ /(?mi)git\s+clone\s+[^\n]+(@[A-Za-z0-9._\-]+|#\w+)/).find()
        return !hasCheckoutPin && !clonePinned
    }

    private boolean containsGitRepoOutsideApproved(final String text, final List<String> approvedRepos) {
        def matcher = (text =~ /(?mi)git\s+clone\s+([^\s]+)/)
        while (matcher.find()) {
            String repo = matcher.group(1)?.toString() ?: ''
            boolean approved = approvedRepos.any { String allow -> repo.contains(allow) }
            if (!approved) {
                return true
            }
        }
        return false
    }

    private boolean hasUnrestrictedNodeTargeting(final Object job, final String joined) {
        List<String> values = [
            valueOf(job, 'nodeFilterEditable'),
            valueOf(job, 'nodeFilterEnabled'),
            valueOf(job, 'nodeFilterInclude'),
            valueOf(job, 'nodeFilterExclude'),
            valueOf(job, 'nodeInclude'),
            valueOf(job, 'nodeExclude')
        ].findAll { it }

        String combined = (values + [joined]).join(' ')
        if ((combined =~ /(?mi)nodeFilter\s*[:=]\s*(\.\*|\*)/).find()) {
            return true
        }
        if ((combined =~ /(?mi)tags?\s*[:=]\s*\*/).find()) {
            return true
        }
        return values.isEmpty()
    }

    private Map loadPolicy(final String project) {
        Map<String, String> props = loadProjectProps(project)
        String yamlText = props.get('project.plugin.JobSecurityAudit.policyYaml')
        if (!yamlText?.trim()) {
            yamlText = defaultPolicyYaml()
        }
        try {
            Object parsed = new Yaml().load(yamlText)
            if (parsed instanceof Map && ((Map) parsed).policy instanceof Map) {
                return (Map) ((Map) parsed).policy
            }
        } catch (Exception e) {
            log.warn("Failed to parse JobSecurity policy YAML: ${e.message}")
        }
        return [max_nodes: 20, allow_root_execution: false, require_vault_secrets: true, require_git_pinning: true]
    }

    private String defaultPolicyYaml() {
        return '''
policy:
  max_nodes: 20
  allow_root_execution: false
  require_vault_secrets: true
  require_git_pinning: true
'''.trim()
    }

    private Map<String, Map> loadRuleConfig(final String project) {
        Map<String, String> props = loadProjectProps(project)

        Map<String, Map> out = [:]
        RULE_DEFS.keySet().each { String ruleId ->
            Map defn = RULE_DEFS[ruleId]
            String group = (String) defn.group
            boolean enabled = props.get("project.plugin.JobSecurityAudit.rules.enabled.${group}") != 'false'
            String severity = props.get("project.plugin.JobSecurityAudit.rules.severity.${ruleId}") ?: (String) defn.defaultSeverity
            if (!SEVERITIES.contains(severity)) {
                severity = (String) defn.defaultSeverity
            }
            out[ruleId] = [enabled: enabled, severity: severity]
        }
        return out
    }

    private List<Map> loadCustomRules(final String project) {
        Map<String, String> props = loadProjectProps(project)
        return loadCustomRulesFromProps(props)
    }

    private List<Map> loadCustomRulesFromProps(final Map<String, String> props) {
        String raw = props.get(CUSTOM_RULES_PROP)
        if (!raw?.trim()) {
            return []
        }
        Object parsed
        try {
            parsed = new JsonSlurper().parseText(raw)
        } catch (Exception e) {
            log.warn("Failed to parse custom security rules JSON: ${e.message}")
            return []
        }
        return normalizeCustomRules(parsed)
    }

    private List<Map> normalizeCustomRules(final Object value) {
        if (!(value instanceof Collection)) {
            return []
        }
        List<Map> out = []
        int idx = 0
        ((Collection) value).each { Object item ->
            if (!(item instanceof Map)) {
                return
            }
            idx++
            Map rule = (Map) item
            String id = (rule.id ?: '').toString().trim().toUpperCase(Locale.ROOT).replaceAll(/[^A-Z0-9_]/, '_')
            String pattern = (rule.pattern ?: '').toString().trim()
            if (!id || !pattern) {
                return
            }
            try {
                Pattern.compile(pattern)
            } catch (Exception ignored) {
                return
            }
            String severity = (rule.severity ?: 'MEDIUM').toString().trim().toUpperCase(Locale.ROOT)
            if (!SEVERITIES.contains(severity)) {
                severity = 'MEDIUM'
            }
            String message = (rule.message ?: "Custom rule '${id}' matched job content.").toString().trim()
            String remediation = (rule.remediation ?: 'Review and remediate according to organizational policy.').toString().trim()
            boolean enabled = rule.enabled == null ? true : rule.enabled.toString().equalsIgnoreCase('true')
            out << [
                id: id,
                pattern: pattern,
                severity: severity,
                message: message,
                remediation: remediation,
                enabled: enabled
            ]
            if (out.size() >= 50) {
                return out
            }
        }
        return out
    }

    private Map<String, String> loadProjectProps(final String project) {
        Map<String, String> props = [:]
        frameworkService.loadProjectProperties(frameworkService.getFrameworkProject(project)).each { k, v ->
            props[(String) k] = v?.toString()
        }
        props
    }

    private boolean ruleEnabled(final Map<String, Map> cfg, final String ruleId) {
        return (boolean) (cfg[ruleId]?.enabled ?: false)
    }

    private String resolveSeverity(final Map<String, Map> cfg, final String ruleId) {
        return (String) (cfg[ruleId]?.severity ?: RULE_DEFS[ruleId]?.defaultSeverity ?: 'LOW')
    }

    private Map buildByJobSummary(final List<Map> findings) {
        Map<String, Map> out = [:]
        findings.each { Map finding ->
            String ref = (String) finding.jobRef
            if (!out.containsKey(ref)) {
                out[ref] = [severity: finding.severity, count: 0, jobUuid: finding.jobUuid]
            }
            out[ref].count = ((Integer) out[ref].count) + 1
            out[ref].severity = maxSeverity((String) out[ref].severity, (String) finding.severity)
        }
        return out
    }

    private String maxSeverity(final String a, final String b) {
        List<String> order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        return order.indexOf(a) >= order.indexOf(b) ? a : b
    }

    private String riskLevelForScore(final int score) {
        if (score >= 86) return 'Critical'
        if (score >= 61) return 'High'
        if (score >= 31) return 'Medium'
        return 'Low'
    }

    private Object createAuditExecution(final String project, final String user, final Date started, final Date completed, final String status, final String message, final Map summary, final List<Map> findings) {
        Class workflowClass = domainClass('rundeck.Workflow')
        Class executionClass = domainClass('rundeck.Execution')

        Object wf = workflowClass.newInstance([keepgoing: true, threadcount: 1, strategy: 'node-first', commands: []])

        Object exec = executionClass.newInstance([
            project: project,
            user: user,
            dateStarted: started,
            dateCompleted: completed,
            status: status,
            workflow: wf,
            loglevel: 'INFO',
            argString: '--job-security-audit',
            executionType: 'job-security-audit'
        ])
        exec.setExtraMetadataMap([jobSecurityAudit: [summary: summary, findings: findings, generatedAt: completed.format("yyyy-MM-dd'T'HH:mm:ssXXX")]])
        exec.save(flush: true, failOnError: true)

        File rdlogFile = logFileStorageService.getFileForExecutionFiletype(exec, 'rdlog', false, false)
        rdlogFile.parentFile.mkdirs()
        rdlogFile.text = ("""
[INFO] Security and Compliance Scan
[INFO] Project: ${project}
[INFO] ${message}
[INFO] Findings: ${findings.size()}
""".stripIndent().trim() + "\n")

        File jsonFile = logFileStorageService.getFileForExecutionFiletype(exec, 'audit.json', false, false)
        jsonFile.parentFile.mkdirs()
        jsonFile.text = JsonOutput.prettyPrint(JsonOutput.toJson([summary: summary, findings: findings]))

        exec.outputfilepath = rdlogFile.absolutePath
        exec.save(flush: true, failOnError: true)
        return exec
    }

    private void saveAuditReport(final Object exec, final String project, final String user, final String status, final String message) {
        SaveReportRequestImpl request = new SaveReportRequestImpl(
            executionId: exec.id as Long,
            executionUuid: exec.uuid?.toString(),
            dateStarted: (Date) exec.dateStarted,
            dateCompleted: (Date) exec.dateCompleted,
            project: project,
            reportId: 'job-security-audit',
            author: user,
            title: 'Security and Compliance Scan',
            status: status == 'succeeded' ? 'succeed' : 'fail',
            node: '0/0/0',
            message: message,
            adhocExecution: true
        )
        def result = reportService.reportExecutionResult(request)
        if (result?.error) {
            log.warn("Failed writing security audit report entry: ${result.errors}")
        }
    }

    private Class domainClass(String fqcn) {
        return grailsApplication.classLoader.loadClass(fqcn)
    }

    private String valueOf(final Object obj, final String prop) {
        try {
            def value = obj?."${prop}"
            return value != null ? value.toString() : null
        } catch (Throwable ignored) {
            return null
        }
    }
}
