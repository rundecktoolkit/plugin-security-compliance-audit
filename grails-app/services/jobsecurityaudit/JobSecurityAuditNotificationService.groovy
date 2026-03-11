package jobsecurityaudit

import groovy.json.JsonOutput

class JobSecurityAuditNotificationService {
    def frameworkService
    def mailService
    def grailsApplication

    Map sendNotifications(
        final String project,
        final String triggeredBy,
        final Map summary,
        final List<Map> findings,
        final String executionLink,
        final Map aiReport = null
    ) {
        Map<String, String> props = getProjectProps(project)
        String webhookUrl = props.get('project.plugin.JobSecurityAudit.webhookUrl')
        List<String> emailRecipients = resolveEmailRecipients(props)

        Map payload = [
            type: 'rundeck.jobSecurityAudit.notification',
            project: project,
            triggeredBy: triggeredBy,
            sentAt: new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX"),
            summary: summary,
            findings: findings,
            aiReport: aiReport,
            links: [execution: executionLink]
        ]

        Map result = [
            webhookSent: false,
            emailSent: false,
            emailRecipients: emailRecipients,
            errors: []
        ]

        if (webhookUrl) {
            try {
                postWebhook(webhookUrl, payload)
                result.webhookSent = true
            } catch (Exception e) {
                log.warn("JobSecurityAudit webhook notification failed: ${e.message}", e)
                ((List) result.errors) << "Webhook send failed: ${e.message}"
            }
        }

        if (emailRecipients) {
            try {
                sendEmail(emailRecipients, project, summary, findings, executionLink, aiReport)
                result.emailSent = true
            } catch (Exception e) {
                log.warn("JobSecurityAudit email notification failed: ${e.message}", e)
                ((List) result.errors) << "Email send failed: ${e.message}"
            }
        } else {
            ((List) result.errors) << 'Email not sent: no valid notification recipient configured (selected user missing email or no email recipients set).'
        }

        return result
    }

    private void postWebhook(final String urlString, final Map payload) {
        URL url = new URL(urlString)
        HttpURLConnection connection = (HttpURLConnection) url.openConnection()
        connection.setRequestMethod('POST')
        connection.setRequestProperty('Content-Type', 'application/json')
        connection.setConnectTimeout(5000)
        connection.setReadTimeout(8000)
        connection.setDoOutput(true)
        connection.outputStream.withWriter('UTF-8') { it << JsonOutput.toJson(payload) }
        int code = connection.responseCode
        if (code < 200 || code >= 300) {
            throw new IllegalStateException("Webhook returned HTTP ${code}")
        }
    }

    private void sendEmail(
        final List<String> recipients,
        final String project,
        final Map summary,
        final List<Map> findings,
        final String executionLink,
        final Map aiReport
    ) {
        List<String> recipientsList = (recipients ?: []).collect { String v -> v?.trim() }.findAll { String v -> v }
        if (!recipientsList) {
            return
        }
        String subject = "[Rundeck] Job Security Audit - ${project}"
        String body = """
Job Security Audit notification

Project: ${project}
Execution: ${summary.executionId}
Status: ${summary.status}
Risk counts: HIGH=${summary.riskCounts?.HIGH ?: 0}, MEDIUM=${summary.riskCounts?.MEDIUM ?: 0}, LOW=${summary.riskCounts?.LOW ?: 0}
Risky jobs: ${summary.riskyJobs ?: 0}
Top findings sent: ${findings?.size() ?: 0}
Link: ${executionLink}

${buildAiReportEmailSection(aiReport)}
""".stripIndent().trim()

        mailService.sendMail {
            to(*recipientsList)
            subject(subject)
            text(body)
        }
    }

    private List<String> resolveEmailRecipients(final Map<String, String> props) {
        String selectedUser = props.get('project.plugin.JobSecurityAudit.emailRecipientUser')?.trim()
        String selectedUserEmail = selectedUser ? lookupUserEmail(selectedUser) : ''
        List<String> configured = (props.get('project.plugin.JobSecurityAudit.emailRecipients') ?: '')
            .split(',')
            .collect { String v -> v?.trim() }
            .findAll { String v -> v }
        if (selectedUserEmail) {
            return [selectedUserEmail]
        }
        if (configured) {
            return configured
        }
        return []
    }

    private String lookupUserEmail(final String login) {
        try {
            def dc = grailsApplication.getDomainClass('rundeck.User')
            if (!dc?.clazz) {
                return ''
            }
            Object user = dc.clazz.findByLogin(login)
            return user?.email?.toString()?.trim() ?: ''
        } catch (Exception e) {
            log.debug("JobSecurityAudit failed to resolve email for user '${login}': ${e.message}")
            return ''
        }
    }

    private static String buildAiReportEmailSection(final Map aiReport) {
        if (!(aiReport instanceof Map) || !aiReport) {
            return ''
        }
        String managementSummary = aiReport.managementSummary?.toString()?.trim() ?: 'N/A'
        List details = aiReport.detailedFindings instanceof Collection ? (List) aiReport.detailedFindings : []
        List recs = aiReport.recommendations instanceof Collection ? (List) aiReport.recommendations : []
        String detailsText = details ? details.collect { "- ${it}" }.join('\n') : '- N/A'
        String recsText = recs ? recs.collect { "- ${it}" }.join('\n') : '- N/A'
        """
AI Report (Preview)
Management summary:
${managementSummary}

Detailed findings:
${detailsText}

Recommendations:
${recsText}
""".stripIndent()
    }

    private Map<String, String> getProjectProps(final String project) {
        def p = frameworkService.getFrameworkProject(project)
        Map props = frameworkService.loadProjectProperties(p)
        Map<String, String> out = [:]
        props.each { k, v -> out[(String) k] = v?.toString() }
        out
    }
}
