package jobsecurityaudit

class UrlMappings {

    static mappings = {
        if (getGrailsApplication().config.getProperty("rundeck.feature.jobSecurityAudit.enabled", Boolean.class, true)) {
            "/project/$project/jobSecurity/admin"(controller: 'jobSecurityAudit', action: 'admin')
            "/project/$project/jobSecurity/scan"(controller: 'jobSecurityAudit') {
                action = [POST: 'scan']
            }
            "/project/$project/jobSecurity/results/latest"(controller: 'jobSecurityAudit', action: 'resultsLatest')
            "/project/$project/jobSecurity/results/$executionId"(controller: 'jobSecurityAudit', action: 'resultsByExecution')
            "/project/$project/jobSecurity/settings"(controller: 'jobSecurityAudit') {
                action = [GET: 'settings', POST: 'saveSettings']
            }
            "/project/$project/jobSecurity/users"(controller: 'jobSecurityAudit', action: 'users')
            "/project/$project/jobSecurity/notify"(controller: 'jobSecurityAudit') {
                action = [POST: 'notifyFindings']
            }
            "/project/$project/jobSecurity/llm/generate"(controller: 'jobSecurityAudit') {
                action = [POST: 'generateLlmReport']
            }
            "/project/$project/jobSecurity/llm/models"(controller: 'jobSecurityAudit') {
                action = [POST: 'discoverLlmModels']
            }
            "/project/$project/jobSecurity/llm/vaultKeys"(controller: 'jobSecurityAudit', action: 'listLlmVaultKeys')
            "/project/$project/jobSecurity/llm/test"(controller: 'jobSecurityAudit') {
                action = [POST: 'testLlmConnection']
            }
            "/project/$project/jobSecurity/llm/diagnose"(controller: 'jobSecurityAudit') {
                action = [POST: 'diagnoseLlmConnection']
            }
            "/project/$project/jobSecurity/llm/download/$executionId"(controller: 'jobSecurityAudit', action: 'downloadLlmReport')
        }
    }
}
