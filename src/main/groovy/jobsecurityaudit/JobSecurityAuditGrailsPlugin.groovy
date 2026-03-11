package jobsecurityaudit

import grails.plugins.Plugin
import jobsecurityaudit.menu.JobSecurityAuditMenuItem
import jobsecurityaudit.ui.UIJobSecurityAuditBadgesFactory

class JobSecurityAuditGrailsPlugin extends Plugin {
    def grailsVersion = "4.0.3 > *"
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    def title = "Job Security Audit"
    def author = "Rundeck OSS"
    def authorEmail = ""
    def description = '''Manual job security scanning with activity-backed audit runs.'''
    def profiles = ['web']

    Closure doWithSpring() {{->
        if (application.config.getProperty("rundeck.feature.jobSecurityAudit.enabled", Boolean.class, true)) {
            jobSecurityAuditMenuItem(JobSecurityAuditMenuItem)
            uIJobSecurityAuditBadges(UIJobSecurityAuditBadgesFactory) {
                pluginRegistry = ref('rundeckPluginRegistry')
            }
        }
    }}
}
