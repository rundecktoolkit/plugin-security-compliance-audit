package jobsecurityaudit

import com.dtolabs.rundeck.core.authorization.AuthContextProvider
import com.dtolabs.rundeck.core.authorization.AuthContextEvaluator
import grails.converters.JSON
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import org.rundeck.core.auth.AuthConstants
import java.util.Locale

@Controller
class JobSecurityAuditController {
    JobSecurityAuditService jobSecurityAuditService
    JobSecurityAuditNotificationService jobSecurityAuditNotificationService
    JobSecurityAuditLlmService jobSecurityAuditLlmService
    JobSecurityAuditLlmCacheService jobSecurityAuditLlmCacheService
    AuthContextProvider rundeckAuthContextProvider
    AuthContextEvaluator rundeckAuthContextEvaluator

    @Get(uri = '/project/{project}/jobSecurity/admin')
    def admin() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        render(view: '/jobSecurityAudit/admin')
    }

    @Post(uri = '/project/{project}/jobSecurity/scan')
    def scan() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        try {
            def payload = jobSecurityAuditService.runScan(params.project, session.user?.toString(), authContext)
            render(contentType: 'application/json', text: [success: true] + payload as JSON)
        } catch (Exception e) {
            log.error("Job security audit scan failed: ${e.message}", e)
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Get(uri = '/project/{project}/jobSecurity/results/latest')
    def resultsLatest() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        def payload = jobSecurityAuditService.latestForProject(params.project, authContext)
        if (!payload) {
            response.status = 404
            render(contentType: 'application/json', text: [success: false, error: 'No scan results found for project'] as JSON)
            return
        }

        render(contentType: 'application/json', text: [success: true] + payload as JSON)
    }

    @Get(uri = '/project/{project}/jobSecurity/results/{executionId}')
    def resultsByExecution() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        Long executionId = params.long('executionId')
        def payload = jobSecurityAuditService.byExecutionId(params.project, executionId, authContext)
        if (!payload) {
            response.status = 404
            render(contentType: 'application/json', text: [success: false, error: 'Execution result not found'] as JSON)
            return
        }

        render(contentType: 'application/json', text: [success: true] + payload as JSON)
    }

    @Post(uri = '/project/{project}/jobSecurity/notify')
    def notifyFindings() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        def body = request.JSON ?: [:]
        Long executionId = body.executionId ? Long.valueOf(body.executionId.toString()) : null
        List<String> selectedFindingIds = (body.selectedFindingIds instanceof Collection) ?
            ((Collection) body.selectedFindingIds).collect { it.toString() } : []
        Map aiReport = body.aiReport instanceof Map ? (Map) body.aiReport : null

        def payload = executionId ?
            jobSecurityAuditService.byExecutionId(params.project, executionId, authContext) :
            jobSecurityAuditService.latestForProject(params.project, authContext)

        if (!payload) {
            response.status = 404
            render(contentType: 'application/json', text: [success: false, error: 'No scan data to notify'] as JSON)
            return
        }

        List<Map> findings = ((List<Map>) payload.findings) ?: []
        if (selectedFindingIds) {
            findings = findings.findAll { Map f -> selectedFindingIds.contains(f.id?.toString()) }
        }

        String executionLink = createLink(
            controller: 'execution',
            action: 'show',
            id: payload.summary?.executionId,
            params: [project: params.project],
            absolute: true
        )

        Map sendResult = jobSecurityAuditNotificationService.sendNotifications(
            params.project,
            session.user?.toString(),
            (Map) payload.summary,
            findings,
            executionLink,
            aiReport
        )

        render(contentType: 'application/json', text: [success: true, notification: sendResult] as JSON)
    }

    @Post(uri = '/project/{project}/jobSecurity/llm/generate')
    def generateLlmReport() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        try {
            Map body = (Map) (request.JSON ?: [:])
            Long executionId = body.executionId ? Long.valueOf(body.executionId.toString()) : null
            if (!executionId) {
                response.status = 400
                render(contentType: 'application/json', text: [success: false, error: 'executionId is required'] as JSON)
                return
            }
            List<String> selectedFindingIds = (body.selectedFindingIds instanceof Collection) ?
                ((Collection) body.selectedFindingIds).collect { it.toString() } : []
            String customPrompt = body.customPrompt?.toString()

            Map payload = jobSecurityAuditService.byExecutionId(params.project, executionId, authContext)
            if (!payload) {
                response.status = 404
                render(contentType: 'application/json', text: [success: false, error: 'Execution result not found'] as JSON)
                return
            }

            List<Map> findings = ((List<Map>) payload.findings) ?: []
            if (selectedFindingIds) {
                findings = findings.findAll { Map f -> selectedFindingIds.contains(f.id?.toString()) }
            }
            if (!findings) {
                response.status = 400
                render(contentType: 'application/json', text: [success: false, error: 'No findings selected for AI report generation'] as JSON)
                return
            }

            String userKey = session.user?.toString() ?: 'unknown'
            Map generated = jobSecurityAuditLlmService.generateReport(
                params.project,
                userKey,
                authContext,
                (Map) payload.summary,
                findings,
                customPrompt
            )
            jobSecurityAuditLlmCacheService.save(params.project, executionId, userKey, generated)
            render(contentType: 'application/json', text: [success: true, executionId: executionId] + generated as JSON)
        } catch (Exception e) {
            log.error("Job security audit AI report generation failed: ${e.message}", e)
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Get(uri = '/project/{project}/jobSecurity/llm/download/{executionId}')
    def downloadLlmReport() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        Long executionId = params.long('executionId')
        String format = (params.format ?: 'md').toString().toLowerCase(Locale.ROOT)
        String user = session.user?.toString() ?: 'unknown'
        Map cached = jobSecurityAuditLlmCacheService.get(params.project, executionId, user)
        if (!cached) {
            response.status = 404
            render(contentType: 'application/json', text: [success: false, error: 'AI report not found in cache. Generate it again first.'] as JSON)
            return
        }
        String markdown = cached.rendered?.markdown?.toString() ?: ''
        String text = cached.rendered?.text?.toString() ?: ''
        String filePrefix = "security-compliance-report-${params.project}-${executionId}"

        if (format == 'txt') {
            response.setHeader('Content-Disposition', "attachment; filename=\"${filePrefix}.txt\"")
            render(contentType: 'text/plain', text: text)
            return
        }
        if (format != 'md') {
            response.status = 400
            render(contentType: 'application/json', text: [success: false, error: 'Unsupported format. Use md or txt.'] as JSON)
            return
        }
        response.setHeader('Content-Disposition', "attachment; filename=\"${filePrefix}.md\"")
        render(contentType: 'text/markdown', text: markdown)
    }

    @Post(uri = '/project/{project}/jobSecurity/llm/models')
    def discoverLlmModels() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        try {
            Map body = (Map) (request.JSON ?: [:])
            Map overrides = [
                provider: body.provider,
                endpointUrl: body.endpointUrl,
                model: body.model,
                username: body.username,
                vaultApiKeyPath: body.vaultApiKeyPath,
                promptTemplate: body.promptTemplate
            ]
            List<String> models = jobSecurityAuditLlmService.discoverModels(params.project, authContext, overrides)
            render(contentType: 'application/json', text: [success: true, models: models] as JSON)
        } catch (Exception e) {
            log.warn("Job security audit model discovery failed: ${e.message}")
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Get(uri = '/project/{project}/jobSecurity/llm/vaultKeys')
    def listLlmVaultKeys() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        try {
            int max = params.int('max') ?: 500
            List<String> keyPaths = jobSecurityAuditLlmService.listVaultKeyPaths(authContext, 'keys', max)
            render(contentType: 'application/json', text: [success: true, keyPaths: keyPaths] as JSON)
        } catch (Exception e) {
            log.warn("Job security audit vault key listing failed: ${e.message}")
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Post(uri = '/project/{project}/jobSecurity/llm/test')
    def testLlmConnection() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResourceAny(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            [AuthConstants.ACTION_ADMIN, AuthConstants.ACTION_APP_ADMIN],
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        try {
            Map body = (Map) (request.JSON ?: [:])
            Map overrides = [
                provider: body.provider,
                endpointUrl: body.endpointUrl,
                model: body.model,
                username: body.username,
                vaultApiKeyPath: body.vaultApiKeyPath,
                promptTemplate: body.promptTemplate
            ]
            Map result = jobSecurityAuditLlmService.testConnection(params.project, authContext, overrides)
            render(contentType: 'application/json', text: [success: true, test: result] as JSON)
        } catch (Exception e) {
            log.warn("Job security audit LLM connectivity test failed: ${e.message}")
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Post(uri = '/project/{project}/jobSecurity/llm/diagnose')
    def diagnoseLlmConnection() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResourceAny(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            [AuthConstants.ACTION_ADMIN, AuthConstants.ACTION_APP_ADMIN],
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        try {
            Map body = (Map) (request.JSON ?: [:])
            Map overrides = [
                provider: body.provider,
                endpointUrl: body.endpointUrl,
                model: body.model,
                username: body.username,
                vaultApiKeyPath: body.vaultApiKeyPath,
                promptTemplate: body.promptTemplate
            ]
            Map result = jobSecurityAuditLlmService.diagnoseConnection(params.project, authContext, overrides)
            render(contentType: 'application/json', text: [success: true, diagnosis: result] as JSON)
        } catch (Exception e) {
            log.warn("Job security audit LLM diagnostic failed: ${e.message}")
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Get(uri = '/project/{project}/jobSecurity/settings')
    def settings() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        render(contentType: 'application/json', text: [success: true, settings: jobSecurityAuditService.settingsForProject(params.project)] as JSON)
    }

    @Post(uri = '/project/{project}/jobSecurity/settings')
    def saveSettings() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResourceAny(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            [AuthConstants.ACTION_ADMIN, AuthConstants.ACTION_APP_ADMIN],
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }

        try {
            Map body = (Map) (request.JSON ?: [:])
            Map saved = jobSecurityAuditService.saveSettingsForProject(params.project, body)
            render(contentType: 'application/json', text: [success: true, settings: saved] as JSON)
        } catch (Exception e) {
            log.error("Job security audit settings save failed: ${e.message}", e)
            response.status = 500
            render(contentType: 'application/json', text: [success: false, error: e.message] as JSON)
        }
    }

    @Get(uri = '/project/{project}/jobSecurity/users')
    def users() {
        def authContext = rundeckAuthContextProvider.getAuthContextForSubjectAndProject(session.subject, params.project)
        if (!rundeckAuthContextEvaluator.authorizeProjectResource(
            authContext,
            AuthConstants.RESOURCE_TYPE_EVENT,
            AuthConstants.ACTION_READ,
            params.project
        )) {
            response.status = 403
            render(contentType: 'application/json', text: [success: false, error: 'Unauthorized'] as JSON)
            return
        }
        render(contentType: 'application/json', text: [success: true, users: jobSecurityAuditService.listUsers()] as JSON)
    }
}
