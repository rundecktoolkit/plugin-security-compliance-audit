package jobsecurityaudit

import com.dtolabs.rundeck.core.authorization.AuthContext
import groovy.json.JsonOutput
import groovy.json.JsonSlurper

import java.io.InputStream
import java.net.URLEncoder
import java.security.MessageDigest
import java.nio.charset.StandardCharsets
import java.util.Locale

class JobSecurityAuditLlmService {
    private static final int CONNECT_TIMEOUT_MS = 8000
    private static final int READ_TIMEOUT_MS = 20000
    private static final int DEFAULT_MAX_VAULT_KEYS = 500
    private static final int MAX_PROVIDER_ERROR_LEN = 500
    private static final List<String> SUPPORTED_PROVIDERS = ['openai', 'anthropic', 'google', 'custom']

    def frameworkService
    def storageService
    JobSecurityAuditReportRenderService jobSecurityAuditReportRenderService

    Map generateReport(
        final String project,
        final String user,
        final AuthContext authContext,
        final Map summary,
        final List<Map> selectedFindings,
        final String customPrompt
    ) {
        Map settings = loadLlmSettings(project)
        validateSettings(settings)

        String apiKey = readVaultKey(settings.vaultApiKeyPath as String, authContext)
        String prompt = (customPrompt ?: settings.promptTemplate ?: defaultPromptTemplate()).toString().trim()

        Map safeSummary = [
            executionId: summary?.executionId,
            scannedAt: summary?.scannedAt,
            riskScore: summary?.riskScore,
            riskLevel: summary?.riskLevel,
            riskCounts: summary?.riskCounts ?: [:],
            riskyJobs: summary?.riskyJobs ?: 0
        ]
        List<Map> safeFindings = sanitizeFindings(selectedFindings ?: [])

        String provider = resolveProvider(settings)
        String endpoint = resolveInferenceEndpoint(settings)
        Map requestBody = buildProviderRequestBody(provider, settings, project, user, safeSummary, safeFindings, prompt)
        Map rawResponse = postToLlm(provider, endpoint, apiKey, requestBody, settings)
        Map structured = parseStructuredReport(rawResponse)

        Map rendered = jobSecurityAuditReportRenderService.render(project, safeSummary, structured)
        return [
            summary: safeSummary,
            report: structured,
            rendered: rendered,
            modelInfo: [provider: provider, endpointUrl: endpoint, model: settings.model]
        ]
    }

    List<String> discoverModels(
        final String project,
        final AuthContext authContext,
        final Map overrides = [:]
    ) {
        Map settings = loadLlmSettings(project)
        Map runtime = [
            enabled: true,
            provider: (overrides?.provider ?: settings.provider ?: '').toString().trim(),
            endpointUrl: (overrides?.endpointUrl ?: settings.endpointUrl ?: '').toString().trim(),
            model: (overrides?.model ?: settings.model ?: '').toString().trim(),
            username: (overrides?.username ?: settings.username ?: '').toString().trim(),
            vaultApiKeyPath: (overrides?.vaultApiKeyPath ?: settings.vaultApiKeyPath ?: '').toString().trim(),
            promptTemplate: (overrides?.promptTemplate ?: settings.promptTemplate ?: defaultPromptTemplate()).toString()
        ]
        validateSettings(runtime, false)
        String apiKey = readVaultKey(runtime.vaultApiKeyPath as String, authContext)
        String provider = resolveProvider(runtime)
        return fetchModels(provider, runtime, apiKey)
    }

    Map testConnection(
        final String project,
        final AuthContext authContext,
        final Map overrides
    ) {
        Map settings = loadLlmSettings(project)
        Map runtime = [
            enabled: true,
            provider: (overrides?.provider ?: settings.provider ?: '').toString().trim(),
            endpointUrl: (overrides?.endpointUrl ?: settings.endpointUrl ?: '').toString().trim(),
            model: (overrides?.model ?: settings.model ?: '').toString().trim(),
            username: (overrides?.username ?: settings.username ?: '').toString().trim(),
            vaultApiKeyPath: (overrides?.vaultApiKeyPath ?: settings.vaultApiKeyPath ?: '').toString().trim(),
            promptTemplate: (overrides?.promptTemplate ?: settings.promptTemplate ?: defaultPromptTemplate()).toString()
        ]
        validateSettings(runtime, false)
        String apiKey = readVaultKey(runtime.vaultApiKeyPath as String, authContext)
        String provider = resolveProvider(runtime)
        String modelsEndpoint = deriveModelsEndpoint(provider, runtime)
        List<String> models = fetchModels(provider, runtime, apiKey)
        boolean modelFound = runtime.model ? models.contains(runtime.model as String) : false
        String modelMessage = runtime.model ?
            (modelFound ? "Configured model '${runtime.model}' was found." : "Configured model '${runtime.model}' was not returned by provider discovery.") :
            'No model configured yet.'
        return [
            ok: true,
            modelsEndpoint: modelsEndpoint,
            discoveredModelCount: models.size(),
            discoveredModels: models.take(50),
            modelFound: modelFound,
            message: "Connection successful. ${modelMessage}"
        ]
    }

    Map diagnoseConnection(
        final String project,
        final AuthContext authContext,
        final Map overrides
    ) {
        Map settings = loadLlmSettings(project)
        Map runtime = [
            enabled: true,
            provider: (overrides?.provider ?: settings.provider ?: '').toString().trim(),
            endpointUrl: (overrides?.endpointUrl ?: settings.endpointUrl ?: '').toString().trim(),
            model: (overrides?.model ?: settings.model ?: '').toString().trim(),
            username: (overrides?.username ?: settings.username ?: '').toString().trim(),
            vaultApiKeyPath: (overrides?.vaultApiKeyPath ?: settings.vaultApiKeyPath ?: '').toString().trim(),
            promptTemplate: (overrides?.promptTemplate ?: settings.promptTemplate ?: defaultPromptTemplate()).toString()
        ]
        validateSettings(runtime, false)
        String apiKey = readVaultKey(runtime.vaultApiKeyPath as String, authContext)
        String provider = resolveProvider(runtime)
        String modelsEndpoint = deriveModelsEndpoint(provider, runtime)
        Map probe = probeModelsEndpoint(provider, modelsEndpoint, apiKey)
        return [
            ok: (probe.status as Integer) >= 200 && (probe.status as Integer) < 300,
            provider: provider,
            vaultApiKeyPath: runtime.vaultApiKeyPath,
            keyLength: apiKey.length(),
            keyFingerprint: fingerprint(apiKey),
            looksLikeOpenAiKey: apiKey.startsWith('sk-'),
            modelsEndpoint: modelsEndpoint,
            probeStatus: probe.status,
            probeMessage: probe.body ?: ''
        ]
    }

    List<String> listVaultKeyPaths(
        final AuthContext authContext,
        final String rootPath = 'keys',
        final int maxResults = DEFAULT_MAX_VAULT_KEYS
    ) {
        int limit = maxResults > 0 ? maxResults : DEFAULT_MAX_VAULT_KEYS
        String root = normalizeStoragePath(rootPath ?: 'keys')
        LinkedHashSet<String> found = new LinkedHashSet<>()
        LinkedHashSet<String> visited = new LinkedHashSet<>()
        ArrayDeque<String> queue = new ArrayDeque<>()
        queue.add(root)

        while (!queue.isEmpty() && found.size() < limit) {
            String path = queue.removeFirst()
            if (!visited.add(path)) {
                continue
            }
            Collection dir
            try {
                dir = (Collection) (storageService.listDir(authContext, path) ?: [])
            } catch (Exception ignored) {
                continue
            }

            dir.each { Object entry ->
                String entryPath = normalizeStoragePath(extractPath(entry))
                if (!entryPath) {
                    return
                }
                if (isDirectoryEntry(entry)) {
                    if (!visited.contains(entryPath)) {
                        queue.add(entryPath)
                    }
                    return
                }
                found.add(stripLeadingSlash(entryPath))
            }
        }
        return (found as List<String>).sort(false)
    }

    private static boolean isDirectoryEntry(final Object entry) {
        if (entry == null) {
            return false
        }
        if (entry instanceof Map) {
            return ((Map) entry).directory == true || 'directory'.equalsIgnoreCase(((Map) entry).type?.toString())
        }
        return entry.hasProperty('directory') ? (entry.directory == true) : false
    }

    private static String extractPath(final Object entry) {
        if (entry == null) {
            return ''
        }
        if (entry instanceof Map) {
            Object value = ((Map) entry).path
            return value?.toString() ?: ''
        }
        if (entry.hasProperty('path')) {
            return entry.path?.toString() ?: ''
        }
        return ''
    }

    private static String normalizeStoragePath(final String path) {
        String p = (path ?: '').trim()
        if (!p) {
            return ''
        }
        if (!p.startsWith('/')) {
            p = '/' + p
        }
        return p.replaceAll('/+', '/')
    }

    private static String stripLeadingSlash(final String value) {
        String v = (value ?: '').trim()
        while (v.startsWith('/')) {
            v = v.substring(1)
        }
        return v
    }

    private Map loadLlmSettings(final String project) {
        def p = frameworkService.getFrameworkProject(project)
        Map props = frameworkService.loadProjectProperties(p)
        return [
            enabled: (props['project.plugin.JobSecurityAudit.llm.enabled']?.toString() ?: 'false').equalsIgnoreCase('true'),
            provider: props['project.plugin.JobSecurityAudit.llm.provider']?.toString() ?: '',
            endpointUrl: props['project.plugin.JobSecurityAudit.llm.endpointUrl']?.toString() ?: '',
            model: props['project.plugin.JobSecurityAudit.llm.model']?.toString() ?: '',
            username: props['project.plugin.JobSecurityAudit.llm.username']?.toString() ?: '',
            vaultApiKeyPath: props['project.plugin.JobSecurityAudit.llm.vaultApiKeyPath']?.toString() ?: '',
            promptTemplate: props['project.plugin.JobSecurityAudit.llm.promptTemplate']?.toString() ?: defaultPromptTemplate()
        ]
    }

    private static String deriveModelsEndpoint(final String provider, final Map settings) {
        String url = resolveBaseEndpoint(provider, settings)
        if (!url) {
            return ''
        }
        if (provider == 'google') {
            String base = url.replaceAll(/\?.*$/, '')
            base = base.replaceAll('/models/[^/]+:(generateContent|streamGenerateContent)$', '')
            base = base.replaceAll('/v1beta/.*$', '/v1beta/models')
            if (base.endsWith('/v1beta/models')) {
                return base
            }
            return base.endsWith('/') ? (base + 'models') : (base + '/models')
        }
        if (provider == 'anthropic') {
            url = url.replaceAll('/v1/messages$', '/v1/models')
            if (url.endsWith('/v1/models')) {
                return url
            }
            return url.replaceAll('/v1/.*$', '/v1/models')
        }
        url = url.replaceAll('/v1/responses$', '/v1/models')
        url = url.replaceAll('/v1/chat/completions$', '/v1/models')
        if (url.endsWith('/v1/models')) {
            return url
        }
        if (url.contains('/v1/')) {
            return url.replaceAll('/v1/.*$', '/v1/models')
        }
        return url + '/v1/models'
    }

    private static String resolveBaseEndpoint(final String provider, final Map settings) {
        String url = (settings?.endpointUrl ?: '').toString().trim()
        if (!url) {
            return ''
        }
        if (provider == 'google') {
            url = url.replace('{model}', settings?.model?.toString()?.trim() ?: '')
        }
        if (url.endsWith('/')) {
            url = url.substring(0, url.length() - 1)
        }
        return url
    }

    private static String resolveInferenceEndpoint(final Map settings) {
        String provider = resolveProvider(settings)
        return resolveBaseEndpoint(provider, settings)
    }

    private static String resolveProvider(final Map settings) {
        String explicit = (settings?.provider ?: '').toString().trim().toLowerCase(Locale.ROOT)
        if (SUPPORTED_PROVIDERS.contains(explicit)) {
            return explicit
        }
        String url = (settings?.endpointUrl ?: '').toString().toLowerCase(Locale.ROOT)
        if (url.contains('api.anthropic.com')) {
            return 'anthropic'
        }
        if (url.contains('generativelanguage.googleapis.com')) {
            return 'google'
        }
        if (url.contains('api.openai.com')) {
            return 'openai'
        }
        return 'custom'
    }

    private static String buildProviderInputText(
        final String project,
        final String user,
        final Map safeSummary,
        final List<Map> safeFindings,
        final String prompt
    ) {
        Map payload = [
            project: project,
            triggeredBy: user,
            summary: safeSummary,
            findings: safeFindings
        ]
        return """${prompt}

Use the following masked scan data as your only source of truth.
Return strict JSON with keys: managementSummary, detailedFindings, recommendations.

SCAN_DATA_JSON:
${JsonOutput.toJson(payload)}
""".trim()
    }

    private static Map buildProviderRequestBody(
        final String provider,
        final Map settings,
        final String project,
        final String user,
        final Map safeSummary,
        final List<Map> safeFindings,
        final String prompt
    ) {
        String inputText = buildProviderInputText(project, user, safeSummary, safeFindings, prompt)
        if (provider == 'anthropic') {
            return [
                model: settings.model,
                max_tokens: 1800,
                system: prompt,
                messages: [[role: 'user', content: inputText]]
            ]
        }
        if (provider == 'google') {
            return [
                contents: [[role: 'user', parts: [[text: inputText]]]],
                generationConfig: [responseMimeType: 'application/json']
            ]
        }
        if (provider == 'custom') {
            Map body = [
                model: settings.model,
                input: [
                    project: project,
                    triggeredBy: user,
                    summary: safeSummary,
                    findings: safeFindings,
                    promptTemplate: prompt
                ]
            ]
            if (settings.username) {
                body.username = settings.username
            }
            return body
        }
        Map body = [
            model: settings.model,
            input: inputText
        ]
        if (settings.username) {
            body.user = settings.username
        }
        return body
    }

    private static void validateSettings(final Map settings, final boolean requireModel = true) {
        if (!(settings.enabled as Boolean)) {
            throw new IllegalStateException('AI report enrichment is disabled for this project.')
        }
        String provider = resolveProvider(settings)
        if (!SUPPORTED_PROVIDERS.contains(provider)) {
            throw new IllegalStateException("Unsupported AI provider: ${provider}")
        }
        if (!(settings.endpointUrl as String)) {
            throw new IllegalStateException('LLM endpoint URL is not configured.')
        }
        if (requireModel && !(settings.model as String)) {
            throw new IllegalStateException('LLM model is not configured.')
        }
        if (!(settings.vaultApiKeyPath as String)) {
            throw new IllegalStateException('LLM vault API key path is not configured.')
        }
    }

    private String readVaultKey(final String keyPath, final AuthContext authContext) {
        def keystore = storageService.storageTreeWithContext(authContext)
        if (!keystore.hasPassword(keyPath)) {
            throw new IllegalStateException("Vault key path not found or inaccessible: ${keyPath}")
        }
        Object raw = keystore.readPassword(keyPath)
        String value = decodePasswordSecret(raw)
        if (!value?.trim()) {
            throw new IllegalStateException('Vault key value is empty.')
        }
        return value.trim()
    }

    private Map postToLlm(final String provider, final String endpointUrl, final String apiKey, final Map body, final Map settings) {
        URL url = new URL(withGoogleApiKey(provider, endpointUrl, apiKey))
        HttpURLConnection connection = (HttpURLConnection) url.openConnection()
        connection.setRequestMethod('POST')
        connection.setRequestProperty('Content-Type', 'application/json')
        applyProviderHeaders(connection, provider, apiKey)
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS)
        connection.setReadTimeout(READ_TIMEOUT_MS)
        connection.setDoOutput(true)
        connection.outputStream.withWriter('UTF-8') { it << JsonOutput.toJson(body) }

        int code = connection.responseCode
        String raw = ''
        try {
            InputStream in = (code >= 200 && code < 300) ? connection.inputStream : connection.errorStream
            raw = in?.getText('UTF-8') ?: ''
        } finally {
            connection.disconnect()
        }
        if (code < 200 || code >= 300) {
            String details = sanitizeProviderError(raw)
            throw new IllegalStateException("LLM endpoint returned HTTP ${code}${details ? ': ' + details : ''}")
        }
        if (!raw?.trim()) {
            throw new IllegalStateException('LLM endpoint returned empty response.')
        }
        def parsed = new JsonSlurper().parseText(raw)
        if (!(parsed instanceof Map)) {
            throw new IllegalStateException('LLM response is not a JSON object.')
        }
        return (Map) parsed
    }

    private static List<Map> sanitizeFindings(final List<Map> findings) {
        findings.collect { Map f ->
            [
                id: f.id,
                ruleId: f.ruleId,
                ruleName: f.ruleName,
                severity: f.severity,
                jobRef: f.jobRef,
                description: f.description ?: f.message,
                whyMatters: f.whyMatters,
                evidenceSnippetMasked: f.evidenceSnippetMasked,
                remediation: f.remediation,
                confidence: f.confidence
            ]
        }
    }

    private static Map parseStructuredReport(final Map rawResponse) {
        Object direct = rawResponse.report ?: rawResponse
        Map candidate = (direct instanceof Map) ? (Map) direct : [:]
        if (hasRequiredSections(candidate)) {
            return normalizeReport(candidate)
        }

        String content = extractContentText(rawResponse)
        if (!content) {
            throw new IllegalStateException('LLM response did not include report content.')
        }
        Map parsedContent = parseJsonObjectFromText(content)
        if (!hasRequiredSections(parsedContent)) {
            throw new IllegalStateException('LLM response missing required sections (managementSummary, detailedFindings, recommendations).')
        }
        return normalizeReport(parsedContent)
    }

    private static boolean hasRequiredSections(final Map report) {
        report?.containsKey('managementSummary') &&
            report?.containsKey('detailedFindings') &&
            report?.containsKey('recommendations')
    }

    private static Map normalizeReport(final Map report) {
        return [
            managementSummary: report.managementSummary?.toString()?.trim() ?: '',
            detailedFindings: normalizeList(report.detailedFindings),
            recommendations: normalizeList(report.recommendations)
        ]
    }

    private static List<String> normalizeList(final Object value) {
        if (value instanceof Collection) {
            return ((Collection) value).collect { it?.toString()?.trim() }.findAll { it } as List<String>
        }
        String text = value?.toString()?.trim()
        if (!text) {
            return []
        }
        return text.split(/\r?\n/).collect { it.trim() }.findAll { it } as List<String>
    }

    private static String extractContentText(final Map raw) {
        if (raw.output_text) {
            return raw.output_text.toString()
        }
        if (raw.content instanceof Collection && !((Collection) raw.content).isEmpty()) {
            List<String> anthropicText = []
            ((Collection) raw.content).each { Object item ->
                if (item instanceof Map && ((Map) item).text) {
                    anthropicText << ((Map) item).text.toString()
                }
            }
            if (anthropicText) {
                return anthropicText.join('\n').trim()
            }
        }
        if (raw.candidates instanceof Collection && !((Collection) raw.candidates).isEmpty()) {
            Object firstCandidate = ((Collection) raw.candidates).iterator().next()
            if (firstCandidate instanceof Map) {
                Map candidate = (Map) firstCandidate
                Object content = candidate.content
                if (content instanceof Map && ((Map) content).parts instanceof Collection) {
                    List<String> parts = []
                    ((Collection) ((Map) content).parts).each { Object part ->
                        if (part instanceof Map && ((Map) part).text) {
                            parts << ((Map) part).text.toString()
                        }
                    }
                    if (parts) {
                        return parts.join('\n').trim()
                    }
                }
            }
        }
        if (raw.output instanceof Collection && !((Collection) raw.output).isEmpty()) {
            for (Object item : (Collection) raw.output) {
                if (!(item instanceof Map)) {
                    continue
                }
                Map m = (Map) item
                if (m.text) {
                    return m.text.toString()
                }
                if (m.content instanceof Collection) {
                    for (Object cItem : (Collection) m.content) {
                        if (!(cItem instanceof Map)) {
                            continue
                        }
                        Map c = (Map) cItem
                        if (c.text) {
                            return c.text.toString()
                        }
                        if (c.output_text) {
                            return c.output_text.toString()
                        }
                    }
                }
            }
        }
        if (raw.content) {
            return raw.content.toString()
        }
        if (raw.choices instanceof Collection && !raw.choices.isEmpty()) {
            Object first = ((Collection) raw.choices).iterator().next()
            if (first instanceof Map) {
                Map m = (Map) first
                if (m.message instanceof Map && ((Map) m.message).content) {
                    return ((Map) m.message).content.toString()
                }
                if (m.text) {
                    return m.text.toString()
                }
            }
        }
        return ''
    }

    private List<String> fetchModels(final String provider, final Map settings, final String apiKey) {
        String modelsEndpoint = deriveModelsEndpoint(provider, settings)
        Map probe = probeModelsEndpoint(provider, modelsEndpoint, apiKey)
        int code = probe.status as Integer
        String raw = probe.raw?.toString() ?: ''
        if (code < 200 || code >= 300) {
            String details = sanitizeProviderError(raw)
            throw new IllegalStateException("Model discovery endpoint returned HTTP ${code}${details ? ': ' + details : ''}")
        }
        def parsed = new JsonSlurper().parseText(raw ?: '{}')
        List<String> ids = []
        if (provider == 'google') {
            Collection rows = (parsed instanceof Map && parsed.models instanceof Collection) ? (Collection) parsed.models : []
            ids = rows.collect { Object row ->
                if (!(row instanceof Map)) {
                    return null
                }
                Map entry = (Map) row
                Collection methods = entry.supportedGenerationMethods instanceof Collection ? (Collection) entry.supportedGenerationMethods : []
                if (methods && !methods.contains('generateContent')) {
                    return null
                }
                String name = entry.name?.toString() ?: ''
                name ? name.replaceFirst(/^models\//, '') : null
            }.findAll { it } as List<String>
        } else {
            Collection rows = (parsed instanceof Map && parsed.data instanceof Collection) ? (Collection) parsed.data : []
            ids = rows.collect { Object row ->
                row instanceof Map ? ((Map) row).id?.toString() : null
            }.findAll { it } as List<String>
        }
        return ids ? ids.unique().sort(false) : []
    }

    private Map probeModelsEndpoint(final String provider, final String modelsEndpoint, final String apiKey) {
        URL url = new URL(withGoogleApiKey(provider, modelsEndpoint, apiKey))
        HttpURLConnection connection = (HttpURLConnection) url.openConnection()
        connection.setRequestMethod('GET')
        applyProviderHeaders(connection, provider, apiKey)
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS)
        connection.setReadTimeout(READ_TIMEOUT_MS)

        int code = connection.responseCode
        String raw = ''
        try {
            InputStream in = (code >= 200 && code < 300) ? connection.inputStream : connection.errorStream
            raw = in?.getText('UTF-8') ?: ''
        } finally {
            connection.disconnect()
        }
        return [status: code, raw: raw, body: sanitizeProviderError(raw)]
    }

    private static void applyProviderHeaders(final HttpURLConnection connection, final String provider, final String apiKey) {
        if (provider == 'anthropic') {
            connection.setRequestProperty('x-api-key', apiKey)
            connection.setRequestProperty('anthropic-version', '2023-06-01')
            return
        }
        if (provider == 'google') {
            return
        }
        connection.setRequestProperty('Authorization', "Bearer ${apiKey}")
    }

    private static String withGoogleApiKey(final String provider, final String endpoint, final String apiKey) {
        if (provider != 'google') {
            return endpoint
        }
        String separator = endpoint.contains('?') ? '&' : '?'
        return endpoint.contains('key=') ? endpoint : endpoint + separator + 'key=' + URLEncoder.encode(apiKey, 'UTF-8')
    }

    private static Map parseJsonObjectFromText(final String text) {
        String trimmed = text.trim()
        String jsonText = trimmed
        if (trimmed.startsWith('```')) {
            int firstNl = trimmed.indexOf('\n')
            int lastFence = trimmed.lastIndexOf('```')
            if (firstNl > -1 && lastFence > firstNl) {
                jsonText = trimmed.substring(firstNl + 1, lastFence).trim()
            }
        } else {
            int start = trimmed.indexOf('{')
            int end = trimmed.lastIndexOf('}')
            if (start >= 0 && end > start) {
                jsonText = trimmed.substring(start, end + 1)
            }
        }
        def parsed = new JsonSlurper().parseText(jsonText)
        if (!(parsed instanceof Map)) {
            throw new IllegalStateException('LLM response content is not a JSON object.')
        }
        return (Map) parsed
    }

    static String defaultPromptTemplate() {
        '''Generate a security & compliance report using the provided summary and masked findings.
Return strict JSON with exactly these keys:
- managementSummary: string
- detailedFindings: array of strings
- recommendations: array of strings

Requirements:
- Keep the summary suitable for management stakeholders.
- Detailed findings should be technically specific but concise.
- Recommendations must be prioritized and actionable.
- Do not invent secrets, credentials, or raw values.
- Use only the provided masked evidence and metadata.'''
    }

    private static String sanitizeProviderError(final String raw) {
        if (!raw?.trim()) {
            return ''
        }
        String text = raw.toString()
        text = text.replaceAll(/(?i)bearer\s+[a-z0-9._\-]+/, 'Bearer [REDACTED]')
        text = text.replaceAll(/(?i)(sk-[a-z0-9_\-]{6,})/, 'sk-[REDACTED]')
        text = text.replaceAll(/(?i)(api[_-]?key["']?\s*[:=]\s*["']?)[^"',\s}]+/, '$1[REDACTED]')
        text = text.replaceAll(/[\r\n\t]+/, ' ').trim()
        if (text.length() > MAX_PROVIDER_ERROR_LEN) {
            text = text.substring(0, MAX_PROVIDER_ERROR_LEN) + '...'
        }
        return text
    }

    private static String decodePasswordSecret(final Object raw) {
        if (raw == null) {
            return ''
        }
        if (raw instanceof byte[]) {
            return new String((byte[]) raw, StandardCharsets.UTF_8)
        }
        if (raw instanceof Collection) {
            Collection c = (Collection) raw
            byte[] bytes = new byte[c.size()]
            int i = 0
            c.each { Object o ->
                try {
                    bytes[i++] = Integer.parseInt(o.toString()).byteValue()
                } catch (Exception ignored) {
                    bytes[i++] = (byte) 0
                }
            }
            return new String(bytes, StandardCharsets.UTF_8)
        }
        if (raw.getClass().isArray()) {
            int len = java.lang.reflect.Array.getLength(raw)
            byte[] bytes = new byte[len]
            for (int i = 0; i < len; i++) {
                Object o = java.lang.reflect.Array.get(raw, i)
                bytes[i] = ((o instanceof Number) ? ((Number) o).byteValue() : (byte) 0)
            }
            return new String(bytes, StandardCharsets.UTF_8)
        }
        return raw.toString()
    }

    private static String fingerprint(final String text) {
        MessageDigest md = MessageDigest.getInstance('SHA-256')
        byte[] digest = md.digest((text ?: '').getBytes(StandardCharsets.UTF_8))
        StringBuilder sb = new StringBuilder()
        for (int i = 0; i < digest.length; i++) {
            sb.append(String.format('%02x', digest[i]))
        }
        return sb.substring(0, 12)
    }
}
