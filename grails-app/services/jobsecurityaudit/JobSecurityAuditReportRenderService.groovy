package jobsecurityaudit

import groovy.transform.CompileStatic

@CompileStatic
class JobSecurityAuditReportRenderService {
    Map render(final String project, final Map summary, final Map report) {
        String scannedAt = summary?.scannedAt?.toString() ?: ''
        String executionId = summary?.executionId?.toString() ?: ''
        String riskLevel = summary?.riskLevel?.toString() ?: ''
        int riskScore = (summary?.riskScore ?: 0) as int

        List<String> details = normalizeLines(report?.detailedFindings)
        List<String> recommendations = normalizeLines(report?.recommendations)
        String managementSummary = report?.managementSummary?.toString()?.trim() ?: 'No management summary provided by model.'

        String markdown = """\
# Security & Compliance AI Report

## Metadata
- Project: ${project}
- Execution: ${executionId}
- Scanned At: ${scannedAt}
- Risk Score: ${riskScore}/100
- Risk Level: ${riskLevel}

## Management Summary
${managementSummary}

## Detailed Findings
${toMarkdownList(details)}

## Recommendations
${toMarkdownList(recommendations)}
""".stripIndent().trim() + "\n"

        String text = """\
Security & Compliance AI Report
================================

Project: ${project}
Execution: ${executionId}
Scanned At: ${scannedAt}
Risk Score: ${riskScore}/100
Risk Level: ${riskLevel}

Management Summary
------------------
${managementSummary}

Detailed Findings
-----------------
${toTextList(details)}

Recommendations
---------------
${toTextList(recommendations)}
""".stripIndent().trim() + "\n"

        return [markdown: markdown, text: text]
    }

    private static List<String> normalizeLines(final Object value) {
        if (value instanceof Collection) {
            return ((Collection) value).collect { it?.toString()?.trim() }.findAll { it } as List<String>
        }
        String text = value?.toString()?.trim()
        if (!text) {
            return ['No items provided.']
        }
        return text.split(/\r?\n/).collect { it.trim() }.findAll { it } as List<String>
    }

    private static String toMarkdownList(final List<String> lines) {
        if (!lines) {
            return '- No items provided.'
        }
        return lines.collect { "- ${it}" }.join('\n')
    }

    private static String toTextList(final List<String> lines) {
        if (!lines) {
            return '* No items provided.'
        }
        return lines.collect { "* ${it}" }.join('\n')
    }
}
