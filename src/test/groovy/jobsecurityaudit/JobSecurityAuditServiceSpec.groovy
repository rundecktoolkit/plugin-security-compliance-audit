package jobsecurityaudit

import spock.lang.Specification

class JobSecurityAuditServiceSpec extends Specification {

    JobSecurityAuditService service = new JobSecurityAuditService()

    def 'detects embedded credentials URL'() {
        expect:
        service.invokeMethod('containsEmbeddedCredentialsUrl', 'https://admin:secret@example.org/path')
        !service.invokeMethod('containsEmbeddedCredentialsUrl', 'https://example.org/path')
    }

    def 'detects literal authorization header'() {
        expect:
        service.invokeMethod('looksLikeLiteralAuthorizationHeader', 'Authorization: Bearer abcdEFGH123456789')
        !service.invokeMethod('looksLikeLiteralAuthorizationHeader', 'Authorization: Bearer ${secureOption.token}')
    }

    def 'masks evidence text'() {
        when:
        String masked = service.invokeMethod('maskEvidence', 'my-very-secret-token-value')

        then:
        masked.startsWith('my')
        masked.endsWith('ue')
        masked.contains('****')
    }
}
