package jobsecurityaudit

import groovy.transform.CompileStatic

import java.util.concurrent.ConcurrentHashMap

@CompileStatic
class JobSecurityAuditLlmCacheService {
    private static final long TTL_MS = 30L * 60L * 1000L

    private final Map<String, Map> reportByKey = new ConcurrentHashMap<>()

    void save(
        final String project,
        final Long executionId,
        final String user,
        final Map payload
    ) {
        if (!project || executionId == null || !user) {
            return
        }
        String key = keyFor(project, executionId, user)
        reportByKey.put(key, [payload: payload, storedAt: System.currentTimeMillis()])
    }

    Map get(
        final String project,
        final Long executionId,
        final String user
    ) {
        if (!project || executionId == null || !user) {
            return null
        }
        String key = keyFor(project, executionId, user)
        Map row = reportByKey.get(key)
        if (!row) {
            return null
        }
        long storedAt = (row.storedAt as Long) ?: 0L
        if ((System.currentTimeMillis() - storedAt) > TTL_MS) {
            reportByKey.remove(key)
            return null
        }
        return (Map) row.payload
    }

    private static String keyFor(final String project, final Long executionId, final String user) {
        "${project}:${executionId}:${user}"
    }
}
