package jobsecurityaudit

import groovy.transform.CompileStatic

import java.util.concurrent.ConcurrentHashMap

@CompileStatic
class JobSecurityAuditCacheService {
    private static final long TTL_MS = 15L * 60L * 1000L

    private final Map<String, Map> latestByProject = new ConcurrentHashMap<>()
    private final Map<Long, Map> byExecution = new ConcurrentHashMap<>()

    void save(final String project, final Long executionId, final Map payload) {
        Map row = [project: project, executionId: executionId, payload: payload, storedAt: System.currentTimeMillis()]
        latestByProject.put(project, row)
        if (executionId != null) {
            byExecution.put(executionId, row)
        }
    }

    Map latest(final String project) {
        Map row = latestByProject.get(project)
        if (!row) {
            return null
        }
        if ((System.currentTimeMillis() - ((Long) row.storedAt)) > TTL_MS) {
            latestByProject.remove(project)
            if (row.executionId) {
                byExecution.remove((Long) row.executionId)
            }
            return null
        }
        return (Map) row.payload
    }

    Map byExecutionId(final Long executionId) {
        Map row = byExecution.get(executionId)
        return row ? (Map) row.payload : null
    }
}
