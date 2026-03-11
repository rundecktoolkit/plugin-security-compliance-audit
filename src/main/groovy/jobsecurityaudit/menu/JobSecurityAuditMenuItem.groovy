package jobsecurityaudit.menu

import com.dtolabs.rundeck.core.authorization.AuthContextEvaluator
import com.dtolabs.rundeck.core.authorization.UserAndRolesAuthContext
import grails.web.mapping.LinkGenerator
import groovy.transform.CompileStatic
import org.rundeck.app.gui.AuthMenuItem
import org.rundeck.app.gui.MenuItem
import org.rundeck.core.auth.AuthConstants
import org.springframework.beans.factory.annotation.Autowired

@CompileStatic
class JobSecurityAuditMenuItem implements MenuItem, AuthMenuItem {
    String title = "Security & Compliance"
    String titleCode = "JobSecurityAudit.title"
    MenuType type = MenuType.PROJECT
    Integer priority = 701

    @Autowired
    LinkGenerator grailsLinkGenerator
    @Autowired
    AuthContextEvaluator rundeckAuthContextEvaluator

    @Override
    String getIconCSS() {
        return "fas fa-shield-alt"
    }

    @Override
    String getProjectHref(final String project) {
        return grailsLinkGenerator.link(uri: "/project/${project}/jobSecurity/admin")
    }

    @Override
    boolean isEnabled(final UserAndRolesAuthContext auth, final String project) {
        return rundeckAuthContextEvaluator.authorizeProjectResourceAny(
            auth,
            AuthConstants.RESOURCE_TYPE_EVENT,
            [AuthConstants.ACTION_READ, AuthConstants.ACTION_ADMIN, AuthConstants.ACTION_APP_ADMIN],
            project
        )
    }
}
