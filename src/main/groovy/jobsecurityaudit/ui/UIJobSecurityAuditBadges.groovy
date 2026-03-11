package jobsecurityaudit.ui

import com.dtolabs.rundeck.core.plugins.Plugin
import com.dtolabs.rundeck.core.plugins.PluginException
import com.dtolabs.rundeck.core.plugins.PluginResourceLoader
import com.dtolabs.rundeck.plugins.ServiceNameConstants
import com.dtolabs.rundeck.plugins.descriptions.PluginDescription
import com.dtolabs.rundeck.plugins.rundeck.UIPlugin
import groovy.transform.CompileStatic

@Plugin(name = UIJobSecurityAuditBadges.PROVIDER_NAME, service = ServiceNameConstants.UI)
@PluginDescription(
    title = UIJobSecurityAuditBadges.PLUGIN_TITLE,
    description = UIJobSecurityAuditBadges.PLUGIN_DESC
)
@CompileStatic
class UIJobSecurityAuditBadges implements UIPlugin, PluginResourceLoader {
    static final String PROVIDER_NAME = 'ui-job-security-audit-badges'
    static final String PLUGIN_TITLE = 'Job Security Audit Badges'
    static final String PLUGIN_DESC = 'Shows risk badges in job list and job detail pages.'

    private static final List<String> SCRIPTS = ['job-security/badges.js']
    private static final List<String> STYLES = ['job-security/badges.css']
    private static final List<String> ALL_RESOURCES = SCRIPTS + STYLES

    @Override
    List<String> listResources() throws PluginException, IOException {
        ALL_RESOURCES
    }

    @Override
    InputStream openResourceStreamFor(final String name) throws PluginException, IOException {
        InputStream stream = this.getClass().getResourceAsStream('/' + name)
        if (null == stream) {
            stream = this.getClass().getClassLoader().getResourceAsStream(name)
        }
        if (null == stream && null != Thread.currentThread()?.contextClassLoader) {
            stream = Thread.currentThread().contextClassLoader.getResourceAsStream(name)
        }
        stream
    }

    @Override
    boolean doesApply(final String path) {
        true
    }

    @Override
    List<String> resourcesForPath(final String path) {
        ALL_RESOURCES
    }

    @Override
    List<String> scriptResourcesForPath(final String path) {
        SCRIPTS
    }

    @Override
    List<String> styleResourcesForPath(final String path) {
        STYLES
    }

    @Override
    List<String> requires(final String path) {
        null
    }
}
