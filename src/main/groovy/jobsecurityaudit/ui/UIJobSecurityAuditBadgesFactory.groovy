package jobsecurityaudit.ui

import com.dtolabs.rundeck.core.plugins.PluginRegistry
import com.dtolabs.rundeck.plugins.ServiceNameConstants
import com.dtolabs.rundeck.plugins.rundeck.UIPlugin
import org.springframework.beans.factory.BeanNameAware
import org.springframework.beans.factory.FactoryBean
import org.springframework.beans.factory.InitializingBean

class UIJobSecurityAuditBadgesFactory implements FactoryBean<UIPlugin>, InitializingBean, BeanNameAware {
    String beanName
    Class<?> objectType = UIJobSecurityAuditBadges
    boolean singleton = true
    PluginRegistry pluginRegistry

    @Override
    UIPlugin getObject() throws Exception {
        return new UIJobSecurityAuditBadges()
    }

    @Override
    void afterPropertiesSet() throws Exception {
        pluginRegistry.registerPlugin(ServiceNameConstants.UI, UIJobSecurityAuditBadges.PROVIDER_NAME, beanName)
    }
}
