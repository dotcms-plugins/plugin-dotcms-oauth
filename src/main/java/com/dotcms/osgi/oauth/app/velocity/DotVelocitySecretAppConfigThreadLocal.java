package com.dotcms.osgi.oauth.app.velocity;

import com.dotcms.osgi.oauth.app.AppConfig;

import java.io.Serializable;
import java.util.Optional;

public class DotVelocitySecretAppConfigThreadLocal implements Serializable {

    private static final long serialVersionUID = 1L;

    private static ThreadLocal<DotVelocitySecretAppConfig> configLocal = new ThreadLocal<>();

    public static final DotVelocitySecretAppConfigThreadLocal INSTANCE = new DotVelocitySecretAppConfigThreadLocal();

    /**
     * Get the request from the current thread
     * 
     * @return {@link DotVelocitySecretAppConfig}
     */
    public Optional<DotVelocitySecretAppConfig> getConfig() {
        return Optional.ofNullable(configLocal.get());
    }

    public void setConfig(final Optional<DotVelocitySecretAppConfig> config) {

        configLocal.set(config !=null && config.isPresent() ? config.get() : null);
    }
    
    public void clearConfig() {

        configLocal.remove();
    }
}
