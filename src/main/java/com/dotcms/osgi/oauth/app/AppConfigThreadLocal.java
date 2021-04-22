package com.dotcms.osgi.oauth.app;

import java.io.Serializable;
import java.util.Optional;

public class AppConfigThreadLocal implements Serializable {


    private static final long serialVersionUID = 1L;

    private static ThreadLocal<AppConfig> configLocal = new ThreadLocal<>();

    public static final AppConfigThreadLocal INSTANCE = new AppConfigThreadLocal();

    /**
     * Get the request from the current thread
     * 
     * @return {@link AppConfig}
     */
    public Optional<AppConfig> getConfig() {
        return Optional.ofNullable(configLocal.get());
    }

    public void setConfig(final Optional<AppConfig> config) {

        configLocal.set(config !=null && config.isPresent() ? config.get() : null);
    }
    
    public void clearConfig() {

        configLocal.remove();
    }
    
    

}
