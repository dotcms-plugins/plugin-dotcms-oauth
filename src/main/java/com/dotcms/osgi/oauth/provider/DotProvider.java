package com.dotcms.osgi.oauth.provider;

import com.dotcms.osgi.oauth.app.AppConfig;

/**
 * @author Jonathan Gamba 8/27/18
 */
public interface DotProvider {

    default String getRevokeTokenEndpoint() {
        return null;
    }
    
    default AppConfig config() {
        return AppConfig.config().get();
    }



}