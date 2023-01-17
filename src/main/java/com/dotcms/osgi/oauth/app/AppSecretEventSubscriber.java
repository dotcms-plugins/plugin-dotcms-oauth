package com.dotcms.osgi.oauth.app;

import com.dotcms.security.apps.AppSecretSavedEvent;
import com.dotcms.system.event.local.model.EventSubscriber;
import com.dotcms.system.event.local.model.KeyFilterable;
import com.dotmarketing.util.Logger;

public class AppSecretEventSubscriber implements EventSubscriber<AppSecretSavedEvent>  ,  KeyFilterable {

    static final String appKey = AppKeys.APP_KEY;

    @Override
    public Comparable getKey() {
        return appKey;
    }

    @Override
    public void notify(AppSecretSavedEvent event) {
        Logger.info(this.getClass().getName(), "We got a secret event for : " + event.getKey() + " from: " + event.getUserId());
    }
}
