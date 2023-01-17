package com.dotcms.osgi.oauth.app.velocity;

import com.dotcms.osgi.oauth.app.AppSecretEventSubscriber;
import com.dotcms.security.apps.AppSecretSavedEvent;
import com.dotcms.system.event.local.business.LocalSystemEventsAPI;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.CacheLocator;
import com.dotmarketing.util.ConfigUtils;
import com.dotmarketing.util.Logger;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

/**
 * Util to handle the Dot Velocity Secret App
 * @author jsanca
 */
public class DotVelocitySecretAppUtil {
    private final File installedAppYaml = new File(ConfigUtils.getAbsoluteAssetsRootPath() + File.separator + "server"
                    + File.separator + "apps" + File.separator + DotVelocitySecretAppKeys.APP_YAML_NAME);
    final LocalSystemEventsAPI localSystemEventsAPI = APILocator.getLocalSystemEventsAPI();

    /**
     * copies the App yaml to the apps directory and refreshes the apps
     * 
     * @throws IOException
     */
    public void copyAppYml() throws IOException {

        Logger.info(this.getClass().getName(), "copying YAML File:" + installedAppYaml);

        try (final InputStream in = this.getClass().getResourceAsStream("/" + DotVelocitySecretAppKeys.APP_YAML_NAME)) {
            IOUtils.copy(in, Files.newOutputStream(installedAppYaml.toPath()));
        }

        CacheLocator.getAppsCache().clearCache();
    }

    /**
     * Deletes the App yaml to the apps directory and refreshes the apps
     * 
     * @throws IOException
     */
    public void deleteYml() throws IOException {

        Logger.info(this.getClass().getName(), "deleting the YAML File:" + installedAppYaml);
        installedAppYaml.delete();
        CacheLocator.getAppsCache().clearCache();
    }

    /**
     * Subscribes a listener to saving the app
     */
    public void subscribeToAppSaveEvent() {
        Logger.info(this.getClass().getName(), "Subscribing to App Save Event");
        localSystemEventsAPI.subscribe(AppSecretSavedEvent.class, new AppSecretEventSubscriber());
    }

    /**
     * Unsubscribes the listener to saving the app
     */
    public void unsubscribeToAppSaveEvent() {
        Logger.info(this.getClass().getName(), "Unsubscribing to App Save Event");
        localSystemEventsAPI.unsubscribe(AppSecretEventSubscriber.class);
    }

}
