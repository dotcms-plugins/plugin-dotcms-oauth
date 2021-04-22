package com.dotcms.osgi.oauth.app;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import com.dotcms.security.apps.AppSecrets;
import com.dotcms.security.apps.Secret;
import com.dotmarketing.beans.Host;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.web.WebAPILocator;
import com.dotmarketing.util.UtilMethods;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.vavr.control.Try;

@JsonDeserialize(builder = AppConfig.Builder.class)
public class AppConfig implements Serializable {


    private static final long serialVersionUID = 1L;


    public final boolean enableBackend, enableFrontend;
    public final String provider, apiKey, protectedResource, groupResource, baseOrganizationUrl,dotCMSCallBackUrl;
    public final char[] apiSecret;
    public final String[] scope;
    public final Map<String, String> extraParameters;


    public final String getValue(final String key, final String defaultValue) {
        return extraParameters.compute(key, (k, v) -> (v == null) ? defaultValue : v);
    }
    
    public final String[] getArrayValue(final String key) {
        
        return UtilMethods.isSet(extraParameters.get(key))
                        ? Arrays.stream(extraParameters.get(key).split(",")).map(String::trim).toArray(String[]::new)
                        : new String[0];

    }
    
    

    public final String getGroupPrefix() {
        return getValue("groupPrefix", "dotcms_");
    }


    private AppConfig(Builder builder) {
        this.enableBackend = builder.enableBackend;
        this.baseOrganizationUrl = builder.baseOrganizationUrl;
        this.enableFrontend = builder.enableFrontend;
        this.protectedResource = builder.protectedResource;
        this.groupResource = builder.groupResource;
        this.provider = builder.provider;
        this.apiKey = builder.apiKey;
        this.apiSecret = builder.apiSecret;
        this.scope = (builder.scope == null) ? new String[0] : builder.scope;
        this.extraParameters = builder.extraParameters;
        this.dotCMSCallBackUrl=builder.dotCMSCallBackUrl;
    }


    public static Optional<AppConfig> config() {
        return AppConfigThreadLocal.INSTANCE.getConfig();

    }


    /**
     * Gets the secrets from the App - this will check the current host then the SYSTEM_HOST for a valid
     * configuration. This lookup is low overhead and cached by dotCMS.
     * 
     * @param request
     * @return
     */
    public static Optional<AppConfig> config(final HttpServletRequest request) {


        if (AppConfigThreadLocal.INSTANCE.getConfig().isPresent()) {
            return AppConfigThreadLocal.INSTANCE.getConfig();
        }

        final Host host = WebAPILocator.getHostWebAPI().getCurrentHostNoThrow(request);

        Optional<AppSecrets> appSecrets = Try.of(
                        () -> APILocator.getAppsAPI().getSecrets(AppKeys.APP_KEY, true, host, APILocator.systemUser()))
                        .getOrElse(Optional.empty());

        if (!appSecrets.isPresent()) {
            return Optional.empty();
        }

        final Map<String, Secret> secrets = new HashMap<>(appSecrets.get().getSecrets());
        
        Map<String, String> extraParameters = new HashMap<>();
        boolean enableBackend =
                        Try.of(() -> secrets.get(AppKeys.ENABLE_BACKEND.key).getBoolean()).getOrElse(Boolean.FALSE);
        boolean enableFrontend =
                        Try.of(() -> secrets.get(AppKeys.ENABLE_FRONTEND.key).getBoolean()).getOrElse(Boolean.FALSE);

        if (!enableBackend && !enableFrontend) {
            return Optional.empty();
        }

        String provider = Try.of(() -> secrets.get(AppKeys.PROVIDER.key).getString().trim()).getOrNull();
        String baseOrganizationUrl =
                        Try.of(() -> secrets.get(AppKeys.BASE_ORGANIZATION_URL.key).getString().trim()).getOrNull();
        String protectedResource =
                        Try.of(() -> secrets.get(AppKeys.PROTECTED_RESOURCE.key).getString().trim()).getOrNull();
        
        if(UtilMethods.isSet(protectedResource) && !protectedResource.startsWith(baseOrganizationUrl) && ! protectedResource.contains("://")) {
            protectedResource = baseOrganizationUrl + protectedResource;
        }
        
        final String dotCMSCallBackUrl = Try.of(() -> secrets.get(AppKeys.DOTCMS_CALLBACK.key).getString().trim()).getOrNull();
        
        String groupResource = Try.of(() -> secrets.get(AppKeys.GROUP_RESOURCE.key).getString().trim()).getOrNull();
        
        if(UtilMethods.isSet(groupResource) && !groupResource.startsWith(baseOrganizationUrl) && ! groupResource.contains("://")) {
            groupResource = baseOrganizationUrl + groupResource;
        }
        
        
        String apiKey = Try.of(() -> secrets.get(AppKeys.API_KEY.key).getString().trim()).getOrNull();
        char[] apiSecret = Try.of(() -> secrets.get(AppKeys.API_SECRET.key).getValue()).getOrElse(new char[0]);
        String[] scope = Try.of(() -> secrets.get(AppKeys.SCOPE.key).getString().split("[, ]"))
                        .getOrElse(new String[0]);

        for (AppKeys key : AppKeys.values()) {
            secrets.remove(key.key);
        }

        for (String key : secrets.keySet()) {
            extraParameters.put(key, secrets.get(key).getString());
        }


        AppConfig config = AppConfig.builder()
                        .withApiKey(apiKey)
                        .withApiSecret(apiSecret)
                        .withEnableBackend(enableBackend)
                        .withEnableFrontend(enableFrontend)
                        .withExtraParameters(extraParameters)
                        .withGroupResource(groupResource)
                        .withProtectedResource(protectedResource)
                        .withBaseOrganizationUrl(baseOrganizationUrl)
                        .withProvider(provider)
                        .withDotCMSCallBackUrl(dotCMSCallBackUrl)
                        .withScope(scope).build();


        AppConfigThreadLocal.INSTANCE.setConfig(Optional.ofNullable(config));


        return AppConfigThreadLocal.INSTANCE.getConfig();


    }


    /**
     * Creates builder to build {@link AppConfig}.
     * 
     * @return created builder
     */

    public static Builder builder() {
        return new Builder();
    }


    /**
     * Creates a builder to build {@link AppConfig} and initialize it with the given object.
     * 
     * @param appConfig to initialize the builder with
     * @return created builder
     */

    public static Builder from(AppConfig appConfig) {
        return new Builder(appConfig);
    }


    /**
     * Builder to build {@link AppConfig}.
     */

    public static final class Builder {
        private boolean enableBackend;
        private boolean enableFrontend;
        private String protectedResource;
        private String groupResource;
        private String provider;
        private String apiKey;
        private String baseOrganizationUrl;
        private String  dotCMSCallBackUrl;
        private char[] apiSecret;
        private String[] scope;
        private Map<String, String> extraParameters = Collections.emptyMap();

        private Builder() {}

        private Builder(AppConfig appConfig) {
            this.enableBackend = appConfig.enableBackend;
            this.enableFrontend = appConfig.enableFrontend;
            this.protectedResource =
                            UtilMethods.isSet(appConfig.protectedResource) ? appConfig.protectedResource : null;
            this.groupResource = UtilMethods.isSet(appConfig.groupResource) ? appConfig.groupResource : null;
            this.provider = UtilMethods.isSet(appConfig.provider) ? appConfig.provider : null;
            this.apiKey = UtilMethods.isSet(appConfig.apiKey) ? appConfig.apiKey : null;
            this.apiSecret = UtilMethods.isSet(appConfig.apiSecret) ? appConfig.apiSecret : null;
            this.scope = appConfig.scope == null ? new String[0] : appConfig.scope;
            this.dotCMSCallBackUrl =  UtilMethods.isSet(appConfig.dotCMSCallBackUrl) ? appConfig.dotCMSCallBackUrl : null;
            this.extraParameters = appConfig.extraParameters;
            this.baseOrganizationUrl =
                            UtilMethods.isSet(appConfig.baseOrganizationUrl) ? appConfig.baseOrganizationUrl : null;
        }

        public Builder withEnableBackend(@Nonnull boolean enableBackend) {
            this.enableBackend = enableBackend;
            return this;
        }

        public Builder withEnableFrontend(@Nonnull boolean enableFrontend) {
            this.enableFrontend = enableFrontend;
            return this;
        }
        
        public Builder withDotCMSCallBackUrl(@Nonnull String dotCMSCallBackUrl) {
            this.dotCMSCallBackUrl = dotCMSCallBackUrl;
            return this;
        }
        
        public Builder withBaseOrganizationUrl(@Nonnull String baseOrganizationUrl) {
            this.baseOrganizationUrl = UtilMethods.isSet(baseOrganizationUrl) ? baseOrganizationUrl : null;
            return this;
        }

        public Builder withProtectedResource(@Nonnull String protectedResource) {
            this.protectedResource = UtilMethods.isSet(protectedResource) ? protectedResource : null;
            return this;
        }

        public Builder withGroupResource(@Nonnull String groupResource) {
            this.groupResource = UtilMethods.isSet(groupResource) ? groupResource : null;
            return this;
        }

        public Builder withProvider(@Nonnull String provider) {
            this.provider = UtilMethods.isSet(provider) ? provider : null;
            return this;
        }

        public Builder withApiKey(@Nonnull String apiKey) {
            this.apiKey = UtilMethods.isSet(apiKey) ? apiKey : null;
            return this;
        }

        public Builder withApiSecret(@Nonnull char[] apiSecret) {
            this.apiSecret = UtilMethods.isSet(apiSecret) ? apiSecret : null;
            return this;
        }


        public Builder withScope(@Nonnull String[] scope) {
            this.scope = (scope == null) ? new String[0] : scope;
            return this;
        }

        public Builder withExtraParameters(@Nonnull Map<String, String> extraParameters) {
            this.extraParameters = extraParameters;
            return this;
        }

        public AppConfig build() {
            return new AppConfig(this);
        }
    }


}
