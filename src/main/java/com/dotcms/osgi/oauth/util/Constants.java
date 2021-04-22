package com.dotcms.osgi.oauth.util;

import javax.servlet.RequestDispatcher;

public class Constants {

    public static final String FRONT_END_LOGIN = "FRONT_END_LOGIN";
    public static final String CALLBACK_URL = "/api/v1/oauth2/callback";

    public static final String CMS_NATIVE_LOGIN = "CMS_NATIVE_LOGIN_NO_OAUTH";
    public static final String OAUTH_PROVIDER = "OAUTH_PROVIDER";
    public static final String OAUTH_PROVIDER_DEFAULT = "DEFAULT_OAUTH_PROVIDER";
    public static final String OAUTH_REDIRECT = "OAUTH_REDIRECT";
    public static final String OAUTH_SERVICE = "OAUTH_SERVICE";
    public static final String OAUTH_API_PROVIDER = "OAUTH_API_PROVIDER";

    public static final String ROLES_TO_ADD = "ROLES_TO_ADD";


    public static final String NATIVE = "native";
    public static final String REFERRER = "referrer";

    public static final String JAVAX_SERVLET_FORWARD_REQUEST_URI = RequestDispatcher.FORWARD_REQUEST_URI;

    public static final String FEMALE = "female";
    public static final String GENDER = "gender";

    public static final String REMEMBER_ME = "rememberMe";

    public static final String EMPTY_SECRET = "";
}
