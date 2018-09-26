package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_PROVIDER;

import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.Logger;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConstants;
import org.scribe.oauth.OAuthService;

/**
 * @author Jonathan Gamba 8/28/18
 */
public class LogoutOAuthInterceptor implements WebInterceptor {

    private static final String NAME = "LogoutOAuthInterceptor_5_0_1";

    private final OauthUtils oauthUtils;

    public LogoutOAuthInterceptor() throws DotDataException {
        this.oauthUtils = OauthUtils.getInstance();
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String[] getFilters() {
        return new String[]{"/api/v1/logout", "/dotcms/logout"};
    }

    @Override
    public Result intercept(HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        Result result = Result.NEXT;

        HttpSession session = request.getSession(false);
        if (null != session) {

            //Check if there is a token to invalidate
            final Object accessTokenObject = session.getAttribute(OAuthConstants.ACCESS_TOKEN);
            if (null != accessTokenObject) {

                //Look for the provider to use
                DefaultApi20 apiProvider = this.oauthUtils.getAPIProvider(request, session);
                if (null != apiProvider) {

                    final String accessToken = (String) accessTokenObject;

                    final String providerName = apiProvider.getClass().getSimpleName();
                    final String apiKey = getProperty(providerName + "_API_KEY");
                    final String apiSecret = getProperty(providerName + "_API_SECRET");

                    final OAuthService service = new ServiceBuilder()
                            .apiKey(apiKey)
                            .apiSecret(apiSecret)
                            .provider(apiProvider)
                            .build();

                    //Invalidate the token
                    if (service instanceof DotService) {
                        ((DotService) service).revokeToken(accessToken);
                    }

                    //Cleaning up the session
                    session.removeAttribute(OAuthConstants.ACCESS_TOKEN);
                    session.removeAttribute(OAUTH_PROVIDER);

                } else {
                    Logger.error(this.getClass(), "Unable to invalidate access token."
                            + " Access token found in session but no oauthProvider was found.");
                }

            }

        }

        return result;
    }

}