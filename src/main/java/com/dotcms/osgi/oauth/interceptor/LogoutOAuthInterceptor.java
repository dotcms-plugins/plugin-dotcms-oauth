package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_PROVIDER;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConstants;
import org.scribe.oauth.OAuthService;
import com.dotcms.concurrent.DotConcurrentFactory;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.app.AppConfig;
import com.dotcms.osgi.oauth.app.AppConfigThreadLocal;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.util.CookieUtil;
import com.dotmarketing.util.Logger;
import io.vavr.control.Try;

/**
 * @author Jonathan Gamba 8/28/18
 */
public class LogoutOAuthInterceptor implements WebInterceptor {

    private final OauthUtils oauthUtils;

    public LogoutOAuthInterceptor() {
        this.oauthUtils = OauthUtils.getInstance();
    }


    @Override
    public String[] getFilters() {
        return new String[] {"/api/v1/logout", "/dotCMS/logout", "/dotAdmin/logout"};
    }

    
    @Override
    public Result intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

        try {
            return _intercept(request, response);
        }
        finally {
            AppConfigThreadLocal.INSTANCE.clearConfig();
        }
    }
    
    

    private Result _intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {


        String uri = request.getRequestURI();
        Logger.info(this.getClass().getName(), "intercepting: " + uri);
        
        
        

        final HttpSession session = request.getSession(false);
        final Optional<AppConfig> config = AppConfig.config(request);
        if (request.getSession(false) == null || !config.isPresent()) {
            return this.logout(request, response);
        }

        OauthUtils.getInstance().setNoCacheHeaders(response);
        String cookieToken =null;
        for(Cookie c : request.getCookies()) {
            if(c.getName().equals("access_token")) {
                cookieToken= c.getValue();
            }
        }
        

        


        // Check if there is a token to invalidate
        final Object accessTokenObject = session.getAttribute(OAuthConstants.ACCESS_TOKEN);



        // Look for the provider to use
        Optional<DefaultApi20> apiProvider = this.oauthUtils.getAPIProvider(config.get());
        if (apiProvider.isPresent()) {

            final String accessToken = (String) accessTokenObject;
            final String apiKey = config.get().apiKey;
            final String apiSecret =new String(config.get().apiSecret);

            final OAuthService service =
                            new ServiceBuilder()
                            .apiKey(apiKey)
                            .apiSecret(apiSecret)
                            .callback(config.get().dotCMSCallBackUrl)
                            .provider(apiProvider.get())
                            .build();

            // Invalidate the token
            if (service instanceof DotService) {
                ((DotService) service).revokeToken(accessToken);
                ((DotService) service).revokeToken(cookieToken);
                Optional<String> providerLogout = ((DotService) service).getLogoutClientRedirect();
                if(providerLogout.isPresent()) {
                    response.setStatus(302);
                    response.setHeader("Location", providerLogout.get());
                    response.getWriter().close();
                }
            }

        } 
        // Cleaning up the session
        session.removeAttribute(OAuthConstants.ACCESS_TOKEN);
        session.removeAttribute(OAUTH_PROVIDER);
        com.liferay.util.CookieUtil.deleteCookie(request, response, "access_token");
        
        
        


        return this.logout(request, response);
    }
    
    private Result logout(HttpServletRequest request, HttpServletResponse response) {
        Try.run(() -> APILocator.getLoginServiceAPI().doActionLogout(request, response)).onFailure(e->Logger.warn("LogoutOAuthInterceptor.class", e.getMessage()));
        if(!response.isCommitted()) {
            response.setStatus(302);
            response.setHeader("Location", "/");
        }
        return Result.SKIP_NO_CHAIN;
    }
    

}
