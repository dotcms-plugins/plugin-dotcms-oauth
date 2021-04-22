/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have chosen to have their login information remembered.
 * Creates a valid WebSession object and passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.Constants.OAUTH_PROVIDER;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_SERVICE;
import java.io.IOException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthConstants;
import org.scribe.oauth.OAuthService;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.app.AppConfig;
import com.dotcms.osgi.oauth.app.AppConfigThreadLocal;
import com.dotcms.osgi.oauth.util.Constants;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.util.Logger;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PortalUtil;
import io.vavr.control.Try;

public class OAuthCallbackInterceptor implements WebInterceptor {

    public static final String CALLBACK_URL = "/api/v1/oauth2/callback";


    public OAuthCallbackInterceptor() {

    }

    @Override
    public String[] getFilters() {
        return new String[] {CALLBACK_URL};
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

   
    private Result _intercept(HttpServletRequest request, HttpServletResponse response) {
        OauthUtils.getInstance().setNoCacheHeaders(response);
        
        Logger.info(this.getClass().getName(), "intercepting: " + request.getRequestURI());
        User user = PortalUtil.getUser(request);

        if (null != user) {
            return redirectLoggedInUser(request, response);
        }


        Optional<AppConfig> configOpt = AppConfig.config(request);
        final String requestedURI = request.getRequestURI();

        // if we have no oauth configured, continue
        if (!configOpt.isPresent()) {
            Logger.warn(this.getClass().getName(), "No OAuthConfig found for :" + requestedURI);
            Try.run(() -> response.sendRedirect("/?error=no+oauth+config"));
            return Result.SKIP_NO_CHAIN;
        }
        final AppConfig config = configOpt.get();

        final String responseCode = request.getParameter(OAuthConstants.CODE);
        if (null == responseCode) {
            Logger.info(this.getClass().getName(), "No Response Code param found, continuing");
            Try.run(() -> response.sendRedirect("/?error=no+oauth+config"));
            return Result.SKIP_NO_CHAIN;
        }
        
        OauthUtils.getInstance().setNoCacheHeaders(response);
        Logger.info(this.getClass().getName(), "Code param found, doing callback");
        
        final Optional<DefaultApi20> apiProviderOpt = OauthUtils.getInstance().getAPIProvider(config);
        if (!apiProviderOpt.isPresent()) {
            Logger.warn(this.getClass().getName(), "No OAuth API Provider found for :" + requestedURI);
            Try.run(() -> response.sendRedirect("/?error=no+oauth+api+provider"));
            return Result.SKIP_NO_CHAIN;
            
        }
        
        System.err.println("Callback PreLogin Session Id: " + request.getSession().getId());
        
        
        
        try {
            
            final DefaultApi20 apiProvider = apiProviderOpt.get();
            final String callbackHost = config.dotCMSCallBackUrl;
            final String apiKey = config.apiKey;
            final String apiSecret = new String(config.apiSecret);
            final String scope =String.join("+", config.scope);

            // todo: this should be a factory based on the provider type
            final OAuthService service = new ServiceBuilder()
                            .apiKey(apiKey)
                            .apiSecret(apiSecret)
                            .callback(callbackHost + Constants.CALLBACK_URL)
                            .provider(apiProvider)
                            .scope(scope)
                            .build();


            final String redirectAfterLogin = (String) request.getSession().getAttribute(OAUTH_REDIRECT);
            
            // With the authentication code lets try to authenticate to dotCMS
            user= Try.of(()->OauthUtils.getInstance().authenticate(request, response, service))
                            .onFailure(e->Logger.warn(this.getClass().getName(), e.getMessage(), e))
                            .getOrNull();
            
            
            System.err.println("Callback POST login Session Id: " + request.getSession().getId());
            
            
            if(user==null) {
                Try.run(() -> response.sendRedirect("/?error=oauth+user+is+null"));
                return Result.SKIP_NO_CHAIN;
            }

            request.getSession(true);


            // redirect onward!

            request.getSession().removeAttribute(OAUTH_REDIRECT);
            request.getSession().removeAttribute(OAUTH_SERVICE);
            request.getSession().setAttribute(OAUTH_PROVIDER, apiProvider.getClass().getCanonicalName());
            if (redirectAfterLogin == null) {
                return this.redirectLoggedInUser(request, response);
            }

            
            response.sendRedirect(redirectAfterLogin);
            return Result.SKIP_NO_CHAIN; // needs to stop the filter chain.

        } catch (Exception e) {
            Logger.error(this.getClass().getName(), e.getMessage(), e);
        }


        Try.run(() -> response.sendError(403));
        return Result.SKIP_NO_CHAIN;
    }



    /***
     * This redirects the user after they have been logged in.
     * It requires a META refresh rather than a redirect because the users
     * session id might have changed and that change does not get picked up in 
     * a redirect
     * @param request
     * @param response
     * @return
     */
    private Result redirectLoggedInUser(HttpServletRequest request, HttpServletResponse response)  {
        
        User user = PortalUtil.getUser(request);
        
        
        final String redirect = user==null 
                        ? "/?no-user-found-after-oauth"  
                        : user.isFrontendUser()
                            ? "/?already-logged-in"
                            : "/dotAdmin/?r=" + System.currentTimeMillis();
        
        Logger.info(this.getClass().getName(), "Already logged in, redirecting to " + redirect);

        Try.run(() -> 
            response.getWriter().println("<html><head><meta http-equiv=\"refresh\" content=\"0;URL='" + redirect + "'\" /></head><body></body></html>")
        );
        return Result.SKIP_NO_CHAIN;
    }

}
