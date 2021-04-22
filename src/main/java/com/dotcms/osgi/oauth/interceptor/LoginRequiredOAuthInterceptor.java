package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.Constants.JAVAX_SERVLET_FORWARD_REQUEST_URI;
import static com.dotcms.osgi.oauth.util.Constants.NATIVE;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_API_PROVIDER;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.util.Constants.OAUTH_SERVICE;
import static com.dotcms.osgi.oauth.util.Constants.REFERRER;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.Token;
import org.scribe.oauth.OAuthService;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.app.AppConfig;
import com.dotcms.osgi.oauth.app.AppConfigThreadLocal;
import com.dotcms.osgi.oauth.util.Constants;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.util.Logger;
import com.google.common.collect.ImmutableList;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PortalUtil;
import io.vavr.control.Try;

/**
 * This interceptor is used for handle the OAuth login check on DotCMS BE.
 *
 * @author jsanca
 */
public class LoginRequiredOAuthInterceptor implements WebInterceptor {


    
    private static final List<String> BACK_END_URLS = ImmutableList.of("/html/portal/login,", "/dotAdmin/", "/c/");
    private static final List<String> BACK_END_URLS_TO_ALLOW = ImmutableList.of(".bundle.", "/appconfiguration",
            "/authentication", ".chunk.", "/loginform", ".woff", ".ttf", "/logout", ".js", ".css");
    private static final List<String> FRONT_END_URLS = ImmutableList.of("/dotCMS/login","/application/login/login*","/login*");

    private static final Token EMPTY_TOKEN = null;


    private final OauthUtils oauthUtils;
    public LoginRequiredOAuthInterceptor() {
        
        oauthUtils= OauthUtils.getInstance();

    }

    
    @Override
    public String[] getFilters() {
        return new ImmutableList.Builder<String>()
                        .addAll(BACK_END_URLS)
                        .addAll(FRONT_END_URLS)
                        .build()
                        .toArray(new String[0]);

    }
    /**
     * This login required will be used for the BE, when the user is on BE, is not logged in and the by
     * pass native=true is not in the query string will redirect to the OAUTH Servlet in order to do the
     * authentication with OAUTH
     */
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

        final String uri = request.getRequestURI();
        // If we already have a logged in user, continue
        User user = PortalUtil.getUser(request);

        if (null != user) {
            return Result.NEXT;
        }
        
        
        Optional<AppConfig> configOpt = AppConfig.config(request);

        
        // if we have no oauth configured, continue
        if(!configOpt.isPresent()) {
            return Result.NEXT;
        }
        AppConfig config = configOpt.get();
        // clear native if ?native=false
        if (Boolean.FALSE.toString().equalsIgnoreCase(request.getParameter(NATIVE)) ) {
            request.getSession().removeAttribute(Constants.CMS_NATIVE_LOGIN);
        }
        
        // if ?native=true set it in session and continue
        if (Boolean.TRUE.toString().equalsIgnoreCase(request.getParameter(NATIVE))) {
            if(request.getSession().getAttribute(Constants.CMS_NATIVE_LOGIN)==null) {
                request.getSession().setAttribute(Constants.CMS_NATIVE_LOGIN,Boolean.TRUE);
            }
            return Result.NEXT;
        }
        

        // if we allow this url, continue
        if(BACK_END_URLS_TO_ALLOW.stream().filter(s->uri.contains(s)).findAny().isPresent()) {
            return Result.NEXT;
        }
            
        // set no cache headers if needed
        OauthUtils.getInstance().setNoCacheHeaders(response);
        
        // set FRONT_END_LOGIN to true if a front end login
        if(config.enableFrontend 
                        && request.getSession().getAttribute(Constants.FRONT_END_LOGIN)==null 
                        && FRONT_END_URLS.stream().filter(s->uri.startsWith(s)).findAny().isPresent()) {
            request.getSession().setAttribute(Constants.FRONT_END_LOGIN,Boolean.TRUE);
        }
        

        // OAUTH HERE, get the provider class from the config
        final Optional<DefaultApi20> apiProviderOpt = this.oauthUtils.getAPIProvider(config);
        
        if (apiProviderOpt.isPresent()) {
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

            // Send for authorization
            Logger.info(this.getClass().getName(), "Sending for authorization");
            sendForAuthorization(request, response, service, apiProvider);
            return Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
        }

            
        

        return Result.NEXT;
    } // intercept.

    

    
    private void sendForAuthorization(final HttpServletRequest request, final HttpServletResponse response,
                    final OAuthService service, final DefaultApi20 apiProvider) throws IOException {

        String retUrl = request.getAttribute(JAVAX_SERVLET_FORWARD_REQUEST_URI) !=null 
                        ?(String) request.getAttribute(JAVAX_SERVLET_FORWARD_REQUEST_URI)
                        : request.getRequestURI();

        if (request.getSession().getAttribute(OAUTH_REDIRECT) != null) {
            retUrl = (String) request.getSession().getAttribute(OAUTH_REDIRECT);
        }

        if (request.getParameter(REFERRER) != null) {
            retUrl = request.getParameter(REFERRER);
        }

        request.getSession().setAttribute(OAUTH_REDIRECT, retUrl);
        request.getSession().setAttribute(OAUTH_SERVICE, service);
        request.getSession().setAttribute(OAUTH_API_PROVIDER, apiProvider);

        final String authorizationUrl = service.getAuthorizationUrl(EMPTY_TOKEN);
        Logger.info(this.getClass().getName(), "Redirecting for authentication to: " + authorizationUrl);

        System.err.println("Initial Session Id: " + request.getSession().getId());
        
        
        
        Try.run(() -> {
            response.getWriter().println("<html><head><meta http-equiv=\"refresh\" content=\"0;URL='" + authorizationUrl + "'\" /></head><body></body></html>");
            response.getWriter().close();
        }
        );

        
        //response.sendRedirect(authorizationUrl);
    }



} // BackEndLoginRequiredOAuthInterceptor.
