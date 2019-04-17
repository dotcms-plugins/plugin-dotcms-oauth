package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.OauthUtils.JAVAX_SERVLET_FORWARD_REQUEST_URI;
import static com.dotcms.osgi.oauth.util.OauthUtils.NATIVE;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_PROVIDER;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.util.OauthUtils.REFERRER;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.util.Logger;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * This interceptor is used for handle the OAuth login check on DotCMS BE.
 *
 * @author jsanca
 */
public class LoginRequiredOAuthInterceptor implements WebInterceptor {

  private static final long serialVersionUID = 1L;

  private static final String NAME = "LoginRequiredOAuthInterceptor_5_1_1";

  // All paths needs to be in lower case as the URI is lowercase before to be evaluated
  private static final String[] BACK_END_URLS = new String[] {"/dotadmin", "/dwr", "/c/"};
  private static final String[] URLS_TO_ALLOW = new String[] {".bundle.", "/appconfiguration", "/authentication", ".chunk.", "/loginform",
      ".woff", ".ttf", "/logout", "/dotadmin/assets/icon/"};
  // All paths needs to be in lower case as the URI is lowercase before to be evaluated
  private static final String[] FRONT_END_URLS = new String[] {"/dotcms/login"};

  private final boolean isFrontEnd;
  private final boolean isBackEnd;


  public LoginRequiredOAuthInterceptor() {


    this.isFrontEnd = new OauthUtils().forFrontEnd();
    this.isBackEnd = new OauthUtils().forBackEnd();
  }

  @Override
  public String[] getFilters() {
    // Verify if a protected page was requested and we need to request a login
    String[] urlsToVerify = new String[] {};
    if (this.isFrontEnd) {
      urlsToVerify = FRONT_END_URLS;
    } else if (this.isBackEnd) {
      urlsToVerify = BACK_END_URLS;
    }

    return urlsToVerify;
  }

  @Override
  public String getName() {
    return NAME;
  }

  /**
   * This login required will be used for the BE, when the user is on BE, is not logged in and the by
   * pass native=true is not in the query string will redirect to the OAUTH Servlet in order to do the
   * authentication with OAUTH
   */
  @Override
  public Result intercept(final HttpServletRequest request, final HttpServletResponse response) throws IOException {

    Result result = Result.NEXT;

    final String requestedURI = request.getRequestURI();

    boolean requiresAuthentication = true;

    // Verify if the requested url requires authentication
    if (null != requestedURI) {
      for (final String allowedSubPath : URLS_TO_ALLOW) {
        if (requestedURI.toLowerCase().contains(allowedSubPath.toLowerCase())) {
          requiresAuthentication = false;
          break;
        }
      }
    }

    // If we already have an user we can continue
    boolean isLoggedInUser = APILocator.getLoginServiceAPI().isLoggedIn(request);
    if (!isLoggedInUser && requiresAuthentication) {

      // Should we use regular login?, we need to allow some urls in order to load the admin page
      boolean isNative = Boolean.TRUE.toString().equalsIgnoreCase(request.getParameter(NATIVE));

      if (!isNative) {

        // Look for the provider to use
        OAuth20Service service = new OauthUtils().getOAuthService(request);

        if (null != service) {

          // Send for authorization
          Logger.info(this.getClass(), "Sending for authorization");
          sendForAuthorization(request, response, service);
          result = Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
        }

      }
    }

    return result; // if it is log in, continue!
  } // intercept.

  private void sendForAuthorization(final HttpServletRequest request, final HttpServletResponse response, final OAuth20Service service)
      throws IOException {
    
    String retUrl = (String) request.getAttribute(JAVAX_SERVLET_FORWARD_REQUEST_URI);

    

    if (request.getParameter(REFERRER) != null) {
      retUrl = request.getParameter(REFERRER);
    }
    if(request.getSession()!=null) {
      request.getSession().setAttribute(OAUTH_REDIRECT, retUrl);
      request.getSession().setAttribute(OAUTH_PROVIDER, service.getApi().getClass().getName());
      if (request.getSession().getAttribute(OAUTH_REDIRECT) != null) {
        retUrl = (String) request.getSession().getAttribute(OAUTH_REDIRECT);
      }

      
      
    }
    final String authorizationUrl = service.getAuthorizationUrl();
    Logger.info(this.getClass(), "Redirecting for authentication to: " + authorizationUrl);
    response.sendRedirect(authorizationUrl);
  }

} // BackEndLoginRequiredOAuthInterceptor.
