/*
 * WebSessionFilter
 *
 * A filter that recognizes return users who have chosen to have their login information remembered.
 * Creates a valid WebSession object and passes it a contact to use to fill its information
 *
 */
package com.dotcms.osgi.oauth.interceptor;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static com.dotcms.osgi.oauth.util.OauthUtils.CALLBACK_URL;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_API_PROVIDER;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_PROVIDER;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_REDIRECT;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_SERVICE;

import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.util.Logger;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.liferay.portal.model.User;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class OAuthCallbackInterceptor implements WebInterceptor {

  private static final String NAME = "AutoLoginOAuthInterceptor_5_0_1";
  private final String oauthCallBackURL;
  private final boolean isBackEnd;
  private final OauthUtils oauthUtils;

  public OAuthCallbackInterceptor() throws DotDataException {
    this.oauthUtils = OauthUtils.getInstance();
    this.oauthCallBackURL = getProperty(CALLBACK_URL).toLowerCase();
    this.isBackEnd = oauthUtils.forBackEnd();
  }

  @Override
  public String[] getFilters() {
    return new String[] {this.oauthCallBackURL};
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public Result intercept(HttpServletRequest request, HttpServletResponse response) {
    Result result = Result.NEXT;

    // If we already have an user we can continue
    boolean isLoggedInUser = APILocator.getLoginServiceAPI().isLoggedIn(request);
    if (!isLoggedInUser) {

      final HttpSession session = request.getSession(false);

      final String responseCode = request.getParameter(OAuthConstants.CODE);
      if (null != responseCode) {

        Logger.info(this.getClass(), "Code param found, doing callback");
        try {

          final OAuth20Service oAuthService = (OAuth20Service) session.getAttribute(OAUTH_SERVICE);
          final DefaultApi20 apiProvider = (DefaultApi20) session.getAttribute(OAUTH_API_PROVIDER);

          final String providerName = apiProvider.getClass().getSimpleName();
          final String protectedResourceUrl = getProperty(providerName + "_PROTECTED_RESOURCE_URL");
          final String firstNameProp = getProperty(providerName + "_FIRST_NAME_PROP");
          final String lastNameProp = getProperty(providerName + "_LAST_NAME_PROP");

          // With the authentication code lets try to authenticate to dotCMS
          this.authenticate(request, response, oAuthService, protectedResourceUrl, firstNameProp, lastNameProp);

          // redirect onward!
          final String authorizationUrl = (String) session.getAttribute(OAUTH_REDIRECT);

          if (authorizationUrl == null) {
            this.alreadyLoggedIn(response);
          } else {
            session.removeAttribute(OAUTH_REDIRECT);
            session.removeAttribute(OAUTH_SERVICE);
            session.removeAttribute(OAUTH_API_PROVIDER);
            session.setAttribute(OAUTH_PROVIDER, apiProvider.getClass().getCanonicalName());
            response.sendRedirect(authorizationUrl);
            result = Result.SKIP_NO_CHAIN; // needs to stop the filter chain.
          }
        } catch (Exception e) {
          Logger.error(this, e.getMessage(), e);
        }

      }
    }

    return result;
  }

  /**
   * This method gets the user from the remote service and either creates them in dotCMS and/or
   * updates
   * 
   * @throws ExecutionException
   * @throws InterruptedException
   * @throws IOException
   */
  private User authenticate(final HttpServletRequest request, final HttpServletResponse response, final OAuth20Service service,
      final String protectedResourceUrl, final String firstNameProp, final String lastNameProp)
      throws DotDataException, IOException, InterruptedException, ExecutionException {

    // Request the access token with the authentication code

    final OAuth2AccessToken accessToken = service.getAccessToken(request.getParameter("code"));
    Logger.info(this.getClass(), "Got the Access Token!");

    // Now that we have a access token we can retrieve the user info and authenticate it
    return oauthUtils.authenticate(request, response, accessToken, service, protectedResourceUrl, firstNameProp, lastNameProp);
  }

  private void alreadyLoggedIn(HttpServletResponse response) throws IOException {

    if (this.isBackEnd) {
      Logger.info(this.getClass(), "Already logged in, redirecting to /dotAdmin");
    } else {
      Logger.info(this.getClass(), "Already logged in, redirecting home");
    }

    response.sendRedirect((this.isBackEnd) ? "/dotAdmin" : "/?already-logged-in");
  }

}
