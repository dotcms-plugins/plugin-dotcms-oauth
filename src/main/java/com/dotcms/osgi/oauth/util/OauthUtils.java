package com.dotcms.osgi.oauth.util;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static com.dotcms.osgi.oauth.util.OauthUtils.CALLBACK_URL;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.lang.reflect.Method;

import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.enterprise.de.qaware.heimdall.PasswordException;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.utils.OAuthEncoder;
import com.github.scribejava.core.utils.Preconditions;
import com.liferay.portal.auth.PrincipalThreadLocal;
import com.liferay.portal.model.User;
import com.liferay.portal.util.WebKeys;
import java.util.Collection;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.concurrent.ExecutionException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OauthUtils {

  public static final String OAUTH_PROVIDER = "OAUTH_PROVIDER";
  public static final String OAUTH_PROVIDER_DEFAULT = "DEFAULT_OAUTH_PROVIDER";
  public static final String OAUTH_REDIRECT = "OAUTH_REDIRECT";
  public static final String OAUTH_SERVICE = "OAUTH_SERVICE";
  public static final String OAUTH_API_PROVIDER = "OAUTH_API_PROVIDER";

  public static final String ROLES_TO_ADD = "ROLES_TO_ADD";
  public static final String CALLBACK_URL = "CALLBACK_URL";

  public static final String NATIVE = "native";
  public static final String REFERRER = "referrer";

  public static final String JAVAX_SERVLET_FORWARD_REQUEST_URI = "javax.servlet.forward.request_uri";

  public static final String FEMALE = "female";
  public static final String GENDER = "gender";

  public static final String REMEMBER_ME = "rememberMe";

  public static final String EMPTY_SECRET = "";

  private static class SingletonHolder {

    private static final OauthUtils INSTANCE = new OauthUtils();
  }

  public static OauthUtils getInstance() {
    return OauthUtils.SingletonHolder.INSTANCE;
  }

  private OauthUtils() {
    // singleton
  }

  public boolean forFrontEnd() {

    final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "").toLowerCase();
    return useFor.contains("frontend");
  }

  public boolean forBackEnd() {

    final String useFor = OAuthPropertyBundle.getProperty("USE_OAUTH_FOR", "").toLowerCase();
    return useFor.contains("backend");
  }

  public OAuth20Service getOAuthService(final HttpServletRequest request) {
    // Look for the provider to use
    String oauthProvider = getOauthProvider(request);

    DefaultApi20 apiProvider = null;
    if (null != oauthProvider) {

      try {

        Class clazz = Class.forName(oauthProvider);
        Method instanceMethod = clazz.getDeclaredMethod("instance");
        if (instanceMethod != null) {
          apiProvider = (DefaultApi20) instanceMethod.invoke(clazz);
        } else {
          apiProvider = (DefaultApi20) clazz.newInstance();
        }

      } catch (Exception e) {
        throw new DotRuntimeException(e);
      }
    }
    final String callbackHost = this.getCallbackHost(request);
    final String providerName = apiProvider.getClass().getSimpleName();
    final String apiKey = getProperty(providerName + "_API_KEY");
    final String apiSecret = getProperty(providerName + "_API_SECRET");
    final String scope = getProperty(providerName + "_SCOPE");
    final String oauthCallBackURL = getProperty(CALLBACK_URL);
    ServiceBuilder builder = new ServiceBuilder(apiKey);
    if (null != apiSecret) {
      builder.apiSecret(apiSecret);
    }
    builder.callback(callbackHost + oauthCallBackURL);
    builder.defaultScope(scope);
    return builder.build(apiProvider);

  }

  private String getCallbackHost(final HttpServletRequest request) {

    String hostName = request.getHeader("host");
    hostName = hostName.contains(":") ? hostName.substring(0, hostName.indexOf(":")) : hostName;

    return (request.isSecure()) ? "https"
        : "http" + "://"
            + (request.getServerPort() == 80 || request.getServerPort() == 443 ? hostName : hostName + ":" + request.getServerPort());
  }

  private synchronized String getOauthProvider(final HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    String oauthProvider = getProperty(OAUTH_PROVIDER_DEFAULT, "org.scribe.builder.api.FacebookApi");

    if (null != session && null != session.getAttribute(OAUTH_PROVIDER)) {
      oauthProvider = (String) session.getAttribute(OAUTH_PROVIDER);
    }

    if (null != request.getParameter(OAUTH_PROVIDER)) {
      oauthProvider = request.getParameter(OAUTH_PROVIDER);
    }

    if (null != request.getAttribute(OAUTH_PROVIDER)) {
      oauthProvider = (String) request.getAttribute(OAUTH_PROVIDER);
    }

    if (null != session) {
      session.setAttribute(OAUTH_PROVIDER, oauthProvider);
    }

    return oauthProvider;
  } // getOauthProvider.

  /**
   * Default method implementation to extract the access token from the request token json response
   */
  public OAuth2AccessToken extractToken(String response) {

    Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");

    try {
      final JSONObject jsonResponse = (JSONObject) new JSONTool().generate(response);
      if (jsonResponse.has(OAuthConstants.ACCESS_TOKEN)) {
        String token = OAuthEncoder.decode(jsonResponse.get(OAuthConstants.ACCESS_TOKEN).toString());
        return new OAuth2AccessToken(token, response);
      } else {
        throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
      }
    } catch (Exception e) {
      throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
    }
  }

  /**
   * This method gets the user from the remote service and either creates them in dotCMS and/or
   * updates
   * 
   * @throws IOException
   * @throws ExecutionException
   * @throws InterruptedException
   */
  public User authenticate(final HttpServletRequest request, final HttpServletResponse response, final OAuth2AccessToken accessToken,
      final OAuth20Service service, final String protectedResourceUrl, final String firstNameProp, final String lastNameProp)
      throws DotDataException, InterruptedException, ExecutionException, IOException {

    final User systemUser = APILocator.getUserAPI().getSystemUser();

    // Now that we have the token lets try a call to a restricted end point
    final OAuthRequest oauthRequest = new OAuthRequest(Verb.GET, protectedResourceUrl);
    service.signRequest(accessToken, oauthRequest);
    final Response protectedCallResponse = service.execute(oauthRequest);
    if (!protectedCallResponse.isSuccessful()) {
      throw new OAuthException(
          String.format("Unable to connect to end point [%s] [%s]", protectedResourceUrl, protectedCallResponse.getMessage()));
    }

    // Parse the response in order to get the user data
    final JSONObject userJsonResponse = (JSONObject) new JSONTool().generate(protectedCallResponse.getBody());

    User user = null;

    // Verify if the user already exist
    try {
      Logger.info(this.getClass(), "Loading an user!");
      final String email = userJsonResponse.optString("email", userJsonResponse.optString("emailAddress", userJsonResponse.optString("userPrincipalName", null)));


      user = APILocator.getUserAPI().loadByUserByEmail(email, systemUser, false);
      Logger.info(this.getClass(), "User loaded!");
    } catch (Exception e) {
      Logger.warn(this, "No matching user, creating");
    }

    // Create the user if does not exist
    if (null == user) {

      try {
        Logger.info(this.getClass(), "User not found, creating one!");
        user = this.createUser(firstNameProp, lastNameProp, userJsonResponse, systemUser);

        // Set the roles to the user
        setRoles(service, userJsonResponse, user);

      } catch (Exception e) {
        Logger.warn(this, "Error creating user:" + e.getMessage(), e);
        throw new DotDataException(e.getMessage());
      }
    }

    if (user.isActive()) {

      // Authenticate to dotCMS
      Logger.info(this.getClass(), "Doing login!");
      HttpSession httpSession = request.getSession(true);

      if (this.forFrontEnd()) {
        httpSession.setAttribute(com.dotmarketing.util.WebKeys.CMS_USER, user);
      }

      if (this.forBackEnd()) {

        final boolean rememberMe = "true".equalsIgnoreCase(getProperty(REMEMBER_ME, "true"));
        APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString(user.getUserId()), request, response,
            rememberMe);

        Logger.info(this.getClass(), "Finish back end login!");
        PrincipalThreadLocal.setName(user.getUserId());
        httpSession.setAttribute(WebKeys.USER_ID, user.getUserId());
      }

      // Keep the token in session
      httpSession.setAttribute(OAuthConstants.ACCESS_TOKEN, accessToken.getAccessToken());
    }

    return user;
  } // authenticate.

  private void setRoles(final OAuth20Service service, final JSONObject userJsonResponse, final User user)
      throws DotDataException, InterruptedException, ExecutionException, IOException {

    /*
     * NOTE: We are not creating roles here, the role needs to exist in order to be associated to the
     * user
     */

    // First lets handle the roles we need to add from the configuration file
    Logger.info(this.getClass(), "User is active, adding roles!");
    final String rolesToAdd = getProperty(ROLES_TO_ADD);
    final StringTokenizer st = new StringTokenizer(rolesToAdd, ",;");
    while (st.hasMoreElements()) {
      final String roleKey = st.nextToken().trim();
      this.addRole(user, roleKey);
    }

    // Now from the remote server
    Collection<String> remoteRoles;
    if (service instanceof DotService) {
      remoteRoles = ((DotService) service).getGroups(user, userJsonResponse);

      if (null != remoteRoles && !remoteRoles.isEmpty()) {
        for (final String roleKey : remoteRoles) {
          this.addRole(user, roleKey);
        }
      }
    }

  }

  private void addRole(final User user, final String roleKey) throws DotDataException {

    final Role role = APILocator.getRoleAPI().loadRoleByKey(roleKey);
    if (role != null && !APILocator.getRoleAPI().doesUserHaveRole(user, role)) {
      APILocator.getRoleAPI().addRoleToUser(role, user);
    }
  } // addRole.

  private User createUser(final String firstNameProp, final String lastNameProp, final JSONObject json, final User sys)
      throws JSONException, DotDataException, DotSecurityException, PasswordException {

    System.err.println("UserJSon=" + json);
    final String userId = UUIDGenerator.generateUuid();
    final String email = json.optString("email", json.optString("emailAddress", json.optString("userPrincipalName", null)));
    final String lastName = json.optString(lastNameProp, json.optString("lastName", json.optString("surname", null)));
    final String firstName = json.optString(firstNameProp, json.optString("firstName", json.optString("givenName", json.optString("displayName", null))));


    final User user = APILocator.getUserAPI().createUser(userId, email);

    user.setFirstName(firstName);
    user.setLastName(lastName);
    user.setActive(true);

    user.setCreateDate(new Date());
    if (!json.isNull(GENDER)) {
      user.setFemale(FEMALE.equals(json.getString(GENDER)));
    }
    user.setPassword(PasswordFactoryProxy.generateHash(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
    user.setPasswordEncrypted(true);
    APILocator.getUserAPI().save(user, sys, false);

    return user;
  } // createUser.

}
