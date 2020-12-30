package com.dotcms.osgi.oauth.util;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static com.dotcms.osgi.oauth.util.Constants.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.StringTokenizer;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;
import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.enterprise.de.qaware.heimdall.PasswordException;
import com.dotcms.osgi.oauth.app.AppConfig;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.Role;
import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.liferay.portal.auth.PrincipalThreadLocal;
import com.liferay.portal.model.User;
import com.liferay.portal.util.WebKeys;

/**
 * @author Jonathan Gamba 8/24/18
 */
public class OauthUtils {




    private static class SingletonHolder {

        private static final OauthUtils INSTANCE = new OauthUtils();
    }

    public static OauthUtils getInstance() {
        return OauthUtils.SingletonHolder.INSTANCE;
    }




    public Optional<DefaultApi20> getAPIProvider(final AppConfig config) {
        // Look for the provider to use
        String oauthProvider = config.provider;

        DefaultApi20 apiProvider = null;
        if (null != oauthProvider) {

            try {
                // Initializing the API provider
                apiProvider = (DefaultApi20) Class.forName(oauthProvider).newInstance();
            } catch (Exception e) {
                Logger.warnEveryAndDebug(this.getClass(), String.format("Unable to instantiate API provider [%s] [%s]",
                                oauthProvider, e.getMessage()), e, 600000);
            }
        }

        return Optional.ofNullable(apiProvider);
    }

    private synchronized String getOauthProvider(final HttpServletRequest request, final HttpSession session) {

        String oauthProvider = getProperty(OAUTH_PROVIDER_DEFAULT, "org.scribe.builder.api.FacebookApi");

        if (null != session && null != session.getAttribute(OAUTH_PROVIDER)) {
            oauthProvider = (String) session.getAttribute(OAUTH_PROVIDER);
        }

        if (null != request.getParameter(OAUTH_PROVIDER)) {
            oauthProvider = request.getParameter(OAUTH_PROVIDER);
        }

        if (null != session) {
            session.setAttribute(OAUTH_PROVIDER, oauthProvider);
        }

        return oauthProvider;
    } // getOauthProvider.

    /**
     * Default method implementation to extract the access token from the request token json response
     */
    public Token extractToken(final String response) {

        Preconditions.checkEmptyString(response,
                        "Response body is incorrect. Can't extract a token from an empty string");

        try {

            Map<String, Object> json = (Map<String, Object>) new JsonUtil().generate(response);

            if (json.containsKey(OAuthConstants.ACCESS_TOKEN)) {
                String token = OAuthEncoder.decode(json.get(OAuthConstants.ACCESS_TOKEN).toString());
                return new Token(token, EMPTY_SECRET, response);
            } else {
                throw new OAuthException(
                                "Response body is incorrect. Can't extract a token from this: '" + response + "'",
                                null);
            }
        } catch (Exception e) {
            throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'",
                            null);
        }
    }

    
    /**
     * This method gets the user from the remote service and either creates them in dotCMS and/or
     * updates
     *
     * @return User
     * @throws JsonProcessingException
     * @throws JsonMappingException
     */
    public void authenticate(final HttpServletRequest request, final HttpServletResponse response,
                    final OAuthService service, final String protectedResourceUrl, final String firstNameProp,
                    final String lastNameProp) throws DotDataException, JsonMappingException, JsonProcessingException {

        // Request the access token with the authentication code
        final Verifier verifier = new Verifier(request.getParameter("code"));
        final Token accessToken = service.getAccessToken(null, verifier);
        Logger.info(this.getClass().getName(), "Got the Access Token!");

        // Now that we have the token lets try a call to a restricted end point
        final OAuthRequest oauthRequest = new OAuthRequest(Verb.GET, protectedResourceUrl);
        service.signRequest(accessToken, oauthRequest);
        final Response protectedCallResponse = oauthRequest.send();
        if (!protectedCallResponse.isSuccessful()) {
            throw new OAuthException(String.format("Unable to connect to end point [%s] [%s]", protectedResourceUrl,
                            protectedCallResponse.getMessage()));
        }


        final Map<String, Object> userJsonResponse =
                        (Map<String, Object>) new JsonUtil().generate(protectedCallResponse.getBody());


        User user = null;

        // Verify if the user already exist
        try {
            Logger.info(this.getClass().getName(), "Loading an user!");
            final String email = (String) userJsonResponse.get("email");
            final String subject = (String) userJsonResponse.get("sub");


            user = APILocator.getUserAPI().loadByUserByEmail(email, APILocator.systemUser(), false);
            Logger.info(this.getClass().getName(), "User loaded!");
        } catch (Exception e) {
            Logger.warn(this.getClass().getName(), "No matching user, creating");
        }

        // Create the user if does not exist
        if (user == null) {
            try {
                Logger.info(this.getClass().getName(), "User not found, creating one!");
                user = this.createUser(firstNameProp, lastNameProp, userJsonResponse, APILocator.systemUser());
            } catch (Exception e) {
                Logger.warn(this.getClass().getName(), "Error creating user:" + e.getMessage(), e);
                throw new DotDataException(e.getMessage());
            }
        }

        if (user.isActive()) {

            // Set the roles to the user
            setRoles(service, userJsonResponse, user);

            // Authenticate to dotCMS
            Logger.info(this.getClass().getName(), "Doing login!");
            HttpSession httpSession = request.getSession(true);
            final Object accessTokenObject = httpSession.getAttribute(OAuthConstants.ACCESS_TOKEN);
            final boolean rememberMe = "true".equalsIgnoreCase(getProperty(REMEMBER_ME, "true"));
            APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString(user.getUserId()),
                            request, response, rememberMe);

            Logger.info(this.getClass().getName(), "Finish back end login!");
            PrincipalThreadLocal.setName(user.getUserId());
            httpSession = request.getSession(true);
            httpSession.setAttribute(WebKeys.USER_ID, user.getUserId());


            // Keep the token in session
            httpSession.setAttribute(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
        }
    } // authenticate.

    public void setRoles(final OAuthService service, final Map<String, Object> userJsonResponse, final User user)
                    throws DotDataException {

        /*
         * NOTE: We are not creating roles here, the role needs to exist in order to be associated to the
         * user
         */

        // First lets handle the roles we need to add from the configuration file
        Logger.info(this.getClass().getName(), "User is active, adding roles!");
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

    public void addRole(final User user, final String roleKey) throws DotDataException {

        final Role role = APILocator.getRoleAPI().loadRoleByKey(roleKey);
        if (role != null && !APILocator.getRoleAPI().doesUserHaveRole(user, role)) {
            APILocator.getRoleAPI().addRoleToUser(role, user);
        }
    } // addRole.

    public User createUser(final String firstNameProp, final String lastNameProp,
                    final Map<String, Object> userJsonResponse, final User sys)
                    throws DotDataException, DotSecurityException, PasswordException {
        final String subject = (String) userJsonResponse.get("sub");
        final String userId = (subject != null) ? subject : UUIDGenerator.generateUuid();
        final String email = new String(userJsonResponse.get("email").toString().getBytes(), UTF_8);
        final String lastName = new String(userJsonResponse.get(lastNameProp).toString().getBytes(), UTF_8);
        final String firstName = new String(userJsonResponse.get(firstNameProp).toString().getBytes(), UTF_8);

        final User user = APILocator.getUserAPI().createUser(userId, email);
        user.setNickName(firstName);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setActive(true);

        user.setCreateDate(new Date());

        user.setPassword(PasswordFactoryProxy
                        .generateHash(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
        user.setPasswordEncrypted(true);
        APILocator.getUserAPI().save(user, sys, false);

        return user;
    } // createUser.
    
    
}
