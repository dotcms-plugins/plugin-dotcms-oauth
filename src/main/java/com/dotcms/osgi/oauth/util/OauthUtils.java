package com.dotcms.osgi.oauth.util;


import static com.dotcms.osgi.oauth.util.Constants.EMPTY_SECRET;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.dotmarketing.util.UtilMethods;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.liferay.portal.model.User;
import com.liferay.portal.util.PortalUtil;
import io.vavr.control.Try;

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
    public void setNoCacheHeaders(HttpServletResponse response) {
        // set no cache on the login page

            Logger.info(this.getClass().getName(), "Login Flow, setting no-cache headers");
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); 
            response.setHeader("Pragma", "no-cache"); 
            response.setDateHeader("Expires", 0); 

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
                Logger.warn(this.getClass().getName(), String.format("Unable to instantiate API provider [%s] [%s]",
                                oauthProvider, e.getMessage()));
            }
        }

        return Optional.ofNullable(apiProvider);
    }



    /**
     * Default method implementation to extract the access token from the request token json response
     */
    public Token extractToken(final String response) {

        Preconditions.checkEmptyString(response,
                        "Response body is incorrect. Can't extract a token from an empty string");


        Map<String, Object> json = (Map<String, Object>) Try.of(() -> new JsonUtil().generate(response))
                        .getOrElseThrow(e -> new DotRuntimeException("unable to get json", e));


        if (json.containsKey(OAuthConstants.ACCESS_TOKEN)) {
            String token = OAuthEncoder.decode(json.get(OAuthConstants.ACCESS_TOKEN).toString());
            return new Token(token, EMPTY_SECRET, response);
        }
        throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'",
                        null);


    }

    
    /**
     * This method gets the user from the remote service and either creates them in dotCMS and/or
     * updates
     *
     * @return User
     * @throws JsonProcessingException
     * @throws JsonMappingException
     */
    public User authenticate(final HttpServletRequest request, final HttpServletResponse response,
                    final OAuthService service) throws DotDataException, JsonMappingException, JsonProcessingException {

        if(PortalUtil.getUser(request)!=null) {
            return PortalUtil.getUser(request);
        }
        
        
        
        final boolean frontEndUser =  request.getSession().getAttribute(Constants.FRONT_END_LOGIN)!=null;
        AppConfig appConfig = AppConfig.config().get();
        
        
        // Request the access token with the authentication code
        final Verifier verifier = new Verifier(request.getParameter("code"));
        final Token accessToken = service.getAccessToken(null, verifier);
        Logger.info(this.getClass().getName(), "Got the Access Token!");

        // Now that we have the token lets try a call to a restricted end point
        final OAuthRequest oauthRequest = new OAuthRequest(Verb.GET, appConfig.protectedResource);
        service.signRequest(accessToken, oauthRequest);
        final Response protectedCallResponse = oauthRequest.send();
        if (!protectedCallResponse.isSuccessful()) {
            throw new OAuthException(String.format("Unable to connect to end point [%s] [%s]", appConfig.protectedResource,
                            protectedCallResponse.getMessage()));
        }

        // Case insensitive map (all lower case)
        Map<String, Object> jsonMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        jsonMap.putAll((Map<String, Object>) new JsonUtil().generate(protectedCallResponse.getBody()));
        
        User user = null;

        // Verify if the user already exists
        final String email = (String) getEmail(jsonMap);
        final String subject = (String) jsonMap.get("sub");

        Logger.info(this.getClass().getName(), "Loading user by email");
        user = Try.of( ()-> APILocator.getUserAPI().loadByUserByEmail(email, APILocator.systemUser(), false)).getOrNull();
        
        if (user == null) {
            Logger.info(this.getClass().getName(), "Loading user by id");
            user = Try.of( ()-> APILocator.getUserAPI().loadUserById(subject)).getOrNull();
        }
        

        // Create the user if does not exist
        if (user == null) {
            try {
                Logger.info(this.getClass().getName(), "User " + email + " not found, creating one!");
                user = this.createUser(jsonMap);
            } catch (Exception e) {
                Logger.warn(this.getClass().getName(), "Error creating user " + email  + " : " + e.getMessage(), e);
                throw new DotDataException(e.getMessage());
            }
        }

        if(!user.isActive()) {
            
            throw new DotRuntimeException("The user is not active in the system");
        }
        
        jsonMap.put("access_token", accessToken);

        setSystemRoles(user, frontEndUser);
        
        // Set the roles to the user
        setRoles(service, jsonMap, user);

        // Authenticate to dotCMS
        Logger.info(this.getClass().getName(), "Doing OAuth login!");

        
        APILocator.getLoginServiceAPI().doCookieLogin(PublicEncryptionFactory.encryptString(user.getUserId()),
                        request, response, false);

        Logger.info(this.getClass().getName(), "Finishing OAuth login!");


        // Keep the token in session
        request.getSession().setAttribute(OAuthConstants.ACCESS_TOKEN, accessToken.getToken());
    
        return user;
    } // authenticate.


    public void setSystemRoles(User user, boolean frontEnd) {

        final Role roleToAdd = frontEnd 
                        ? Try.of(() -> APILocator.getRoleAPI().loadLoggedinSiteRole()).getOrNull()
                        : Try.of(() -> APILocator.getRoleAPI().loadBackEndUserRole()).getOrNull();

        if (roleToAdd != null) {
            Try.run(() -> APILocator.getRoleAPI().addRoleToUser(roleToAdd, user)).onFailure(e->{Logger.warn(OauthUtils.class.getName(), e.getMessage(),e);});
        }


    }
    
    
    
    
    public void setRoles(final OAuthService service, final Map<String, Object> userJsonResponse, final User user)
                    throws DotDataException {

        /*
         * NOTE: We are not creating roles here, the role needs to exist in order to be associated to the
         * user
         */
        AppConfig appConfig = AppConfig.config().get();
        // First lets handle the roles we need to add from the configuration file
        Logger.info(this.getClass().getName(), "User is active, adding roles!");
        
        final String[] rolesToAdd = appConfig.getArrayValue("role.extra");
        
        for (String roleKey : rolesToAdd) {
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

    
    public User createUser(final Map<String, Object> userJsonResponse )
                    throws DotDataException, DotSecurityException, PasswordException {
        final String subject = (String) userJsonResponse.get("sub");
        final String email = getEmail(userJsonResponse);
        final String userId = (subject != null) ? subject : UUIDGenerator.generateUuid();
        
        final String lastName = getLastName(userJsonResponse);
        final String firstName = getFirstName(userJsonResponse);

        final User user = APILocator.getUserAPI().createUser(userId, email);
        user.setNickName(firstName);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setActive(true);

        user.setCreateDate(new Date());

        user.setPassword(PasswordFactoryProxy
                        .generateHash(UUIDGenerator.generateUuid() + "/" + UUIDGenerator.generateUuid()));
        user.setPasswordEncrypted(true);
        APILocator.getUserAPI().save(user, APILocator.systemUser(), false);

        return user;
    } // createUser.
    
    private String getEmail(Map<String, Object> jsonMap) {

        String email= (String) jsonMap.getOrDefault("email", 
                        jsonMap.getOrDefault("email_address", 
                        jsonMap.getOrDefault("emailaddress", 
                        jsonMap.getOrDefault("userPrincipalName", null))));
        
        return UtilMethods.isValidEmail(email) ? email : null;
        

    }
    private String getSubject(Map<String, Object> jsonMap) {

        String email= (String) jsonMap.getOrDefault("email", 
                        jsonMap.getOrDefault("email_address", 
                        jsonMap.getOrDefault("emailaddress", 
                        jsonMap.getOrDefault("userPrincipalName", null))));
        
        return UtilMethods.isValidEmail(email) ? email : null;
        

    }
    
    private String getFirstName(Map<String, Object> jsonMap) {
        return (String) jsonMap.getOrDefault("first_name", 
                        jsonMap.getOrDefault("firstname",
                        jsonMap.getOrDefault("given_name", 
                        jsonMap.getOrDefault("givenname", 
                        "unknown"))));

    }
    
    private String getLastName(Map<String, Object> jsonMap) {
        return (String) jsonMap.getOrDefault("last_name", 
                        jsonMap.getOrDefault("lastname",
                        jsonMap.getOrDefault("family_name", 
                        jsonMap.getOrDefault("familyname", 
                        jsonMap.getOrDefault("surname", 
                        "unknown")))));

    }
    
    
}
