package com.dotcms.osgi.oauth.rest;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;
import static com.dotcms.osgi.oauth.util.OauthUtils.EMPTY_SECRET;
import static com.dotcms.osgi.oauth.util.OauthUtils.OAUTH_PROVIDER;
import static com.dotcms.util.CollectionsUtils.map;
import static java.util.Collections.EMPTY_MAP;

import com.dotcms.auth.providers.jwt.JsonWebTokenUtils;
import com.dotcms.cms.login.LoginServiceAPI;
import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotcms.repackage.com.google.common.annotations.VisibleForTesting;
import com.dotcms.repackage.javax.ws.rs.POST;
import com.dotcms.repackage.javax.ws.rs.Path;
import com.dotcms.repackage.javax.ws.rs.Produces;
import com.dotcms.repackage.javax.ws.rs.core.Context;
import com.dotcms.repackage.javax.ws.rs.core.MediaType;
import com.dotcms.repackage.javax.ws.rs.core.Response;
import com.dotcms.rest.ErrorEntity;
import com.dotcms.rest.InitDataObject;
import com.dotcms.rest.ResponseEntityView;
import com.dotcms.rest.WebResource;
import com.dotcms.rest.annotation.NoCache;
import com.dotcms.rest.api.v1.authentication.ResponseUtil;
import com.dotcms.rest.exception.mapper.ExceptionMapperUtil;
import com.dotcms.util.HttpRequestDataUtil;
import com.dotcms.util.SecurityLoggerServiceAPI;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.SecurityLogger;
import com.dotmarketing.util.UtilMethods;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.github.scribejava.core.oauth.OAuthService;
import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.PortalException;
import com.liferay.portal.RequiredLayoutException;
import com.liferay.portal.SystemException;
import com.liferay.portal.UserActiveException;
import com.liferay.portal.UserEmailAddressException;
import com.liferay.portal.UserPasswordException;
import com.liferay.portal.auth.AuthException;
import com.liferay.portal.language.LanguageException;
import com.liferay.portal.language.LanguageUtil;
import com.liferay.portal.language.LanguageWrapper;
import com.liferay.portal.model.User;
import com.liferay.util.LocaleUtil;
import java.io.Serializable;
import java.util.Collections;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Create a new Json Web Token
 *
 * @author jsanca
 */
@Path("/v1/authentication")
public class JsonWebTokenResource implements Serializable {

    private final static int JSON_WEB_TOKEN_MAX_ALLOWED_EXPIRATION_DAYS_DEFAULT_VALUE = 30;
    private final ResponseUtil responseUtil;
    private final JsonWebTokenUtils jsonWebTokenUtils;
    private final SecurityLoggerServiceAPI securityLoggerServiceAPI;
    private final WebResource webResource;

    private final OauthUtils oauthUtils;

    /**
     * Default constructor.
     */
    public JsonWebTokenResource() {
        this(
                OauthUtils.getInstance(),
                ResponseUtil.INSTANCE,
                JsonWebTokenUtils.getInstance(),
                APILocator.getSecurityLogger(),
                new WebResource()
        );
    }

    @VisibleForTesting
    protected JsonWebTokenResource(
            final OauthUtils oauthUtils,
            final ResponseUtil responseUtil,
            final JsonWebTokenUtils jsonWebTokenUtils,
            final SecurityLoggerServiceAPI securityLoggerServiceAPI,
            final WebResource webResource
    ) {
        this.oauthUtils = oauthUtils;
        this.responseUtil = responseUtil;
        this.jsonWebTokenUtils = jsonWebTokenUtils;
        this.securityLoggerServiceAPI = securityLoggerServiceAPI;
        this.webResource = webResource;
    }

    /**
     * Method that generates a JWT token for an authenticated user
     *
     * <pre>
     * curl -u admin@dotcms.com:admin -XPOST http://localhost:8080/api/v1/authentication/token \
     * -H "Content-Type:application/json" \
     * -d '{
     *     "expirationDays": 10
     * }'
     * </pre>
     *
     * <pre>
     * curl -XPOST http://localhost:8080/api/v1/authentication/token \
     * -H "Content-Type:application/json" \
     * -d '{
     *     "oauthToken":"eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.eyJzY29wZSI6WyJvcGVuaWQiLCJlbWFpbCIsInByb2ZpbGUiLCJjbXMiXSwiY2xpZW50X2lkX25hbWUiOiJkb3RjbXMiLCJzdWIiOiJwcmFzYW5uYSIsIk9yZ05hbWUiOiJCbGFoIiwiVXNlcm5hbWUiOiJwcmFzYW5uYSIsImhvdXNlIjoiQ01TIEFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InVzZXIuMzc2QGV4YW1wbGUuY29tIiwiZXhwIjoxNTM5MjA4MTE4fQ.RCeSxqbUYWZBFK_77BG1sI5V7aPhBf_Pk2vToLAHi0rzjf0u4nJWDncLW53nSHn2KQ7YI9_hWrxqJkv8403FpLlBpqAfJdnSd0uhvDCt-g-my5DkYUHd-PC6DdCFzPYLlCi3Tu4Wo77AZivTPOKM2XTSNVL_Kucn0RvebMphKKbbw46sOJgmeQ_cGXC64160nm5Zg83ix69JJO_imYUGVZx4HKgKsoW7n942ALv3ZEuyLruNQDGS__k8HwgVyNtMLdOCdaZjDVK42jVCd-K92LWZ5I3XTqLXmhGW63a-xkQz5HDGMmcE3-h3avILCLY1mrGLyZZ3InrkHG6r9xo__A",
     *     "oauthProvider":"com.dotcms.osgi.oauth.provider.Ping20Api",
     *     "expirationDays": 10
     * }'
     * </pre>
     */
    @POST
    @Path("/token")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public final Response getToken(@Context final HttpServletRequest request,
            @Context final HttpServletResponse response,
            final TokenForm tokenForm) {

        String userId = null;
        Response res = null;
        Locale locale = LocaleUtil.getLocale(request);

        try {

            //Authenticate the user
            final InitDataObject initDataObject = this.webResource.init
                    (null, true, request, false, null);

            //We can not request tokens as an anonymous user
            User user = initDataObject.getUser();
            if (null != user) {
                final User anonymousUser = APILocator.getUserAPI().getAnonymousUser();
                if (user.getUserId().equals(anonymousUser.getUserId())) {
                    user = null;
                }
            }

            final int expirationDays = tokenForm.getExpirationDays();

            if (null != user) {//We already found an user, we can deliver a token
                userId = user.getUserId();

                //Generate the token for this user
                res = generateToken(user, expirationDays, request);
            } else {

                //Verify if we found an oauth2 token in the request
                final String oauth2Token = tokenForm.getOauthToken();
                if (UtilMethods.isSet(oauth2Token)) {

                    final HttpSession session = request.getSession(false);

                    final String oauth2Provider = tokenForm.getOauthProvider();
                    if (UtilMethods.isSet(oauth2Provider)) {
                        request.setAttribute(OAUTH_PROVIDER, oauth2Provider);
                    }

                    //Look for the provider to use
                    final OAuth20Service service = this.oauthUtils.getOAuthService(request);
                    DefaultApi20 apiProvider = service.getApi();
                    if (null != apiProvider) {

                        final String providerName = apiProvider.getClass().getSimpleName();
                        final String protectedResourceUrl = getProperty(
                                providerName + "_PROTECTED_RESOURCE_URL");

                        final String firstNameProp = getProperty(providerName + "_FIRST_NAME_PROP");
                        final String lastNameProp = getProperty(providerName + "_LAST_NAME_PROP");

                        
                        HttpClientConfig config = new HttpClientConfig() {
                          
                          @Override
                          public HttpClientConfig createDefaultConfig() {
                            // TODO Auto-generated method stub
                            return null;
                          }
                        };


                        // Send for authorization
                        Logger.info(this.getClass(),
                                String.format("Trying to authenticate with an oauth2"
                                        + "token and for the provider [%s]", providerName));

                        //Now that we have a access token we can retrieve the user info and authenticate it
                        final OAuth2AccessToken accessToken =new OAuth2AccessToken(oauth2Token);
                        user = this.oauthUtils.authenticate(request, response, accessToken, service,
                                protectedResourceUrl, firstNameProp, lastNameProp);

                        userId = user.getUserId();

                        //Generate the token for this user
                        res = generateToken(user, expirationDays, request);
                    } else {
                        //No user no provided
                        throw new NoSuchUserException();
                    }

                } else {
                    //No user no provided
                    throw new NoSuchUserException();
                }
            }

        } catch (NoSuchUserException | UserEmailAddressException | UserPasswordException | AuthException e) {

            res = this.responseUtil.getErrorResponse(request, Response.Status.UNAUTHORIZED,
                    locale, userId, "authentication-failed");
        } catch (RequiredLayoutException e) {

            res = this.responseUtil.getErrorResponse(request, Response.Status.INTERNAL_SERVER_ERROR,
                    locale, userId, "user-without-portlet");
        } catch (UserActiveException e) {

            try {

                res = Response.status(Response.Status.UNAUTHORIZED).entity(new ResponseEntityView
                        (Collections.singletonList(new ErrorEntity("your-account-is-not-active",
                                LanguageUtil.format(locale,
                                        "your-account-is-not-active",
                                        new LanguageWrapper[]{
                                                new LanguageWrapper("<b><i>", userId, "</i></b>")},
                                        false)
                        )))).build();
            } catch (LanguageException e1) {
                // Quiet
            }
        } catch (Exception e) { // this is an unknown error, so we report as a 500.

            SecurityLogger.logInfo(this.getClass(), String.format("An invalid attempt to login as "
                            + "[%s] has been made from IP [%s]", userId,
                    request.getRemoteAddr()));
            res = ExceptionMapperUtil.createResponse(e, Response.Status.INTERNAL_SERVER_ERROR);
        }

        return res;
    } // authentication

    private Response generateToken(final User user, final int expirationDays,
            final HttpServletRequest request)
            throws SystemException, PortalException {

        final int jwtMaxAge = expirationDays > 0 ?
                this.getExpirationDays(expirationDays) :
                Config.getIntProperty(
                        LoginServiceAPI.JSON_WEB_TOKEN_DAYS_MAX_AGE,
                        LoginServiceAPI.JSON_WEB_TOKEN_DAYS_MAX_AGE_DEFAULT);

        this.securityLoggerServiceAPI.logInfo(this.getClass(),
                "A Json Web Token " + user.getUserId() + " has been created from IP: " +
                        HttpRequestDataUtil.getRemoteAddress(request));
        return Response.ok(new ResponseEntityView(map("token",
                createJsonWebToken(user, jwtMaxAge)), EMPTY_MAP)).build();
    }

    private int getExpirationDays(final int expirationDays) {

        final int jsonWebTokenMaxAllowedExpirationDay =
                Config.getIntProperty(LoginServiceAPI.JSON_WEB_TOKEN_MAX_ALLOWED_EXPIRATION_DAYS,
                        JSON_WEB_TOKEN_MAX_ALLOWED_EXPIRATION_DAYS_DEFAULT_VALUE);

        final int maxAllowedExpirationDays =
                (jsonWebTokenMaxAllowedExpirationDay > 0 && (expirationDays
                        > jsonWebTokenMaxAllowedExpirationDay)) ?
                        this.getJsonWebTokenMaxAllowedExpirationDay(
                                jsonWebTokenMaxAllowedExpirationDay, expirationDays) :
                        expirationDays;

        Logger.debug(this, "Json Web Token Expiration days value: " + expirationDays + " days");

        return maxAllowedExpirationDays;
    }

    private int getJsonWebTokenMaxAllowedExpirationDay(
            final int jsonWebTokenMaxAllowedExpirationDay,
            final int expirationDays) {

        Logger.debug(this, "Json Web Token Expiration days pass by the user is: " + expirationDays
                + " days, it exceeds the max allowed expiration day set in the configuration: "
                + jsonWebTokenMaxAllowedExpirationDay +
                ", so the expiration days for this particular token will be overriden to :"
                + jsonWebTokenMaxAllowedExpirationDay);
        return jsonWebTokenMaxAllowedExpirationDay;
    }

    /**
     * Creates Json Web Token
     *
     * @param user {@link User}
     * @param jwtMaxAge {@link Integer}
     * @return String json web token
     */
    private String createJsonWebToken(final User user, final int jwtMaxAge)
            throws PortalException, SystemException {

        return this.jsonWebTokenUtils.createToken(user, jwtMaxAge);
    }

}