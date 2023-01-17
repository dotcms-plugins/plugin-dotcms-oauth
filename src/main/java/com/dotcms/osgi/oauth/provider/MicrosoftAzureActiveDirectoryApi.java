package com.dotcms.osgi.oauth.provider;


import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.osgi.oauth.util.JsonUtil;
import com.dotmarketing.exception.DotRuntimeException;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.UUIDGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.liferay.portal.model.User;
import io.vavr.control.Try;

/**
 * Microsoft Azure Active Directory Api
 *
 * @see <a href=
 *      "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code">
 *      Understand the OAuth 2.0 authorization code flow in Azure AD | Microsoft Docs</a>
 * @see <a href=
 *      "https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-devquickstarts-webapp-java">
 *      Azure AD Java web app Getting Started | Microsoft Docs</a>
 * @see <a href=
 *      "https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/signed-in-user-operations">
 *      Azure AD Graph API Operations on the Signed-in User</a>
 * @see <a href="https://portal.azure.com">https://portal.azure.com</a>
 */
public class MicrosoftAzureActiveDirectoryApi extends DefaultApi20 implements DotProvider {


    public static final String MSFT_ENDPOINT = "https://login.microsoftonline.com";
    private static final String MSFT_AUTHORIZATION = MSFT_ENDPOINT + "/common/oauth2/v2.0/authorize";
    private static final String MSFT_TOKEN = MSFT_ENDPOINT + "/common/oauth2/v2.0/token";
    private static final String MSFT_LOGOUT = MSFT_ENDPOINT + "/common/oauth2/v2.0/logout";
    
    public static final String MSFT_PROTECTED_RESOURCE="https://graph.microsoft.com/v1.0/me";
    
    private static final String MSFT_GROUP_RESOURCE="https://graph.microsoft.com/v1.0/me/memberOf";
    
    private final String state = UUIDGenerator.generateUuid();

    private static class InstanceHolder {

        private static final MicrosoftAzureActiveDirectoryApi INSTANCE = new MicrosoftAzureActiveDirectoryApi();
    }

    public static MicrosoftAzureActiveDirectoryApi instance() {
        return InstanceHolder.INSTANCE;
    }

    @Override
    public String getAccessTokenEndpoint() {

        return MSFT_TOKEN;
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new AccessTokenExtractor() {

            public Token extract(String response) {
                Preconditions.checkEmptyString(response,
                                "Response body is incorrect. Can't extract a token from an empty string");


                HashMap<String,String> map = Try.of(()->new ObjectMapper().readValue(response, HashMap.class)).getOrElseThrow(e->new DotRuntimeException("bad response: "+response, e));
                if(map.containsKey("error")){
                    throw new  OAuthException("bad response: "+response);
                }

                
                return new Token(map.get("access_token"), "", response);
                

            }
        };

    }


    @Override
    public String getAuthorizationUrl(OAuthConfig config) {


        return String.format(MSFT_AUTHORIZATION

                        + "?client_id=%s" 
                        + "&response_type=%s" 
                        + "&scope=%s" 
                        + "&redirect_uri=%s" 
                        + "&state=%s",
                        OAuthEncoder.encode(config.getApiKey()), 
                        OAuthEncoder.encode(getResponseType()),
                        config.getScope(), 
                        OAuthEncoder.encode(config.getCallback()), 
                        state);


    }

    private String getResponseType() {
        return "code";
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }


    @Override
    public MicrosoftAzureActiveDirectoryService createService(OAuthConfig config) {
        return new MicrosoftAzureActiveDirectoryService(this, config);
    }


    public class MicrosoftAzureActiveDirectoryService extends OAuth20ServiceImpl  implements DotService {
        private DefaultApi20 api;
        private OAuthConfig config;

        public MicrosoftAzureActiveDirectoryService(DefaultApi20 api, OAuthConfig config) {
            super(api, config);
            this.api = api;
            this.config = config;
        }


        @Override
        public Token getAccessToken(Token requestToken, Verifier verifier) {
            OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());


            request.addHeader("Content-Type", "application/x-www-form-urlencoded");
            request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
            request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
            request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
            request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
            request.addBodyParameter("grant_type", "authorization_code");
            


            Response response = request.send();
            return api.getAccessTokenExtractor().extract(response.getBody());
        }


        @Override
        public void signRequest(Token accessToken, OAuthRequest request) {
            request.addHeader("Authorization", "Bearer " + accessToken.getToken());
            request.addHeader("Accept", "*/*");
        }

 
        
        
        
        /**
         * Custom implementation (extra call) in order to get roles/groups from the Okta server as the
         * request that returns the user data does not have the user groups.
         */
        @Override
        public Collection<String> getGroups(User user, final Map<String, Object> userJsonResponse) {


            final String groupPrefix = config().getGroupPrefix();
            final Token apiToken = (Token) userJsonResponse.get("access_token");
            final String groupsResourceUrl = MSFT_GROUP_RESOURCE;

            final OAuthRequest oauthGroupsRequest = new OAuthRequest(Verb.GET, groupsResourceUrl);
            this.signRequest(apiToken,oauthGroupsRequest);

            final Collection<String> groups = new ArrayList<>();
            Response groupsCallResponse = null;
            try {
                groupsCallResponse = oauthGroupsRequest.send();
                if (!groupsCallResponse.isSuccessful()) {

                    Logger.error(this.getClass().getName(), String.format("Unable to connect to end point [%s] [%s]",
                                    groupsResourceUrl, groupsCallResponse.getMessage()));
                    return groups;
                }


                // Parse the response in order to get the user data
                final List<Map<String, Object>> groupsJsonResponse =
                                (List<Map<String, Object>>) new JsonUtil().generate(groupsCallResponse.getBody());

                groupsJsonResponse.stream().filter(m -> m.containsKey("profile")).forEach(m -> {
                    final Map<String, Object> profile = (Map<String, Object>) m.get("profile");
                    final String group = (String) profile.get("name");
                    if (null != group) {

                        // Verify if we need to filter by prefix
                        if (null != groupPrefix && !groupPrefix.isEmpty()) {
                            if (group.startsWith(groupPrefix)) {
                                groups.add(group);
                            }
                        } else {
                            groups.add(group);
                        }
                    }
                });


            } catch (Exception e) {
                Logger.warn(Okta20Api.class.getName(), String.format("Unable to get groups in remote authentication server [%s] [%s]",
                                groupsResourceUrl, groupsCallResponse.getMessage()));
            }

            return groups;
        }

        @Override
        public void revokeToken(String token) {

            // Now lets try to invalidate the token

            String callback = config.getCallback();


            final OAuthRequest revokeRequest = new OAuthRequest(Verb.GET, MSFT_LOGOUT);
            revokeRequest.addQuerystringParameter("client_id", config.getApiKey());
            revokeRequest.addQuerystringParameter("post_logout_redirect_uri", callback);

            final Response revokeCallResponse = revokeRequest.send();

            if (!revokeCallResponse.isSuccessful()) {
                Logger.error(this.getClass().getName(), String.format("Unable to revoke access token [%s] [%s] [%s]",
                                MSFT_LOGOUT, token, revokeCallResponse.getMessage()));
            } else {
                Logger.info(this.getClass().getName(), "Successfully revoked access token");
                Logger.debug(this.getClass().getName(), revokeCallResponse.getBody());
            }


        }
        @Override
        public Optional<String> getLogoutClientRedirect(){
            String callback = config.getCallback();


            final OAuthRequest revokeRequest = new OAuthRequest(Verb.GET, MSFT_LOGOUT);
            revokeRequest.addQuerystringParameter("client_id", config.getApiKey());
            revokeRequest.addQuerystringParameter("post_logout_redirect_uri", callback);

            return Optional.ofNullable(revokeRequest.getCompleteUrl());
            
        }
        
        
    }
}
