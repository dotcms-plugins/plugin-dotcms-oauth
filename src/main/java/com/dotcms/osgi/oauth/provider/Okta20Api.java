package com.dotcms.osgi.oauth.provider;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

import com.dotcms.osgi.oauth.util.OauthUtils;
import com.dotcms.osgi.oauth.service.DotService;
import com.dotcms.rendering.velocity.viewtools.JSONTool;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.json.JSONArray;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.liferay.portal.model.User;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutionException;


/**
 * @author Jonathan Gamba 8/24/18
 */
public class Okta20Api extends DefaultApi20 implements DotProvider {

    private final String state;

    public Okta20Api() {
        this.state = "state_" + new Random().nextInt(999_999);
    }

    /**
     * https://developer.okta.com/blog/2018/04/10/oauth-authorization-code-grant-type
     */
    @Override
    public String getAccessTokenEndpoint() {
        return getBaseAccessTokenEndpoint() + "?grant_type=authorization_code";
    }

    private String getBaseAccessTokenEndpoint() {
        return String.format("%s/oauth2/v1/token", getOrganizationURL());
    }

    @Override
    public String getRevokeTokenEndpoint() {
        return String.format("%s/oauth2/v1/revoke", getOrganizationURL());
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    
    @Override
    protected String getAuthorizationBaseUrl() {
      // TODO Auto-generated method stub
      return null;
    }

  @Override
  public String getAuthorizationUrl(String responseType, String apiKey, String callback, String scope, String state,
      Map<String, String> additionalParams) {

    return getBaseAuthorizationUrl()
        + String.format("" + "?client_id=%s" + "&response_type=%s" + "&scope=%s" + "&redirect_uri=%s" + "&state=%s", apiKey, responseType,
            scope, callback, state);

  }



    private String getBaseAuthorizationUrl() {
        return String.format("%s/oauth2/v1/authorize", getOrganizationURL());
    }

    private String getOrganizationURL() {
        return getProperty(getSimpleName() + "_ORGANIZATION_URL");
    }

    /**
     * response_type is code, indicating that we are using the authorization code grant type.
     */
    private String getResponseType() {
        return "code";
    }

    /**
     * state is an arbitrary alphanumeric string that the authorization server will reproduce when
     * redirecting the user-agent back to the client. This is used to help prevent cross-site
     * request forgery.
     */
    private String getState() {
        return this.state;
    }

    private String getSimpleName() {
        return this.getClass().getSimpleName();
    }



    private class Okta20Service extends OAuth20Service implements DotService {

        public Okta20Service(DefaultApi20 api, String apiKey, String apiSecret, String callback, String defaultScope, String responseType,
          String userAgent, HttpClientConfig httpClientConfig, HttpClient httpClient) {
        super(api, apiKey, apiSecret, callback, defaultScope, responseType, userAgent, httpClientConfig, httpClient);
        // TODO Auto-generated constructor stub
      }

        Okta20Api api;



        /**
         * Custom implementation (extra call) in order to get roles/groups from the Okta server as
         * the request that returns the user data does not have the user groups.
         * @throws IOException 
         * @throws ExecutionException 
         * @throws InterruptedException 
         */
        @Override
        public Collection<String> getGroups(User user, final JSONObject userJsonResponse) throws InterruptedException, ExecutionException, IOException {

            final String providerName = getSimpleName();
            final String groupPrefix = getProperty(providerName + "_GROUP_PREFIX");
            final String organizationURL = getProperty(providerName + "_ORGANIZATION_URL");
            final String apiToken = getProperty(providerName + "_API_TOKEN");
            final String groupsResourceUrl = String
                    .format(getProperty(providerName + "_GROUPS_RESOURCE_URL"),
                            user.getEmailAddress());

            final OAuthRequest oauthGroupsRequest = new OAuthRequest(Verb.GET,
                    organizationURL + groupsResourceUrl);
            oauthGroupsRequest.addHeader("Authorization", "SSWS " + apiToken);
            oauthGroupsRequest.addHeader("Content-Type", "application/json");
            oauthGroupsRequest.addHeader("Accept", "application/json");

            final Response groupsCallResponse = execute(oauthGroupsRequest);
            if (!groupsCallResponse.isSuccessful()) {
                throw new OAuthException(
                        String.format("Unable to connect to end point [%s] [%s]",
                                groupsResourceUrl,
                                groupsCallResponse.getMessage()));
            }

            Collection<String> groups = new ArrayList<>();
            try {
                //Parse the response in order to get the user data
                final JSONArray groupsJsonResponse = (JSONArray) new JSONTool()
                        .generate(groupsCallResponse.getBody());

                for (int i = 0; i < groupsJsonResponse.length(); i++) {
                    JSONObject groupJSONData = groupsJsonResponse.getJSONObject(i);

                    final JSONObject profile = groupJSONData.getJSONObject("profile");
                    if (null != profile) {

                        final String group = profile.getString("name");
                        if (null != group) {

                            //Verify if we need to filter by prefix
                            if (null != groupPrefix && !groupPrefix.isEmpty()) {
                                if (group.startsWith(groupPrefix)) {
                                    groups.add(group);
                                }
                            } else {
                                groups.add(group);
                            }
                        }
                    }
                }
            } catch (JSONException e) {
                throw new OAuthException(
                        String.format(
                                "Unable to get groups in remote authentication server [%s] [%s]",
                                groupsResourceUrl,
                                groupsCallResponse.getMessage()), e);
            }

            return groups;
        }

        @Override
        public void revokeToken(String token) throws InterruptedException, ExecutionException, IOException {

            //Now lets try to invalidate the token
            final String revokeURL = this.api.getRevokeTokenEndpoint();

            if (null != revokeURL && !revokeURL.isEmpty()) {

                final OAuthRequest revokeRequest = new OAuthRequest(Verb.POST, revokeURL);
                revokeRequest.addQuerystringParameter("token", token);
                revokeRequest
                        .addQuerystringParameter("token_type_hint", OAuthConstants.ACCESS_TOKEN);
                revokeRequest.addQuerystringParameter(OAuthConstants.CLIENT_ID, getApiKey());
                revokeRequest.addQuerystringParameter(OAuthConstants.CLIENT_SECRET,
                        getApiSecret());

                final Response revokeCallResponse = execute(revokeRequest);

                if (!revokeCallResponse.isSuccessful()) {
                    Logger.error(this.getClass(),
                            String.format("Unable to revoke access token [%s] [%s] [%s]",
                                    revokeURL,
                                    token,
                                    revokeCallResponse.getMessage()));
                } else {
                    Logger.info(this.getClass(), "Successfully revoked access token");
                    Logger.info(this.getClass(), revokeCallResponse.getBody());
                }

            }
        }

    }

}