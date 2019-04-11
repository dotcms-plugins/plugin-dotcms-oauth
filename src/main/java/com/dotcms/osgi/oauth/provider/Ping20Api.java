package com.dotcms.osgi.oauth.provider;

import static com.dotcms.osgi.oauth.util.OAuthPropertyBundle.getProperty;

import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import com.dotcms.osgi.oauth.service.DotService;
import com.dotmarketing.util.json.JSONException;
import com.dotmarketing.util.json.JSONObject;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.exceptions.OAuthException;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.liferay.portal.model.User;

/**
 * https://www.pingidentity.com/content/developer/en/resources/oauth-2-0-developers-guide.html
 * https://www.pingidentity.com/content/developer/en/resources/openid-connect-developers-guide/basic-client-profile.html
 * https://docs.pingidentity.com/bundle/pf_sm_pingfederateOauth20Endpoints_pf83/page/concept/oAuth2_0Endpoints.html
 *
 * @author Jonathan Gamba 8/28/18
 */
public class Ping20Api extends DefaultApi20 implements DotProvider {

    private final String state;

    public Ping20Api() {
        this.state = "state_" + new Random().nextInt(999_999);
    }

    @Override
    public String getAccessTokenEndpoint() {
        return String.format("%s/as/token.oauth2", getOrganizationURL());
    }

    @Override
    public String getRevokeTokenEndpoint() {
        return String.format("%s/as/revoke_token.oauth2", getOrganizationURL());
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    
    


    private String getBaseAuthorizationUrl() {
        return String.format("%s/as/authorization.oauth2", getOrganizationURL());
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



    private class PingService extends OAuth20Service implements DotService {

        public PingService(DefaultApi20 api, String apiKey, String apiSecret, String callback, String defaultScope, String responseType,
          String userAgent, HttpClientConfig httpClientConfig, HttpClient httpClient) {
        super(api, apiKey, apiSecret, callback, defaultScope, responseType, userAgent, httpClientConfig, httpClient);
        // TODO Auto-generated constructor stub
      }

        Ping20Api api;

        @Override
        public Collection<String> getGroups(User user, final JSONObject userJsonResponse) {

            Collection<String> groupsCollection = null;
            try {
                if (null != userJsonResponse && userJsonResponse.has("groups")) {

                    final String groups = userJsonResponse.getString("groups");
                    String[] groupsArray = groups.split(",");
                    groupsCollection = Arrays.asList(groupsArray);
                }
            } catch (JSONException e) {
                throw new OAuthException(
                        String.format(
                                "Unable to get groups from the remote user data [%s]",
                                e.getMessage()), e);
            }
            return groupsCollection;
        }


    }

    @Override
    protected String getAuthorizationBaseUrl() {
      // TODO Auto-generated method stub
      return null;
    }

}