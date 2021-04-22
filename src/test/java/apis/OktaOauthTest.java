package apis;

import java.io.IOException;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import com.dotcms.osgi.oauth.provider.Okta20Api;
import com.dotcms.osgi.oauth.util.JsonUtil;
import com.dotcms.osgi.oauth.util.OAuthPropertyBundle;

public class OktaOauthTest {





    public static void main(String[] args) throws IOException, InterruptedException, ExecutionException {
        // Replace these with your client id and secret

        final String PROTECTED_RESOURCE_URL = OAuthPropertyBundle.getProperty("Okta20Api_PROTECTED_RESOURCE_URL");
        final String clientId = OAuthPropertyBundle.getProperty("Okta20Api_API_KEY");
        final String clientSecret = OAuthPropertyBundle.getProperty("Okta20Api_API_SECRET");
        
        final DefaultApi20 apiProvider = new Okta20Api();


        final OAuthService service = new ServiceBuilder()
                        .apiKey(clientId)
                        .apiSecret(clientSecret)
                        .scope("openid email profile groups")
                        .callback("https://localhost.dotcms.com/api/v1/oauth2/callback")
                        .provider(apiProvider).build();

        final Scanner in = new Scanner(System.in, "UTF-8");
        System.out.println("=== OktaOauth's OAuth Workflow ===");
        System.out.println();


        // Obtain the Authorization URL
        System.out.println("Fetching the Authorization URL...");
        final String authorizationUrl = service.getAuthorizationUrl(null);
        System.out.println("Got the Authorization URL!");
        System.out.println("Now go and authorize ScribeJava here:");
        System.out.println(authorizationUrl);
        System.out.println("And paste the authorization code here");
        System.out.print(">>");
        final String code = in.nextLine();
        System.out.println();
        // Trade the Request Token and Verfier for the Access Token
        System.out.println("Trading the Request Token for an Access Token...");
        final Verifier verifier = new Verifier(code);
        final Token accessToken = service.getAccessToken(null, verifier);
        System.out.println("Got the Access Token!");
        System.out.println("(The raw response looks like this: " + accessToken.getRawResponse() + "')");
        System.out.println();
        // Now let's go and ask for a protected resource!
        System.out.println("Now we're going to access a protected resource...");
        
        
        final OAuthRequest oauthRequest = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
        service.signRequest(accessToken, oauthRequest);
        final Response protectedCallResponse = oauthRequest.send();
        
        if (!protectedCallResponse.isSuccessful()) {
            throw new OAuthException(String.format("Unable to connect to end point [%s] [%s]", PROTECTED_RESOURCE_URL,
                            protectedCallResponse.getMessage()));
        }
        System.out.println("Got it! Lets see what we found...");
        System.out.println(protectedCallResponse.getCode());
        System.out.println(protectedCallResponse.getBody());        
        


        final Map<String, Object> userJsonResponse =
                        (Map<String, Object>) new JsonUtil().generate(protectedCallResponse.getBody());


        System.out.println("key = value");
        System.out.println("--------------------");
        userJsonResponse.keySet().forEach(k->{
            System.out.println(k + " = " + userJsonResponse.get(k));
        });

        System.out.println();
        System.out.println("Thats it man! Go and build something awesome  :)");
    }
}
