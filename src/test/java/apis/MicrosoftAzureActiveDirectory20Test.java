package apis;

import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.DefaultApi20;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;
import com.dotcms.osgi.oauth.provider.MicrosoftAzureActiveDirectoryApi;

public class MicrosoftAzureActiveDirectory20Test {


  private MicrosoftAzureActiveDirectory20Test() {}


  public static void main(String[] args) throws IOException, InterruptedException, ExecutionException {

    // Replace these with your client id and secret
    final String clientId = "c20f47d1-f726-4ccc-aa6d-f712d4966e26";
    final String clientSecret = "dYvHYUPPorslpoGPne3mBOj+LfEGcKZS8aV8mnBHjUw=";
    
    final DefaultApi20 apiProvider = new MicrosoftAzureActiveDirectoryApi();
    
    final OAuthService service = new ServiceBuilder()
                    .apiKey(clientId)
                    .apiSecret(clientSecret)
                    .provider(apiProvider)
                    .scope("openid+profile+email")
        .callback("http://localhost:8080/api/v1/oauth2/callback")
        .build();
    
    
    final Scanner in = new Scanner(System.in, "UTF-8");
    System.out.println("=== " +apiProvider.getClass().getSimpleName() + "'s OAuth Workflow ===");
    System.out.println();
    // Obtain the Authorization URL
    System.out.println("Fetching the Authorization URL...");
    final String authorizationUrl = service.getAuthorizationUrl(null);
    System.out.println("Got the Authorization URL!");
    System.out.println("Now go and authorize ScribeJava here:");
    System.out.println();
    System.out.println(authorizationUrl);
    System.out.println();
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
    final OAuthRequest request = new OAuthRequest(Verb.GET, MicrosoftAzureActiveDirectoryApi.MSFT_PROTECTED_RESOURCE);
    service.signRequest(accessToken, request);
    final Response protectedCallResponse = request.send();
    System.out.println("Got it! Lets see what we found...");
    System.out.println();
    System.out.println(protectedCallResponse.getCode());
    System.out.println(protectedCallResponse.getBody());
    System.out.println();
    System.out.println("Thats it man! Go and build something awesome with ScribeJava! :)");

  }
}
