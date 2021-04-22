package com.dotcms.osgi.oauth.service;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import com.dotmarketing.util.UtilMethods;
import com.liferay.portal.model.User;

/**
 * @author Jonathan Gamba 8/28/18
 */
public interface DotService {

    /**
     * Custom implementation (extra call) in order to get roles/groups from the authentication
     * server if required, most of the implementations will return groups along with the user data,
     * use this in case an extra call is required.
     */
    Collection<String> getGroups(User user, final Map<String,Object> userJsonResponse);

    default void revokeToken(final String token) {}
    
    default void logout(final String token) {}

    default String getEmail(Map<String, Object> jsonMap) {

        String email= (String) jsonMap.getOrDefault("email", 
                        jsonMap.getOrDefault("email_address", 
                        jsonMap.getOrDefault("emailaddress", 
                        jsonMap.getOrDefault("userPrincipalName", null))));
        
        return UtilMethods.isValidEmail(email) ? email : null;
        

    }
    
    
    default String getFirstName(Map<String, Object> jsonMap) {
        return (String) jsonMap.getOrDefault("first_name", 
                        jsonMap.getOrDefault("firstname",
                        jsonMap.getOrDefault("given_name", 
                        jsonMap.getOrDefault("givenname", 
                        "unknown"))));

    }
    
    default  String getLastName(Map<String, Object> jsonMap) {
        return (String) jsonMap.getOrDefault("last_name", 
                        jsonMap.getOrDefault("lastname",
                        jsonMap.getOrDefault("family_name", 
                        jsonMap.getOrDefault("familyname", 
                        jsonMap.getOrDefault("surname", 
                        "unknown")))));

    }

    default Optional<String> getLogoutClientRedirect(){
        return Optional.empty();
    }
    

}