package com.dotcms.osgi.oauth.app.velocity;

public enum DotVelocitySecretAppKeys {
        TITLE("title")
        ;


       final public String key;

       DotVelocitySecretAppKeys(String key){
            this.key=key;
        }
        
    
       public final static String APP_KEY = "dotVelocitySecretApp";
       
       public final static String APP_YAML_NAME = APP_KEY + ".yml";
       
       
       
}
