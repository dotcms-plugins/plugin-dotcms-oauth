package com.dotcms.osgi.oauth.rest;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.dotcms.rest.api.Validated;

@JsonDeserialize(builder = TokenForm.Builder.class)
public class TokenForm extends Validated {

    private final String oauthToken;
    private final String oauthProvider;
    private final int expirationDays;

    public String getOauthToken() {
        return oauthToken;
    }

    public String getOauthProvider() {
        return oauthProvider;
    }

    public int getExpirationDays() {
        return expirationDays;
    }

    private TokenForm(Builder builder) {
        oauthToken = builder.oauthToken;
        oauthProvider = builder.oauthProvider;
        expirationDays = builder.expirationDays;

        checkValid();
    }

    public static final class Builder {

        @JsonProperty
        private String oauthToken;
        @JsonProperty
        private String oauthProvider;
        @JsonProperty
        private int expirationDays = -1;

        public Builder oauthToken(String oauthToken) {
            this.oauthToken = oauthToken;
            return this;
        }

        public Builder oauthProvider(String oauthProvider) {
            this.oauthProvider = oauthProvider;
            return this;
        }

        public Builder expirationDays(int expirationDays) {
            this.expirationDays = expirationDays;
            return this;
        }

        public TokenForm build() {
            return new TokenForm(this);
        }
    }
}