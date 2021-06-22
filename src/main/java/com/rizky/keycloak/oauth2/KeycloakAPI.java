package com.rizky.keycloak.oauth2;

import com.github.scribejava.core.builder.api.DefaultApi20;


public class KeycloakAPI extends DefaultApi20{

    private static KeycloakAPI cloakApi;
    private String accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl;

    private KeycloakAPI(String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl) {
        this.accessTokenUrl=accessTokenUrl;
        this.authBaseUrl=authBaseUrl;
        this.refreshTokenUrl=refreshTokenUrl;
        this.revokeTokenUrl=revokeTokenUrl;

    }


    public static KeycloakAPI instance(String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl) {
        if(cloakApi==null)  {
            cloakApi=new KeycloakAPI(accessTokenUrl, authBaseUrl, refreshTokenUrl, revokeTokenUrl);
        }
        return cloakApi;
    }
    
    @Override
    public String getAccessTokenEndpoint() {

        return accessTokenUrl;
    }


    @Override
    protected String getAuthorizationBaseUrl() {
        return authBaseUrl;
    }

    @Override
    public String getRefreshTokenEndpoint() {
        return refreshTokenUrl;
    }

    @Override
    public String getRevokeTokenEndpoint() {
        return revokeTokenUrl;
    }

}
