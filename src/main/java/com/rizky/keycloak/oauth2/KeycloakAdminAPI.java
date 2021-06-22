package com.rizky.keycloak.oauth2;

import java.io.OutputStream;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;


public class KeycloakAdminAPI extends DefaultApi20{
    
    private static KeycloakAdminAPI adminApi;
    private String accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl;
    
    private KeycloakAdminAPI(String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl) {
        this.accessTokenUrl=accessTokenUrl;
        this.authBaseUrl=authBaseUrl;
        this.refreshTokenUrl=refreshTokenUrl;
        this.revokeTokenUrl=revokeTokenUrl;
        
    }
   
    public static KeycloakAdminAPI instance(String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl) {
        if(adminApi==null)  {
            adminApi=new KeycloakAdminAPI(accessTokenUrl, authBaseUrl, refreshTokenUrl, revokeTokenUrl);
        }
        return adminApi;
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

    @Override
    public KeycloakServices createService(String apiKey, String apiSecret,
            String callback, String defaultScope, String responseType,
            OutputStream debugStream, String userAgent,
            HttpClientConfig httpClientConfig, HttpClient httpClient) {
        // TODO Auto-generated method stub
        return new KeycloakServices(this,apiKey, apiSecret, callback, defaultScope,
                responseType, debugStream, userAgent, httpClientConfig, httpClient);
    }

}
