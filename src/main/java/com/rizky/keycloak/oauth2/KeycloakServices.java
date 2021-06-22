package com.rizky.keycloak.oauth2;

import java.io.OutputStream;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.oauth.OAuth20Service;

public class KeycloakServices extends OAuth20Service{

    
    //Creating custom services to add CLIENT-ID Parameter in request
    
    public KeycloakServices(DefaultApi20 api, String apiKey, String apiSecret,
            String callback, String defaultScope, String responseType,
            OutputStream debugStream, String userAgent,
            HttpClientConfig httpClientConfig, HttpClient httpClient) {
        super(api, apiKey, apiSecret, callback, defaultScope, responseType,
                debugStream, userAgent, httpClientConfig, httpClient);

    }

    @Override
    protected OAuthRequest createAccessTokenPasswordGrantRequest(
            String username, String password, String scope) {

        OAuthRequest request1=super.createAccessTokenPasswordGrantRequest(username, password, scope);
        request1.addParameter(OAuthConstants.CLIENT_ID, "admin-cli");

        return request1;
    }

}
