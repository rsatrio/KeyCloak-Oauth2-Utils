package com.rizky.keycloak.oauth2;

import io.fusionauth.jwks.domain.JSONWebKey;

import java.util.List;

public class JsonWebKeyPojo {

    List<JSONWebKey> keys;

    public List<JSONWebKey> getKeys() {
        return keys;
    }

    public void setKeys(List<JSONWebKey> keys) {
        this.keys = keys;
    }
    
    
}
