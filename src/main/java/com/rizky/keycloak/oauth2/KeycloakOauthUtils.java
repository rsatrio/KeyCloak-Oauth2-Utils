package com.rizky.keycloak.oauth2;

import java.security.interfaces.RSAPublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.gson.Gson;
import com.rizky.keycloak.oauth2.CreateUserKeycloak.UserCred;

import io.fusionauth.jwt.Verifier;
import io.fusionauth.jwt.domain.JWT;
import io.fusionauth.jwt.rsa.RSAVerifier;
import kong.unirest.Unirest;


public class KeycloakOauthUtils {

    static Logger logKcloak=LoggerFactory.getLogger(KeycloakOauthUtils.class);

    public static boolean logoutKeyCloak(String refreshToken,String clientId,
            String clientSecret,String urlLogout)  {

        try {
            String resp=Unirest.post(urlLogout.trim())
                    .field("client_id",clientId)
                    .field("client_secret",clientSecret)
                    .field("refresh_token",refreshToken)
                    .asString().getBody();

            if(resp.contains("error"))  {
                logKcloak.error("Failed to logout from keycloak");
                return false;
            }
            return true;
        }
        catch(Exception e)  {
            logKcloak.error("Failed to logout from keycloak:",e);
            return false;
        }
    }

    public static OAuth2AccessToken loginKeyCloak(String clientId,
            String clientSecret,String username,String password,
            RSAPublicKey pubKey,
            String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl
            )   {

        try {
            OAuth20Service serviceKcloak=new ServiceBuilder(clientId)
                    .apiSecret(clientSecret).build(KeycloakAPI.instance(
                            accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl));

            OAuth2AccessToken tokenOauth2=serviceKcloak.getAccessTokenPasswordGrant(username, password);

            Verifier verify1=RSAVerifier.newVerifier(pubKey);
            JWT jwt1=JWT.getDecoder().decode(tokenOauth2.getAccessToken(), verify1);

            return tokenOauth2;

        }
        catch(Exception e)  {
            logKcloak.error("JWT Logon Failed",e);
            return null;
        }
    }

    public static boolean resetPassword(String adminUser,String adminSecret,
            String urlReset,String urlUsers,
            String newPassword,String email,
            String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl,
            String logoutUrl)   {

        OAuth2AccessToken token1=null;
        try {

            KeycloakServices kcloakService=(KeycloakServices) new ServiceBuilder("admin-cli").
                    build(KeycloakAdminAPI.instance(
                            accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl));
            token1=kcloakService.getAccessTokenPasswordGrant(adminUser, adminSecret);

            //Get UserId from KeyCloak
            String resp=Unirest.get(urlUsers.trim())
                    .header("Authorization", "Bearer "+token1.getAccessToken())
                    .queryString("email", email)
                    .queryString("exact", "true")
                    .asString().getBody();

            CreateUserKeycloak[] userResp=new Gson().fromJson(resp, CreateUserKeycloak[].class);

            //Set new Password for user in KeyCloak
            UserCred credential=new CreateUserKeycloak().new  UserCred();
            credential.setType("password");
            credential.setValue(newPassword);
            credential.setTemporary(false);

            //Reset Password
            String resetResp=Unirest.put(urlReset.trim())
                    .routeParam("id", userResp[0].getId())
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer "+token1.getAccessToken())
                    .body(credential)
                    .asString().getBody();
            if(resetResp!=null && resetResp.contains("error")) {
                logKcloak.error("Error reset password in keycloak for userId:{}",userResp[0].getId());
                return false;
            }
            else    {
                logKcloak.info("Successfully reset password in keycloak for userId:{}",userResp[0].getId());
                return true;
            }

        }
        catch(Exception e)  {
            logKcloak.error("Error reset password in keycloak for email:{}",email,e);
            return false;
        }
        finally {
            if(token1!=null)    {
                logoutKeyCloak(token1.getRefreshToken(), "admin-cli",
                        "", logoutUrl);
            }
        }
    }

    public static String getKeyCloakUserId(String email,String url,
            String adminUser,String adminSecret,OAuth2AccessToken token,
            String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl,
            String logoutUrl)    {
        OAuth2AccessToken token1=null;
        boolean logout=false;
        try {
            if(token==null) {
                KeycloakServices serviceKeycloak=(KeycloakServices) new ServiceBuilder("admin-cli").
                        build(KeycloakAdminAPI.instance
                                (accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl));
                token1=serviceKeycloak.getAccessTokenPasswordGrant(adminUser, adminSecret);
                logout=true;
            }
            else   {
                token1=token;
            }

            //Get UserId by Email
            String resp=Unirest.get(url.trim())
                    .header("Authorization", "Bearer "+token1.getAccessToken())
                    .queryString("email", email)
                    .queryString("exact", "true")
                    .asString().getBody();

            CreateUserKeycloak[] userResp=new Gson().fromJson(resp, CreateUserKeycloak[].class);

            return userResp[0].getId();
        }
        catch(Exception e)  {
            logKcloak.error("Failed to get userId from keycloak for email:{}",email,e);
            return null;
        }
        finally {
            if(token1!=null && logout)    {
                logoutKeyCloak(token1.getRefreshToken(), "admin-cli",
                        "", logoutUrl);
            }
        }
    }

    public static boolean createNewUser(String adminUser,
            String adminSecret,CreateUserKeycloak userData,String url,
            String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl,
            String logoutUrl)    {
        OAuth2AccessToken token1=null;

        try {
            KeycloakServices serviceKeycloak=(KeycloakServices) new ServiceBuilder("admin-cli").
                    build(KeycloakAdminAPI.instance(
                            accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl));
            token1=serviceKeycloak.getAccessTokenPasswordGrant(adminUser, adminSecret);

            String resp=Unirest.post(url.trim())
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer "+token1.getAccessToken())
                    .body(userData).asString().getBody();

            if(resp!=null && resp.contains("error"))    {
                logKcloak.error("Failed to create new user with email:{}",userData.getEmail());
                return false;
            }
            else    {
                logKcloak.info("Successfully create new user in keycloak with email {}",userData.getEmail());
                return true;
            }

        }
        catch(Exception e)  {
            logKcloak.error("Failed to create new user with email:{}",userData.getEmail(),e);
            return false;
        }
        finally {
            if(token1!=null)    {
                logoutKeyCloak(token1.getRefreshToken(), "admin-cli",
                        "", logoutUrl);
            }
        }
    }

    public static boolean enableUser(String adminUser,
            String adminSecret,String url,String urlUserId,
            String email,
            String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl,
            String logoutUrl)  {
        OAuth2AccessToken tokenOauth2=null;

        try {
            KeycloakServices serviceKeycloak=(KeycloakServices) new ServiceBuilder("admin-cli").
                    build(KeycloakAdminAPI.instance(
                            accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl));
            tokenOauth2=serviceKeycloak.getAccessTokenPasswordGrant(adminUser, adminSecret);

            //Get User Id from KeyCloak
            String userId=getKeyCloakUserId(email,urlUserId , adminUser, adminSecret,tokenOauth2
                    ,accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl,logoutUrl);

            CreateUserKeycloak userData=new CreateUserKeycloak();
            userData.setEnabled(true);
            String resp=Unirest.put(url.trim())
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer "+tokenOauth2.getAccessToken())
                    .routeParam("id", userId)
                    .body(userData).asString().getBody();

            if(resp!=null && resp.contains("error"))    {
                logKcloak.error("Failed to enabled user with email {}",email);
                return false;
            }
            else    {
                logKcloak.info("Successfully enabled user in Keycloak with email {}",email);
                return true;
            }

        }
        catch(Exception e)  {
            logKcloak.error("Failed to enabled user with email {}",email,e);
            return false;
        }
        finally {
            if(tokenOauth2!=null)    {
                logoutKeyCloak(tokenOauth2.getRefreshToken(), "admin-cli",
                        "", logoutUrl);
            }

        }
    }

    public static boolean changePassword(String adminUser,String adminSecret,
            String urlReset,String urlUsers,String urlLogout,
            String newPassword,String email,String oldPassword,
            String clientId,String clientSecret,
            RSAPublicKey pubKey,
            String accessTokenUrl,
            String authBaseUrl,
            String refreshTokenUrl,
            String revokeTokenUrl,
            String logoutUrl) {
        try {
            OAuth2AccessToken token=loginKeyCloak(clientId, clientSecret, email, oldPassword, pubKey,
                    accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl);

            if(token!=null) {
                logoutKeyCloak(token.getRefreshToken(), clientId, clientSecret, urlLogout);
                return resetPassword(adminUser, adminSecret, urlReset, urlUsers, newPassword, email,
                        accessTokenUrl,authBaseUrl,refreshTokenUrl,revokeTokenUrl,logoutUrl);
            }
            else    {
                logKcloak.error("Failed to changed password user with email {}",email);
                return false;
            }
        }
        catch(Exception e)  {
            logKcloak.error("Failed to changed password user with email {}",email,e);
            return false;
        }
    }

}
