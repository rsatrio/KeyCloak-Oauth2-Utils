package com.rizky.keycloak.oauth2;

import java.util.HashMap;
import java.util.List;

public class CreateUserKeycloak {

    String username,lastName,firstName,email,id;
    boolean enabled=false;
    
    HashMap<String, String[]> attributes;
    List<UserCred> credentials;
    
    
        
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

        
    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }



    public HashMap<String, String[]> getAttributes() {
        return attributes;
    }

    public void setAttributes(HashMap<String, String[]> attributes) {
        this.attributes = attributes;
    }

    public List<UserCred> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<UserCred> credentials) {
        this.credentials = credentials;
    }



    public class UserAttrib {
        String role;

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
        
        
    }
    
    public class UserCred   {
        String type,value;
        boolean temporary;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public boolean isTemporary() {
            return temporary;
        }

        public void setTemporary(boolean temporary) {
            this.temporary = temporary;
        }

      
        
        
    }
}
