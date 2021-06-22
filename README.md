
# KeyCloak OAuth2 Utils 

A simple utility to wrap OAuth2 usage in KeyCloak.  Build with Java 8, and using these additional libraries:

- ScribeJava

- FusionAuth-JWT

- Unirest

- Logback

  

## Features

Features included are helper to interfacing with keycloak for these functions:

- Login with OAuth2 
- Logout with OAuth2
- Reset Password based on user's email
- Change Password based on user's email
- Create new user
- Enabled user
- Get Keycloak's UserId based on email

## Build
Use mvn package to build the module into jar file
```shell
mvn clean package
```


## Usage
- Add the jar library into your project. Don't forget to also add these dependencies into your project:
1. Scribejava
2. Fusionauth-jwt
3. Unirest
4. Logback


## Feedback
For feedback and feature request, please raise issues in the issue section of the repository. Enjoy!!.