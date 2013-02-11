# PHP OAuth2.0

## PHP OAuth2.0 Authorization Server
based on RFC6749 

Supports several grant types:
 - implicit
 - authorization code
 - username/password pair
 - client credentials
 - refresh token

Your custom server implementation can specify which grant types to support
implementing one or more interfaces - IOAuth2Implicit, IOAuth2Codes etc.
This will eliminate the need to implement something you will not use.

## PHP OAuth2.0 Resource Server
Uses bearer tokens as desribed in RFC6750

## PHP OAuth2.0 Client
The client is very unstable for now! But you can use one of many existing OAuth2 clients

## TODO
 - add support for MAC tokens (http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02)
