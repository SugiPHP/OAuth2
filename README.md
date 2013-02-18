# PHP OAuth2.0

### Authorization Server
based on RFC6749 

Supports several grant types:
 - implicit
 - authorization code
 - username/password pair
 - client credentials
 - refresh token

Your custom server implementation can specify which grant types to support
implementing one or more interfaces - ImplicitInterface, AuthCodeInterface etc.
This will eliminate the need to implement something you will not use.

### Resource Server
Uses bearer tokens as desribed in RFC6750

### Client
The client is not very stable for now! But you can use one of many existing OAuth2 clients

### TODO
 - add support for MAC tokens (http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02)
