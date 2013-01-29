=== PHP OAuth2.0 authorization server ===
based on RFC6749

Will support four grant types:
 - implicit
 - authorization code
 - username/password pair (not ready)
 - client credentials (not ready)

Refresh tokens support as well.

Your custom server implementation can specify which grant types to support
implementing one or more interfaces - IOAuth2Implicit, IOAuth2Codes etc.
This will eliminate the need to implement something you will not use.

