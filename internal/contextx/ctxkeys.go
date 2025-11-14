package contextx

// Keys used for storing/retrieving user information in the context of a request before authentication.
type NakamaApiKey struct{}

// Keys used for storing/retrieving user information in the context of a request after authentication.
type UserIDKey struct{}
type UsernameKey struct{}
type VarsKey struct{}
type ExpiryKey struct{}
type TokenIDKey struct{}
type TokenIssuedAtKey struct{}
type TenantIDKey struct{}
type FullMethodKey struct{}

// Keys used for storing/retrieving user information in the context of a request after authentication.
// type ctxUserIDKey = UserIDKey
// type ctxUsernameKey = UsernameKey
// type ctxVarsKey = VarsKey
// type ctxExpiryKey = ExpiryKey
// type ctxTokenIDKey = TokenIDKey
// type ctxTokenIssuedAtKey = TokenIssuedAtKey
// type ctxTenantIDKey = TenantIDKey
