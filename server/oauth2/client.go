package oauth2

type clientType string

type authenticationMethod string

const (
	// Clients capable of maintaining the confidentiality of their
	// credentials (e.g., client implemented on a secure server with
	// restricted access to the client credentials), or capable of secure
	// client authentication using other means.
	//
	// Defined in https://www.rfc-editor.org/rfc/rfc6749#section-2.1
	ConfidentialClient clientType = "confidential"

	//Clients incapable of maintaining the confidentiality of their
	//credentials (e.g., clients executing on the device used by the
	//resource owner, such as an installed native application or a web
	//browser-based application), and incapable of secure client
	//authentication via any other means.
	//
	//Defined in https://www.rfc-editor.org/rfc/rfc6749#section-2.1
	PublicClient clientType = "public"

	// Clients must authenticate using a secret using POST
	ClientSecretPost authenticationMethod = "client_secret_post"

	// Clients must authenticate using a secret using `Authenication` header and `Basic` schema.
	ClientSecretBasic authenticationMethod = "client_secret_basic"

	// Not implemented
	ClientSecretJWT authenticationMethod = "client_secret_jwt"

	// Not implemented
	ClientPrivateKey authenticationMethod = "private_key_jwt"

	// Client must not authenticate itself
	ClientAuthenticationNone authenticationMethod = "none"
)

type clientID string

// TODO: move to different file
type responseTypes string
type grantTypes string

// Response when a new client registers.
//
// Defined https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
type ClientMetadata struct {
	// OPTIONAL. Name of the Client to be presented to the End-User.
	Name string `json:"client_name;omitempty"`
	// OPTIONAL. Requested Client Authentication method for the Token Endpoint.
	AuthenticationMethod authenticationMethod `json:"token_endpoint_auth_method;omitempty"`
	// REQUIRED. Array of Redirection URI values used by the Client.
	RedirectionURIs []string `json:"redirection_uris"`
	// OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type
	// values that the Client is declaring that it will restrict itself to using.
	// If omitted, the default is that the Client will use only the `code` Response Type.
	ResponseTypes []responseTypes `json:"response_types;omitempty"`
	// OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the.
	// Client is declaring that it will restrict itself to using.
	GrantTypes []grantTypes `json:"grant_types;omitempty"`
}

// Response when a new client registers.
//
// Defined https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
type ClientRegistrationResponse struct {
	ClientMetadata
	// REQUIRED. Unique Client Identifier. It MUST NOT be currently valid for any other registered Client.
	ID clientID `json:"client_id"`
	// OPTIONAL. Client Secret. The same Client Secret value MUST NOT be assigned to multiple Clients.
	Secret []byte `json:"client_secret;omitempty"`
	// OPTIONAL. Registration Access Token that can be used at the Client Configuration Endpoint to perform subsequent operations upon the Client registration.
	AccessToken string `json:"registration_access_token;omitempty"`
	// OPTIONAL. Location of the Client Configuration Endpoint where the Registration Access Token can be used to perform subsequent operations upon the resulting Client registration.
	RegistrationURI string `json:"registration_client_uri;omitempty"`
	// OPTIONAL. Time at which the Client Identifier was issued.
	IssuedAt int64 `json:"client_id_issued_at;omitempty"`
	// REQUIRED if client_secret is issued. Time at which the client_secret will expire or 0 if it will not expire.
	SecretExpiresAt int64 `json:"client_secret_expires_at;omitempty"`
}
