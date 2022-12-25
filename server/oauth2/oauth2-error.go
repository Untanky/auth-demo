package oauth2

import "net/http"

type OAuth2Error struct {
	// REQUIRED. A single ASCII error code.
	ErrorType string `json:"error" form:"error"`
	// OPTIONAL. Human-readable ASCII text providing
	// additional information, used to assist the client developer in
	// understanding the error that occurred.
	ErrorDescription string `json:"error_description;omitempty" form:"error_description;omitempty"`
	// OPTIONAL. A URI identifying a human-readable web page with
	// information about the error, used to provide the client
	// developer with additional information about the error.
	ErrorURI string `json:"error_uri;omitempty" form:"error_uri;omitempty"`
	// The status code associated with the error
	StatusCode int `json:"status"`
}

func (err *OAuth2Error) Error() string {
	return err.ErrorDescription
}

var InvalidRequest = OAuth2Error{
	ErrorType:        "invalid_request",
	ErrorDescription: `The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.`,
	StatusCode:       http.StatusBadRequest,
}

var UnauthorizedClient = OAuth2Error{
	ErrorType:        "unauthorized_client",
	ErrorDescription: `The client is not authorized to perform this request.`,
	StatusCode:       http.StatusForbidden,
}

var AccessDenied = OAuth2Error{
	ErrorType:        "access_denied",
	ErrorDescription: `The resource owner or authorization server denied the request.`,
	StatusCode:       http.StatusConflict,
}

var UnsupportedResponseType = OAuth2Error{
	ErrorType:        "unsupported_response_type",
	ErrorDescription: `The authorization server does not support obtaining an authorization code using this method.`,
	StatusCode:       http.StatusBadRequest,
}

var InvalidScope = OAuth2Error{
	ErrorType:        "invalid_scope",
	ErrorDescription: `The requested scope is invalid, unknown, or malformed.`,
	StatusCode:       http.StatusBadRequest,
}

var ServerError = OAuth2Error{
	ErrorType:        "server_error",
	ErrorDescription: `The authorization server encountered an unexpected condition that prevented it from fulfilling the request.`,
	StatusCode:       http.StatusInternalServerError,
}

var InvalidClient = OAuth2Error{
	ErrorType:        "invalid_client",
	ErrorDescription: `Client authentication failed (e.g., unknown client, client authentication included, or authentication method).`,
	StatusCode:       http.StatusUnauthorized,
}

var InvalidGrant = OAuth2Error{
	ErrorType:        "invalid_grant",
	ErrorDescription: `The provided authorization grant or refresh token is invalid, expired, revoked, does not match the URI used in the authorization request, or was issued to another client.`,
	StatusCode:       http.StatusForbidden,
}

var UnsupportedGrantType = OAuth2Error{
	ErrorType:        "unsupported_grant_type",
	ErrorDescription: `The authorization grant type is not supported by the authorization server.`,
	StatusCode:       http.StatusForbidden,
}

var TemporarilyUnavailable = OAuth2Error{
	ErrorType:        "temporarily_unavailable",
	ErrorDescription: "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
	StatusCode:       http.StatusServiceUnavailable,
}

type ErrorResponse struct {
	OAuth2Error
	// REQUIRED if the "state" parameter was present in the client authorization request.
	State string `json:"state;omitempty" form:"state'omitempty"`
}
