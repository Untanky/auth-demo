package oauth2

import "errors"

type oauth2Error error

var invalid_request = oauth2Error(errors.New(`The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.`))

var unauthorized_client = oauth2Error(errors.New(`The client is not authorized to request an authorization code using this method.`))

var access_denied = oauth2Error(errors.New(`The resource owner or authorization server denied the request.`))

var unsupported_response_type = oauth2Error(errors.New(`The authorization server does not support obtaining an authorization code using this method.`))

var invalid_scope = oauth2Error(errors.New(`The requested scope is invalid, unknown, or malformed.`))

var server_error = oauth2Error(errors.New(`The authorization server encountered an unexpected condition that prevented it from fulfilling the request.`))

var temporarily_unavailable = oauth2Error(errors.New("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."))

type ErrorResponse struct {
	// REQUIRED. A single ASCII error code.
	Error oauth2Error `json:"error form:"error"`
	// OPTIONAL. Human-readable ASCII text providing
	// additional information, used to assist the client developer in
	// understanding the error that occurred.
	ErrorDescription string `json:"error_description;omitempty" form:"error_description;omitempty"`
	// OPTIONAL. A URI identifying a human-readable web page with
	// information about the error, used to provide the client
	// developer with additional information about the error.
	ErrorURI string `json:"error_uri;omitempty" form:"error_uri;omitempty"`
	// REQUIRED if the "state" parameter was present in the client authorization request.
	State string `json:"state;omitempty" form:"state'omitempty"`
}
