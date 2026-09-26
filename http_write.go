package oauth2

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// writeJSON sends a JSON body with the no-store headers RFC 6749 section 5.1
// requires on every token endpoint response.
//
// Caching a token response is how a token ends up in a shared proxy or a
// browser's back button, so the headers are not optional politeness.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("oauth2: could not write the response", "error", err)
	}
}

// errorBody is the shape RFC 6749 section 5.2 requires.
//
// The framework's own error helpers render {"message": ...}, which is wrong
// here: a client library parses the "error" member and branches on its value,
// so a differently shaped body reads as an unknown failure rather than as the
// specific one it is.
type errorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// writeError renders a protocol error.
//
// The cause is logged and never sent: the description is written for an
// integrator, while an internal failure might name a table or a column.
func writeError(w http.ResponseWriter, err error) {
	protocolErr := asProtocolError(err)

	if cause := protocolErr.Unwrap(); cause != nil {
		slog.Error("oauth2: request failed", "code", protocolErr.Code, "error", cause)
	}

	status := protocolErr.Status
	if status == 0 {
		status = statusFor(protocolErr.Code)
	}

	// RFC 6749 section 5.2: invalid_client answered with 401 must carry a
	// challenge, or a client cannot tell authentication failed from the
	// request being malformed.
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
	}

	writeJSON(w, status, errorBody{
		Error:            protocolErr.Code,
		ErrorDescription: protocolErr.Description,
		ErrorURI:         protocolErr.URI,
	})
}

// asProtocolError narrows any error to one the protocol can express.
//
// An unrecognised error becomes server_error with no description, because an
// internal message is not something to hand a client.
func asProtocolError(err error) *Error {
	var protocolErr *Error
	if errors.As(err, &protocolErr) {
		return protocolErr
	}
	return &Error{Code: ErrCodeServerError, cause: err}
}

func statusFor(code string) int {
	switch code {
	case ErrCodeInvalidClient:
		return http.StatusUnauthorized
	case ErrCodeServerError:
		return http.StatusInternalServerError
	case ErrCodeTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	case ErrCodeAccessDenied:
		return http.StatusForbidden
	default:
		// Everything else in RFC 6749 section 5.2 is a 400, including
		// authorization_pending and slow_down, which RFC 8628 section 3.5
		// says are ordinary token error responses rather than a separate
		// status.
		return http.StatusBadRequest
	}
}

// methodNotAllowed answers with the Allow header a correct 405 needs.
//
// Each endpoint registers one pattern with no method verb and dispatches
// inside, rather than registering a method-qualified pattern: an unmatched
// method on the latter falls through to the application's catch-all and
// surfaces as a 404, which tells a client the endpoint does not exist.
func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, &Error{
		Code:        ErrCodeInvalidRequest,
		Description: "this endpoint accepts " + strings.Join(allowed, " and "),
		Status:      http.StatusMethodNotAllowed,
	})
}
