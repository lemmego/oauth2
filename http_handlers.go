package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// postForm reads the request body as form parameters.
//
// It returns r.PostForm rather than r.Form deliberately. ParseForm merges the
// URL query into r.Form, so a server reading that would accept client
// credentials and authorization codes in a query string — where they land in
// access logs, proxy logs and browser history.
func postForm(r *http.Request) (url.Values, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errorf(ErrCodeInvalidRequest, "the request body is not valid form data")
	}
	if r.PostForm == nil {
		return url.Values{}, nil
	}
	return r.PostForm, nil
}

// HandleToken serves the token endpoint.
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	body, err := postForm(r)
	if err != nil {
		writeError(w, err)
		return
	}

	response, err := s.Token(r.Context(), r.Header.Get("Authorization"), body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// HandleDeviceCode serves the device authorization endpoint, RFC 8628 §3.1.
func (s *Server) HandleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	body, err := postForm(r)
	if err != nil {
		writeError(w, err)
		return
	}

	client, err := s.AuthenticateClient(r.Context(), r.Header.Get("Authorization"), body)
	if err != nil {
		writeError(w, err)
		return
	}

	response, err := s.AuthorizeDevice(r.Context(), client, body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// HandleRevoke serves RFC 7009 token revocation.
func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	body, err := postForm(r)
	if err != nil {
		writeError(w, err)
		return
	}

	if err := s.Revoke(r.Context(), r.Header.Get("Authorization"), body); err != nil {
		writeError(w, err)
		return
	}
	// RFC 7009 section 2.2: success is 200 with an empty body, including for
	// a token that was already invalid.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// HandleIntrospect serves RFC 7662 token introspection.
func (s *Server) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	body, err := postForm(r)
	if err != nil {
		writeError(w, err)
		return
	}

	response, err := s.Introspect(r.Context(), r.Header.Get("Authorization"), body)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// HandleJWKS serves the public key set.
//
// It is cacheable — the keys change only on rotation — and carries a strong
// ETag over the document, so a rotation invalidates every cache immediately
// rather than leaving clients unable to verify new tokens until a TTL passes.
func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}

	ring := s.keys.Load()
	if ring == nil {
		writeError(w, errorf(ErrCodeServerError, "no signing keys are loaded"))
		return
	}
	document, err := ring.MarshalJWKS()
	if err != nil {
		writeError(w, errorf(ErrCodeServerError, "could not render the key set").WithCause(err))
		return
	}

	sum := sha256.Sum256(document)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "application/jwk-set+json")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(document)
	}
}

// HandleMetadata serves the RFC 8414 discovery document.
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	document, err := json.Marshal(s.Metadata())
	if err != nil {
		writeError(w, errorf(ErrCodeServerError, "could not render the metadata").WithCause(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(document)
	}
}
