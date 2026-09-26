package oauth2

import (
	"net/http"
	"strings"
)

// CORS for the endpoints a browser-based client calls directly.
//
// These wrappers are private to this package rather than taken from framework
// middleware, for one reason: an authorization server's CORS behaviour must
// not depend on the application wiring middleware correctly. A protocol
// endpoint that is only correct when a project remembers to configure
// something is a foot-gun.

// corsPublic allows the configured origins. It never sets
// Allow-Credentials: a browser client here is a public client using PKCE, not
// one authenticating with a cookie, and allowing credentials would invite
// exactly the confusion PKCE exists to remove.
func (s *Server) corsPublic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			// The response varies by Origin, so a cache must not serve one
			// origin's response to another.
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsAny allows every origin, for the two documents that are public,
// unauthenticated and cacheable.
func (s *Server) corsAny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.CORSOrigins {
		if allowed == "*" {
			return true
		}
		if strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}
