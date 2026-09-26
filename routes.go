package oauth2

import (
	"net/http"

	"github.com/lemmego/api/app"
)

// AddRoutes mounts the server.
//
// The split is the design, not a workaround: protocol endpoints are raw
// handlers on the mux, human endpoints are typed routes in a group.
//
// A raw handler never enters the framework's Handler pipeline, so CSRF
// verification never sees the token endpoint — which is correct, and correct
// *by construction* rather than by the application remembering to add an
// exclusion pattern. A protocol endpoint whose correctness depends on a
// project editing bootstrap/middleware.go is a foot-gun.
//
// The human endpoints do want the pipeline: they are first-party, cookie
// authenticated and browser driven, so CSRF, the session and the error map
// all apply.
//
// The cost, documented rather than hidden: a raw handler is not counted by
// the framework's in-flight request tracking, so a graceful shutdown will not
// wait for a token exchange. Those take milliseconds.
func (p *Provider) AddRoutes() app.RouteCallback {
	return func(a app.App) {
		// Provide may have returned early, and the callback is registered
		// either way.
		server := p.Server()
		if server == nil {
			return
		}
		cfg := server.cfg
		router := a.Router()

		// One pattern per endpoint with no method verb, dispatching inside.
		// A method-qualified pattern would let a wrong method fall through
		// to the application's catch-all and answer 404, telling a client
		// the endpoint does not exist.
		router.Handle(cfg.RoutePrefix+"/token",
			server.corsPublic(http.HandlerFunc(server.HandleToken)))
		router.Handle(cfg.RoutePrefix+"/device/code",
			server.corsPublic(http.HandlerFunc(server.HandleDeviceCode)))
		router.Handle(cfg.RoutePrefix+"/revoke",
			server.corsPublic(http.HandlerFunc(server.HandleRevoke)))

		// No CORS on introspection: RFC 7662 section 2.1 restricts it to
		// confidential clients, and a browser is not one.
		router.Handle(cfg.RoutePrefix+"/introspect", http.HandlerFunc(server.HandleIntrospect))

		// Both discovery documents live at the site root, as RFC 8414
		// requires, and are unaffected by the route prefix.
		router.Handle("/.well-known/jwks.json",
			server.corsAny(http.HandlerFunc(server.HandleJWKS)))
		router.Handle("/.well-known/oauth-authorization-server",
			server.corsAny(http.HandlerFunc(server.HandleMetadata)))

		// Human-facing routes, in a group so they inherit CSRF and the
		// session. Middleware is registered before the routes because a
		// group snapshots its middleware into each route at registration:
		// a UseBefore after a Get silently does nothing.
		group := router.Group(cfg.RoutePrefix)
		group.UseBefore(p.requireResourceOwner)
		group.Get("/authorize", p.showConsent)
		group.Post("/authorize", p.decideConsent)
		group.Get("/device", p.showDeviceForm)
		group.Post("/device", p.submitDeviceCode)
	}
}

var _ app.RouteProvider = (*Provider)(nil)
