package oauth2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lemmego/api/app"
	"github.com/spf13/cobra"
)

// AddCommands contributes the oauth:* commands.
func (p *Provider) AddCommands() []app.Command {
	return []app.Command{
		p.keysCommand,
		p.clientCommand,
		p.installCommand,
		p.purgeCommand,
		p.routesCommand,
	}
}

var _ app.CommandProvider = (*Provider)(nil)

// resolve returns the server, or an error saying what to do about it.
//
// It never panics. A command is how someone recovers from a half-configured
// application, so failing with a goroutine dump would take away the tool they
// came here to use.
func (p *Provider) resolve() (*Server, error) {
	server := p.Server()
	if server == nil {
		return nil, fmt.Errorf(
			"oauth2: the server is not configured; add &oauth2.Provider{} to bootstrap/providers.go, " +
				"below the database connector")
	}
	return server, nil
}

func (p *Provider) keysCommand(a app.App) *cobra.Command {
	var (
		length  int
		rotate  bool
		keyPath string
	)

	cmd := &cobra.Command{
		Use:   "oauth:keys",
		Short: "Generate the RSA keypair tokens are signed with",
		Long: "Generate the RSA keypair tokens are signed with.\n\n" +
			"The private key is written with O_EXCL, so a second run fails rather than\n" +
			"replacing it: a replaced signing key invalidates every access token in\n" +
			"flight and every refresh token ever issued. Use --rotate to retire the\n" +
			"current key instead, which keeps verifying its outstanding tokens until\n" +
			"they expire.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := keyPath
			if dir == "" {
				if server, err := p.resolve(); err == nil {
					dir = server.cfg.KeysPath
				} else {
					dir = DefaultConfig().KeysPath
				}
			}

			if rotate {
				kid, err := RetireKey(dir)
				if err != nil {
					return fmt.Errorf("retiring the current key: %w", err)
				}
				cmd.Printf("Retired %s (kid %s); it will keep verifying its tokens until they expire.\n",
					PrivateKeyPath(dir), kid)
			}

			key, err := GenerateKey(length)
			if err != nil {
				return err
			}
			if err := WriteKey(dir, key); err != nil {
				return err
			}

			cmd.Printf("Wrote %s and %s\n", PrivateKeyPath(dir), PublicKeyPath(dir))
			cmd.Printf("kid: %s\n", KeyID(&key.PublicKey))

			if err := ensureGitignored(cmd, dir); err != nil {
				cmd.Printf("Could not check .gitignore: %v\n", err)
			}
			if server, err := p.resolve(); err == nil {
				if err := server.ReloadKeys(); err != nil {
					cmd.Printf("The key was written but could not be loaded: %v\n", err)
				}
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&length, "length", 2048, "RSA key size in bits; 2048 is the minimum")
	cmd.Flags().BoolVar(&rotate, "rotate", false, "retire the current key and generate a new one")
	cmd.Flags().StringVar(&keyPath, "path", "", "directory to write to; defaults to the configured keys path")
	return cmd
}

// ensureGitignored keeps a signing key out of version control.
//
// It only appends to an existing .gitignore and never creates one, because
// creating a file a project did not ask for is a surprise — and a project
// without one is probably not using git.
func ensureGitignored(cmd *cobra.Command, dir string) error {
	const name = ".gitignore"
	content, err := os.ReadFile(name)
	if err != nil {
		if os.IsNotExist(err) {
			cmd.Printf("No .gitignore here. Make sure %s is not committed.\n", dir)
			return nil
		}
		return err
	}

	entry := strings.TrimPrefix(filepath.Clean(dir), "./")
	if gitignoreCovers(string(content), entry) {
		return nil
	}

	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "\n# OAuth2 signing keys\n%s/\n", entry); err != nil {
		return err
	}
	cmd.Printf("Added %s/ to .gitignore\n", entry)
	return nil
}

func (p *Provider) clientCommand(a app.App) *cobra.Command {
	var (
		name       string
		redirects  []string
		scopes     []string
		public     bool
		firstParty bool
		personal   bool
		machine    bool
		device     bool
		userID     string
	)

	cmd := &cobra.Command{
		Use:   "oauth:client",
		Short: "Register an OAuth2 client",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := p.resolve()
			if err != nil {
				return err
			}
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			var grants []string
			switch {
			case personal:
				grants = []string{GrantPersonalAccess}
			case machine:
				grants = []string{GrantClientCredentials}
			case device:
				grants = []string{GrantDeviceCode, GrantRefreshToken}
			default:
				grants = []string{GrantAuthorizationCode, GrantRefreshToken}
				if len(redirects) == 0 {
					return fmt.Errorf("--redirect-uri is required for the authorization code grant")
				}
			}

			for _, uri := range redirects {
				if err := ValidateRedirectURI(uri); err != nil {
					return fmt.Errorf("%s: %w", uri, err)
				}
			}

			id := PersonalAccessClientID
			if !personal {
				generated, err := randomToken(16)
				if err != nil {
					return err
				}
				id = generated
			}

			client := &Client{
				ID:           id,
				UserID:       userID,
				Name:         name,
				RedirectURIs: redirects,
				GrantTypes:   grants,
				Scopes:       newScopes(scopes),
				Confidential: !public,
				FirstParty:   firstParty || personal,
				CreatedAt:    server.now(),
				UpdatedAt:    server.now(),
			}

			var secret string
			if client.Confidential {
				secret, err = randomToken(32)
				if err != nil {
					return err
				}
				client.SecretHash = HashSecret(secret)
			}

			if err := server.store.CreateClient(cmd.Context(), client); err != nil {
				return fmt.Errorf("creating the client: %w", err)
			}

			cmd.Printf("Client ID:     %s\n", client.ID)
			if secret != "" {
				// The secret is only ever hashed, so this is genuinely the
				// only time it can be shown.
				cmd.Printf("Client secret: %s\n", secret)
				cmd.Printf("\nThis is the only time the secret can be shown; it is stored hashed.\n")
			} else {
				cmd.Printf("Public client: authenticates with its id and PKCE, no secret.\n")
			}
			cmd.Printf("Grants:        %s\n", strings.Join(grants, ", "))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "a name the user will see on the consent screen")
	cmd.Flags().StringSliceVar(&redirects, "redirect-uri", nil, "where authorization responses are sent; repeatable")
	cmd.Flags().StringSliceVar(&scopes, "scopes", nil, "limit this client to these scopes")
	cmd.Flags().BoolVar(&public, "public", false, "a client that cannot keep a secret, such as a SPA or a mobile app")
	cmd.Flags().BoolVar(&firstParty, "first-party", false, "a client this application owns; consent can be skipped")
	cmd.Flags().BoolVar(&personal, "personal", false, "the client personal access tokens are issued against")
	cmd.Flags().BoolVar(&machine, "client-credentials", false, "a machine-to-machine client with no user")
	cmd.Flags().BoolVar(&device, "device", false, "a client using the device authorization grant")
	cmd.Flags().StringVar(&userID, "user", "", "the id of the user who owns this client")
	return cmd
}

func (p *Provider) installCommand(a app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "oauth:install",
		Short: "Set up OAuth2 in this project",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := p.resolve()
			if err != nil {
				return err
			}

			dir := server.cfg.KeysPath
			if _, statErr := os.Stat(PrivateKeyPath(dir)); statErr == nil {
				cmd.Printf("Signing keys already exist at %s.\n", dir)
			} else {
				key, err := GenerateKey(server.cfg.KeyLength)
				if err != nil {
					return err
				}
				if err := WriteKey(dir, key); err != nil {
					return err
				}
				cmd.Printf("Wrote signing keys to %s (kid %s)\n", dir, KeyID(&key.PublicKey))
				if err := ensureGitignored(cmd, dir); err != nil {
					cmd.Printf("Could not check .gitignore: %v\n", err)
				}
			}

			// The migration and the config file are published rather than
			// written here, so there is one way to get them and `publish`
			// keeps behaving the way people expect.
			cmd.Printf(`
Next:

  1. lemmego run publish --tags=config,migrations
  2. go build ./...          # the published migration must be compiled in
  3. lemmego run migrate up
  4. lemmego run oauth:client --personal --name "%s"

Step 2 is not optional and is the easy one to miss: the migration was
written by a running binary that does not contain it yet.

Then register the provider in bootstrap/providers.go, below the database
connector:

  &oauth2.Provider{},
`, "Personal Access Client")
			return nil
		},
	}
}

func (p *Provider) purgeCommand(a app.App) *cobra.Command {
	var hours int
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "oauth:purge",
		Short: "Delete expired authorization codes, tokens and device codes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := p.resolve()
			if err != nil {
				return err
			}
			if hours == 0 {
				hours = server.cfg.PruneAfterHours
			}
			before := server.now().Add(-time.Duration(hours) * time.Hour)

			if dryRun {
				cmd.Printf("Would delete rows that expired before %s\n", before.Format(time.RFC3339))
				return nil
			}

			result, err := server.store.Prune(cmd.Context(), before)
			if err != nil {
				return err
			}
			cmd.Printf("Deleted rows that expired before %s:\n", before.Format(time.RFC3339))
			cmd.Printf("  authorization codes %d\n  access tokens       %d\n"+
				"  refresh tokens      %d\n  device codes        %d\n",
				result.AuthCodes, result.AccessTokens, result.RefreshTokens, result.DeviceCodes)
			return nil
		},
	}

	cmd.Flags().IntVar(&hours, "hours", 0, "delete rows that expired more than this many hours ago")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be deleted without deleting it")
	return cmd
}

// routesCommand prints what got mounted. The framework has no route listing
// of any kind, so without this there is no way to see where the endpoints
// ended up after a route_prefix change.
func (p *Provider) routesCommand(a app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "oauth:routes",
		Short: "Print the mounted OAuth2 endpoints",
		RunE: func(cmd *cobra.Command, _ []string) error {
			server, err := p.resolve()
			if err != nil {
				return err
			}
			prefix := server.cfg.RoutePrefix

			for _, row := range [][2]string{
				{"GET  " + prefix + "/authorize", "consent screen"},
				{"POST " + prefix + "/authorize", "the user's decision"},
				{"POST " + prefix + "/token", "token endpoint"},
				{"POST " + prefix + "/device/code", "device authorization"},
				{"GET  " + prefix + "/device", "user code entry"},
				{"POST " + prefix + "/device", "device decision"},
				{"POST " + prefix + "/revoke", "RFC 7009 revocation"},
				{"POST " + prefix + "/introspect", "RFC 7662 introspection"},
				{"GET  /.well-known/jwks.json", "public keys"},
				{"GET  /.well-known/oauth-authorization-server", "RFC 8414 metadata"},
			} {
				cmd.Printf("  %-46s %s\n", row[0], row[1])
			}
			cmd.Printf("\nIssuer: %s\n", server.cfg.Issuer)
			if ring := server.Keyring(); ring != nil {
				_, kid := ring.Sign()
				cmd.Printf("Signing key: %s\n", kid)
			} else {
				cmd.Printf("Signing key: none loaded — run `lemmego run oauth:keys`\n")
			}
			return nil
		},
	}
}

// gitignoreCovers reports whether an existing rule already ignores the path.
//
// A scaffolded project ignores "storage/*", which covers storage/oauth —
// appending a second rule for it would be noise suggesting the first was not
// enough. Patterns are matched with filepath.Match so a glob is understood,
// and a directory rule is treated as covering everything beneath it.
//
// Negations are read as not covering: "!storage/.gitkeep" re-includes a path
// rather than ignoring one, so treating it as coverage would leave a key
// committed.
func gitignoreCovers(content, path string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		rule := strings.TrimSuffix(strings.TrimPrefix(line, "/"), "/")
		if rule == "" {
			continue
		}
		// The rule itself, or any parent of the path, matching it.
		for candidate := path; candidate != "." && candidate != "/" && candidate != ""; candidate = filepath.Dir(candidate) {
			if candidate == rule {
				return true
			}
			if matched, err := filepath.Match(rule, candidate); err == nil && matched {
				return true
			}
		}
	}
	return false
}
