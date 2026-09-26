# lemmego/oauth2

An OAuth 2.0 authorization server for [Lemmego](https://lemmego.org), in the
spirit of Laravel Passport: your application issues and revokes the tokens
third parties use to call its API.

This is the server side. Signing in to *someone else's* provider — "log in
with GitHub" — is the client side and is a different, much smaller thing this
package does not do.

> **Status: incomplete.** The store, schema, keys and all five grants are
> implemented and tested. The HTTP endpoints, the consent screen and the
> `oauth:*` commands are not written yet, so this cannot yet be mounted in an
> application. See [What is missing](#what-is-missing).

## What it does

| Grant | Notes |
|---|---|
| Authorization code + PKCE | S256 only. Required of every client by default, not just public ones. |
| Refresh token | Rotating, with reuse detection. |
| Client credentials | Confidential clients only; no refresh token, per RFC 6749 §4.4.3. |
| Device authorization | RFC 8628, for CLIs, TVs and headless devices. |
| Personal access tokens | Long-lived tokens a user makes for themselves. |

Not implemented, deliberately: the **implicit** grant, which is obsolete, and
the **password** grant, which RFC 9700 deprecates because it requires the
client to handle the user's credentials directly. Passport dropped both too.
They are absent rather than disabled, so no configuration can turn them on.

## How it differs from Passport

**Five tables, not six.** Passport carries a separate
`oauth_personal_access_clients` table only because its early versions had no
grant-type column. Here a personal access client is one whose `grant_types`
contains `personal_access`, which removes a join and a way to be inconsistent.

**Client secrets are SHA-256, not bcrypt.** A secret is 32 bytes from
`crypto/rand`, so there is no dictionary to make expensive and nothing a slow
hash would buy — while cost-10 bcrypt would add tens of milliseconds to every
request at an unauthenticated endpoint, which is both a throughput problem and
an amplification vector. bcrypt stays right for a user's password, which is
human-chosen and low entropy.

**The wildcard scope is first-party only.** Passport lets any client request
`*`. A third-party application that can request everything makes the consent
screen a lie.

**`plain` PKCE is refused.** RFC 7636 makes `plain` the default when
`code_challenge_method` is omitted, so an absent method is rejected too rather
than treated as unset.

## Persistence

The store is written against `database/sql` and a dialect, resolved through
`api/db`:

```go
conn, ok := db.Resolve(a)      // whichever ORM opened the connection
store, err := oauth2.NewSQLStore(conn)
```

It does not depend on an ORM or on GPA. GPA is off by default in a scaffolded
project, makes the provider and the native handle mutually exclusive under
GORM and Bun, and cannot hand out a repository through an interface at all,
since Go forbids generic methods on interfaces — so a framework package that
needs its own tables cannot build on it.

`Store` exposes **transitions, not CRUD**. Consuming an authorization code,
rotating a refresh token and claiming a device poll each have to be atomic
against a concurrent identical request, so each is one method whose result
distinguishes "it worked" from "it was already used" and from "it never
existed". In SQL each is a single conditional `UPDATE` whose affected row
count is the decision. Exposing `Get` and `Update` instead would let every
caller re-implement that race, and one of them would get it wrong.

An in-memory `Store` ships for tests and for trying the server out.

## Tokens

Access tokens are RS256 JWTs following RFC 9068 (`typ: at+jwt`), whose `jti`
is a row in `oauth_access_tokens`. That row is what makes revocation real: the
signature proves the token was issued, and the row proves it still counts.

The cost is honest — one RSA verification and one indexed primary-key read per
authenticated request. `revocation` can be set to `cached` (which reopens a
revocation window as long as its TTL) or `never` (under which revoking does
nothing until the token expires), and the configuration comment says so in
those words.

The `kid` is the **RFC 7638 JWK thumbprint** rather than a name. The same key
therefore has the same `kid` in every process with no state to keep in sync —
and a `kid` is only ever a lookup into a map of keys already loaded, never a
path or a filename, so `"kid": "../../etc/passwd"` resolves to nothing and is
rejected before anything touches a filesystem.

Rotation moves the active key aside; its public half stays in the ring and in
the JWKS, so tokens it signed keep verifying until they expire.

## The migration is yours

`lemmego publish --tags=migrations` writes a real migration into your
configured migration path, with the schema spelled out as ordinary
`migration.Create` calls — the same form as the `create_users_table` migration
a scaffolded project already has.

The file is then **yours**: add a column, widen a type, drop the device-code
table if you will never use the device grant. Nothing in this package reads it
back. A stub that called into the package would have looked like ownership and
given none of it, since changing anything would have meant forking.

What the server does expect is that the columns it reads and writes still
exist with compatible types. Removing a table disables the grant that uses it;
removing a column the server writes fails at runtime rather than at migrate
time.

## Testing

```bash
go test ./...                       # in-memory and SQLite
GOWORK=off go test ./...            # as a published module

export OAUTH2_POSTGRES_DSN="postgres://$USER@127.0.0.1:5432/lemmego_oauth2_test?sslmode=disable"
export OAUTH2_MYSQL_DSN="root@tcp(127.0.0.1:3306)/lemmego_oauth2_test?parseTime=true&loc=UTC"
go test -run TestIntegration ./...  # the same contract on MySQL and PostgreSQL
```

`storetest` holds the contract every `Store` must satisfy, and both
implementations run it on all three dialects. It has already earned its keep
twice: it caught the in-memory store silently overwriting a duplicate token id
where SQL rejects it, and it caught the schema builder rendering SQLite DDL
for every dialect.

Time comes from an injectable clock, so expiry is tested by advancing a
variable rather than by sleeping.

### What the adversarial suite proves

Code replay (and that it revokes the whole family), code substitution across
clients, `redirect_uri` substitution at exchange, PKCE downgrade, stripping,
`plain`, and the classic bug of comparing the verifier against the challenge
instead of deriving it; refresh reuse, refresh bound to its client, scope
elevation at exchange and at refresh; concurrent exchange issuing exactly one
token; `alg:none`, HMAC confusion using four encodings of the public key,
algorithm substitution within the RSA family, `kid` injection, `typ`
confusion, cross-issuer and cross-audience tokens, a forged `jti` failing
closed, and a JWKS carrying no private material.

**This proves the listed attacks are blocked. It does not prove the absence of
attacks** — that is the risk taken in hand-rolling a protocol implementation
rather than using an audited one such as `ory/fosite`.

## What is missing

- The HTTP endpoints: `/authorize`, `/token`, `/device/code`, `/device`,
  `/revoke`, `/introspect`, and the two `/.well-known/` documents. The
  server-side logic behind each exists and is tested; the routing does not.
- The consent screen.
- `oauth2.Protect` middleware and the bearer-token bridge into `auth`.
- The `oauth:install`, `oauth:client`, `oauth:keys` and `oauth:purge`
  commands — including the one that generates the signing keys.
- Documentation on lemmego.org.

## Licence

Same as the rest of Lemmego.
