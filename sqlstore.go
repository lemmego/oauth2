package oauth2

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lemmego/api/db"
)

// SQLStore persists protocol state in the application's database.
//
// Every security-critical transition is one conditional UPDATE whose affected
// row count is the decision, so two concurrent requests carrying the same
// credential cannot both win. That is a property of the statement, not of the
// caller, which is why the Store methods are transitions rather than CRUD.
type SQLStore struct {
	db      *sql.DB
	dialect string
	prefix  string
	q       queries
}

var _ Store = (*SQLStore)(nil)

// StoreOption configures a SQLStore.
type StoreOption func(*SQLStore)

// WithTablePrefix changes the oauth_ prefix every table name carries.
func WithTablePrefix(prefix string) StoreOption {
	return func(s *SQLStore) { s.prefix = prefix }
}

// NewSQLStore builds a store over the application's connection.
//
// It takes a db.Connection rather than a *sql.DB so the dialect travels with
// the pool: a borrowed pool may have been opened through a connector with no
// registered database/sql driver name, so there is nothing to infer from.
func NewSQLStore(conn db.Connection, opts ...StoreOption) (*SQLStore, error) {
	if conn == nil {
		return nil, errors.New("oauth2: no database connection")
	}
	pool := conn.SQLDB()
	if pool == nil {
		return nil, errors.New("oauth2: the database connection carries no pool")
	}
	if conn.Dialect() == db.DialectUnknown {
		return nil, errors.New("oauth2: the database connection reports no dialect")
	}

	s := &SQLStore{db: pool, dialect: string(conn.Dialect()), prefix: "oauth_"}
	for _, opt := range opts {
		opt(s)
	}
	if !validTablePrefix(s.prefix) {
		return nil, fmt.Errorf("oauth2: invalid table prefix %q", s.prefix)
	}
	// Built once, so the request path does no string work.
	s.q = buildQueries(s.dialect, s.prefix)
	return s, nil
}

// NewSQLStoreWithDB is for tests and for an application that opened its own
// pool deliberately.
func NewSQLStoreWithDB(pool *sql.DB, dialect string, opts ...StoreOption) (*SQLStore, error) {
	return NewSQLStore(staticConn{pool: pool, dialect: db.Dialect(dialect)}, opts...)
}

type staticConn struct {
	pool    *sql.DB
	dialect db.Dialect
}

func (c staticConn) SQLDB() *sql.DB      { return c.pool }
func (c staticConn) Dialect() db.Dialect { return c.dialect }
func (c staticConn) Name() string        { return "oauth2" }

// validTablePrefix keeps the prefix out of SQL injection range. Table names
// cannot be bound as parameters, so the prefix is interpolated, and the only
// safe interpolation is one that cannot contain anything but an identifier.
func validTablePrefix(prefix string) bool {
	if len(prefix) > 32 {
		return false
	}
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

func (s *SQLStore) Client(ctx context.Context, id string) (*Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, s.q.clientByID, id))
}

func scanClient(row *sql.Row) (*Client, error) {
	var (
		c         Client
		userID    sql.NullString
		secret    sql.NullString
		redirects string
		grants    string
		scopes    sql.NullString
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&c.ID, &userID, &c.Name, &secret, &redirects, &grants, &scopes,
		&c.Confidential, &c.FirstParty, &c.Revoked,
		timeValue{into: &createdAt}, timeValue{into: &updatedAt})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.UserID = stringFrom(userID)
	c.SecretHash = stringFrom(secret)
	c.RedirectURIs = decodeList(redirects)
	c.GrantTypes = decodeList(grants)
	c.Scopes = decodeScopes(stringFrom(scopes))
	c.CreatedAt = createdAt
	c.UpdatedAt = updatedAt
	return &c, nil
}

func (s *SQLStore) CreateClient(ctx context.Context, c *Client) error {
	_, err := s.db.ExecContext(ctx, s.q.insertClient,
		c.ID, nullString(c.UserID), c.Name, nullString(c.SecretHash),
		encodeList(c.RedirectURIs), encodeList(c.GrantTypes), nullString(encodeScopes(c.Scopes)),
		c.Confidential, c.FirstParty, c.Revoked, utc(c.CreatedAt), utc(c.UpdatedAt))
	return s.translateInsertErr(err)
}

// translateInsertErr turns a unique-constraint violation into ErrDuplicate.
//
// The three drivers word it differently and none exposes a portable code, so
// this matches on the text. A miss is not a security problem — the insert
// failed either way — but it would report an unhelpful error, so the
// conformance suite checks it on every dialect.
func (s *SQLStore) translateInsertErr(err error) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	for _, marker := range []string{
		"UNIQUE constraint failed", // sqlite
		"Duplicate entry",          // mysql
		"duplicate key value",      // postgres
	} {
		if containsFold(text, marker) {
			return ErrDuplicate
		}
	}
	return err
}

func (s *SQLStore) UpdateClient(ctx context.Context, c *Client) error {
	result, err := s.db.ExecContext(ctx, s.q.updateClient,
		nullString(c.UserID), c.Name, nullString(c.SecretHash),
		encodeList(c.RedirectURIs), encodeList(c.GrantTypes), nullString(encodeScopes(c.Scopes)),
		c.Confidential, c.FirstParty, c.Revoked, utc(c.UpdatedAt), c.ID)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

func requireAffected(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) ClientsForUser(ctx context.Context, userID string) ([]*Client, error) {
	rows, err := s.db.QueryContext(ctx, s.q.clientsByUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Client
	for rows.Next() {
		var (
			c         Client
			owner     sql.NullString
			secret    sql.NullString
			redirects string
			grants    string
			scopes    sql.NullString
			createdAt time.Time
			updatedAt time.Time
		)
		if err := rows.Scan(&c.ID, &owner, &c.Name, &secret, &redirects, &grants, &scopes,
			&c.Confidential, &c.FirstParty, &c.Revoked,
			timeValue{into: &createdAt}, timeValue{into: &updatedAt}); err != nil {
			return nil, err
		}
		c.UserID = stringFrom(owner)
		c.SecretHash = stringFrom(secret)
		c.RedirectURIs = decodeList(redirects)
		c.GrantTypes = decodeList(grants)
		c.Scopes = decodeScopes(stringFrom(scopes))
		c.CreatedAt, c.UpdatedAt = createdAt, updatedAt
		out = append(out, &c)
	}
	return out, rows.Err()
}

// RevokeClient cascades in one transaction, so an administrator pays the cost
// once rather than every request asking whether the client behind a token is
// still live.
func (s *SQLStore) RevokeClient(ctx context.Context, id string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, s.q.revokeClient, utc(now), id)
		if err != nil {
			return err
		}
		if err := requireAffected(result); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q.revokeAccessByClient, utc(now), id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, s.q.revokeRefreshByClient, id)
		return err
	})
}

func (s *SQLStore) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) CreateAuthCode(ctx context.Context, code *AuthCode) error {
	_, err := s.db.ExecContext(ctx, s.q.insertAuthCode,
		code.ID, code.UserID, code.ClientID, encodeScopes(code.Scopes), code.RedirectURI,
		nullString(code.CodeChallenge), nullString(code.CodeChallengeMethod),
		code.FamilyID, utc(code.ExpiresAt), utcPtr(code.ConsumedAt), code.Revoked, utc(code.CreatedAt))
	return s.translateInsertErr(err)
}

// ExchangeAuthCode consumes the code and writes the issued pair in one
// transaction. The UPDATE is the decision: zero rows affected means the code
// was already consumed, revoked or expired, and the follow-up read says which.
func (s *SQLStore) ExchangeAuthCode(ctx context.Context, id string, issued Issued, now time.Time) (*AuthCode, error) {
	var code *AuthCode
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, s.q.consumeAuthCode, utc(now), id, utc(now))
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			existing, err := scanAuthCode(tx.QueryRowContext(ctx, s.q.authCodeByID, id))
			if err != nil {
				return err
			}
			code = existing
			switch {
			case existing.ConsumedAt != nil:
				return ErrCodeReplayed
			case existing.Revoked:
				return ErrNotFound
			default:
				return ErrExpired
			}
		}

		if code, err = scanAuthCode(tx.QueryRowContext(ctx, s.q.authCodeByID, id)); err != nil {
			return err
		}
		return s.writeIssued(ctx, tx, issued)
	})
	if err != nil {
		return code, err
	}
	return code, nil
}

func scanAuthCode(row *sql.Row) (*AuthCode, error) {
	var (
		c          AuthCode
		scopes     string
		challenge  sql.NullString
		method     sql.NullString
		expiresAt  time.Time
		createdAt  time.Time
		consumedAt *time.Time
	)
	err := row.Scan(&c.ID, &c.UserID, &c.ClientID, &scopes, &c.RedirectURI,
		&challenge, &method, &c.FamilyID,
		timeValue{into: &expiresAt}, nullTimeValue{into: &consumedAt},
		&c.Revoked, timeValue{into: &createdAt})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Scopes = decodeScopes(scopes)
	c.CodeChallenge = stringFrom(challenge)
	c.CodeChallengeMethod = stringFrom(method)
	c.ExpiresAt, c.CreatedAt, c.ConsumedAt = expiresAt, createdAt, consumedAt
	return &c, nil
}

func (s *SQLStore) writeIssued(ctx context.Context, tx *sql.Tx, issued Issued) error {
	if issued.Access != nil {
		if _, err := tx.ExecContext(ctx, s.q.insertAccess,
			issued.Access.ID, nullString(issued.Access.UserID), issued.Access.ClientID,
			nullString(issued.Access.Name), encodeScopes(issued.Access.Scopes),
			issued.Access.FamilyID, issued.Access.Revoked,
			utc(issued.Access.ExpiresAt), utc(issued.Access.CreatedAt), utc(issued.Access.UpdatedAt),
		); err != nil {
			return s.translateInsertErr(err)
		}
	}
	if issued.Refresh != nil {
		if _, err := tx.ExecContext(ctx, s.q.insertRefresh,
			issued.Refresh.ID, nullString(issued.Refresh.AccessTokenID), issued.Refresh.ClientID,
			nullString(issued.Refresh.UserID), encodeScopes(issued.Refresh.Scopes),
			issued.Refresh.FamilyID, nullString(issued.Refresh.RotatedTo), issued.Refresh.Revoked,
			utc(issued.Refresh.ExpiresAt), utc(issued.Refresh.CreatedAt),
		); err != nil {
			return s.translateInsertErr(err)
		}
	}
	return nil
}
