package oauth2

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func (s *SQLStore) RefreshToken(ctx context.Context, id string) (*RefreshToken, error) {
	return scanRefresh(s.db.QueryRowContext(ctx, s.q.refreshByID, id))
}

func scanRefresh(row *sql.Row) (*RefreshToken, error) {
	var (
		t         RefreshToken
		accessID  sql.NullString
		userID    sql.NullString
		rotatedTo sql.NullString
		scopes    string
		expiresAt time.Time
		createdAt time.Time
	)
	err := row.Scan(&t.ID, &accessID, &t.ClientID, &userID, &scopes, &t.FamilyID,
		&rotatedTo, &t.Revoked, timeValue{into: &expiresAt}, timeValue{into: &createdAt})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.AccessTokenID = stringFrom(accessID)
	t.UserID = stringFrom(userID)
	t.RotatedTo = stringFrom(rotatedTo)
	t.Scopes = decodeScopes(scopes)
	t.ExpiresAt, t.CreatedAt = expiresAt, createdAt
	return &t, nil
}

// RotateRefresh revokes the presented token, records what replaced it and
// writes the new pair, in one transaction.
//
// The conditional UPDATE requires the token to be neither revoked nor already
// rotated. Zero rows affected on a row that exists is the RFC 6819 reuse
// signal: this credential was already spent, so one of its two holders is an
// attacker and the caller must revoke the whole family.
func (s *SQLStore) RotateRefresh(ctx context.Context, oldID string, issued Issued, now time.Time) (*RefreshToken, error) {
	var old *RefreshToken
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		successor := ""
		if issued.Refresh != nil {
			successor = issued.Refresh.ID
		}

		result, err := tx.ExecContext(ctx, s.q.rotateRefresh, nullString(successor), oldID, utc(now))
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			existing, err := scanRefresh(tx.QueryRowContext(ctx, s.q.refreshByID, oldID))
			if err != nil {
				return err
			}
			old = existing
			if existing.Revoked || existing.RotatedTo != "" {
				return ErrRefreshReused
			}
			return ErrExpired
		}

		if old, err = scanRefresh(tx.QueryRowContext(ctx, s.q.refreshByID, oldID)); err != nil {
			return err
		}
		return s.writeIssued(ctx, tx, issued)
	})
	if err != nil {
		return old, err
	}
	return old, nil
}

func (s *SQLStore) CreateAccessToken(ctx context.Context, t *AccessToken) error {
	_, err := s.db.ExecContext(ctx, s.q.insertAccess,
		t.ID, nullString(t.UserID), t.ClientID, nullString(t.Name), encodeScopes(t.Scopes),
		t.FamilyID, t.Revoked, utc(t.ExpiresAt), utc(t.CreatedAt), utc(t.UpdatedAt))
	return s.translateInsertErr(err)
}

// AccessToken is the hot path: one indexed primary-key read per authenticated
// request. It is what makes a self-contained token revocable, and the honest
// price of that.
func (s *SQLStore) AccessToken(ctx context.Context, jti string) (*AccessToken, error) {
	return scanAccess(s.db.QueryRowContext(ctx, s.q.accessByID, jti))
}

func scanAccess(row *sql.Row) (*AccessToken, error) {
	var (
		t         AccessToken
		userID    sql.NullString
		name      sql.NullString
		scopes    string
		expiresAt time.Time
		createdAt time.Time
		updatedAt time.Time
	)
	err := row.Scan(&t.ID, &userID, &t.ClientID, &name, &scopes, &t.FamilyID, &t.Revoked,
		timeValue{into: &expiresAt}, timeValue{into: &createdAt}, timeValue{into: &updatedAt})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.UserID = stringFrom(userID)
	t.Name = stringFrom(name)
	t.Scopes = decodeScopes(scopes)
	t.ExpiresAt, t.CreatedAt, t.UpdatedAt = expiresAt, createdAt, updatedAt
	return &t, nil
}

func (s *SQLStore) AccessTokensForUser(ctx context.Context, userID string) ([]*AccessToken, error) {
	rows, err := s.db.QueryContext(ctx, s.q.accessByUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*AccessToken
	for rows.Next() {
		var (
			t         AccessToken
			owner     sql.NullString
			name      sql.NullString
			scopes    string
			expiresAt time.Time
			createdAt time.Time
			updatedAt time.Time
		)
		if err := rows.Scan(&t.ID, &owner, &t.ClientID, &name, &scopes, &t.FamilyID, &t.Revoked,
			timeValue{into: &expiresAt}, timeValue{into: &createdAt}, timeValue{into: &updatedAt}); err != nil {
			return nil, err
		}
		t.UserID = stringFrom(owner)
		t.Name = stringFrom(name)
		t.Scopes = decodeScopes(scopes)
		t.ExpiresAt, t.CreatedAt, t.UpdatedAt = expiresAt, createdAt, updatedAt
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (s *SQLStore) RevokeAccessToken(ctx context.Context, jti string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, s.q.revokeAccess, utc(now), jti)
	if err != nil {
		return err
	}
	return requireAffected(result)
}

// RevokeFamily kills every token descended from one grant. Two indexed
// updates, and no row count to check: a family whose tokens are already
// revoked is a legitimate no-op.
func (s *SQLStore) RevokeFamily(ctx context.Context, familyID string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q.revokeAccessByFamily, utc(now), familyID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q.revokeRefreshByFamily, familyID)
		return err
	})
}

func (s *SQLStore) RevokeForUserClient(ctx context.Context, userID, clientID string, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q.revokeAccessByUserClient, utc(now), userID, clientID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, s.q.revokeRefreshByUserClient, userID, clientID)
		return err
	})
}

func (s *SQLStore) Prune(ctx context.Context, before time.Time) (PruneResult, error) {
	var result PruneResult
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		for _, step := range []struct {
			query string
			into  *int64
		}{
			{s.q.pruneAuthCodes, &result.AuthCodes},
			{s.q.pruneAccess, &result.AccessTokens},
			{s.q.pruneRefresh, &result.RefreshTokens},
			{s.q.pruneDevices, &result.DeviceCodes},
		} {
			outcome, err := tx.ExecContext(ctx, step.query, utc(before))
			if err != nil {
				return err
			}
			affected, err := outcome.RowsAffected()
			if err != nil {
				return err
			}
			*step.into = affected
		}
		return nil
	})
	return result, err
}
