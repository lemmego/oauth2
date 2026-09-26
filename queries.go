package oauth2

import "strings"

// queries holds every statement this package runs, already rebound for the
// dialect, so the request path does no string work.
//
// Every statement is written with "?" placeholders and no string literal.
// rebind renumbers them for PostgreSQL and relies on the absence of literals;
// TestNoQueryContainsAStringLiteral checks that rather than trusting it.
type queries struct {
	clientByID    string
	clientsByUser string
	insertClient  string
	updateClient  string
	revokeClient  string

	insertAuthCode  string
	authCodeByID    string
	consumeAuthCode string

	insertAccess             string
	accessByID               string
	accessByUser             string
	revokeAccess             string
	revokeAccessByFamily     string
	revokeAccessByClient     string
	revokeAccessByUserClient string

	insertRefresh             string
	refreshByID               string
	rotateRefresh             string
	revokeRefreshByFamily     string
	revokeRefreshByClient     string
	revokeRefreshByUserClient string

	insertDevice       string
	deviceByID         string
	deviceByUserCode   string
	approveDevice      string
	denyDevice         string
	claimDevicePoll    string
	penaliseDevicePoll string
	consumeDevice      string

	pruneAuthCodes string
	pruneAccess    string
	pruneRefresh   string
	pruneDevices   string
}

const (
	clientColumns   = `id, user_id, name, secret, redirect_uris, grant_types, scopes, confidential, first_party, revoked, created_at, updated_at`
	authCodeColumns = `id, user_id, client_id, scopes, redirect_uri, code_challenge, code_challenge_method, family_id, expires_at, consumed_at, revoked, created_at`
	accessColumns   = `id, user_id, client_id, name, scopes, family_id, revoked, expires_at, created_at, updated_at`
	refreshColumns  = `id, access_token_id, client_id, user_id, scopes, family_id, rotated_to, revoked, expires_at, created_at`
	deviceColumns   = `id, user_code_hash, client_id, user_id, scopes, family_id, interval_seconds, poll_count, last_polled_at, approved_at, denied_at, consumed_at, expires_at, created_at`
)

func buildQueries(dialect, prefix string) queries {
	table := func(name string) string { return prefix + name }
	clients := table("clients")
	codes := table("auth_codes")
	access := table("access_tokens")
	refresh := table("refresh_tokens")
	devices := table("device_codes")

	raw := queries{
		clientByID:    `SELECT ` + clientColumns + ` FROM ` + clients + ` WHERE id = ?`,
		clientsByUser: `SELECT ` + clientColumns + ` FROM ` + clients + ` WHERE user_id = ? ORDER BY created_at, id`,
		insertClient: `INSERT INTO ` + clients + ` (` + clientColumns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		updateClient: `UPDATE ` + clients + ` SET user_id = ?, name = ?, secret = ?,
			redirect_uris = ?, grant_types = ?, scopes = ?, confidential = ?,
			first_party = ?, revoked = ?, updated_at = ? WHERE id = ?`,
		revokeClient: `UPDATE ` + clients + ` SET revoked = 1, updated_at = ? WHERE id = ?`,

		insertAuthCode: `INSERT INTO ` + codes + ` (` + authCodeColumns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		authCodeByID: `SELECT ` + authCodeColumns + ` FROM ` + codes + ` WHERE id = ?`,
		// The single-use latch. Zero rows affected on a row that exists means
		// it was already consumed, revoked, or has expired.
		consumeAuthCode: `UPDATE ` + codes + ` SET consumed_at = ?
			WHERE id = ? AND consumed_at IS NULL AND revoked = 0 AND expires_at > ?`,

		insertAccess: `INSERT INTO ` + access + ` (` + accessColumns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		accessByID:               `SELECT ` + accessColumns + ` FROM ` + access + ` WHERE id = ?`,
		accessByUser:             `SELECT ` + accessColumns + ` FROM ` + access + ` WHERE user_id = ? ORDER BY created_at, id`,
		revokeAccess:             `UPDATE ` + access + ` SET revoked = 1, updated_at = ? WHERE id = ?`,
		revokeAccessByFamily:     `UPDATE ` + access + ` SET revoked = 1, updated_at = ? WHERE family_id = ? AND revoked = 0`,
		revokeAccessByClient:     `UPDATE ` + access + ` SET revoked = 1, updated_at = ? WHERE client_id = ? AND revoked = 0`,
		revokeAccessByUserClient: `UPDATE ` + access + ` SET revoked = 1, updated_at = ? WHERE user_id = ? AND client_id = ? AND revoked = 0`,

		insertRefresh: `INSERT INTO ` + refresh + ` (` + refreshColumns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		refreshByID: `SELECT ` + refreshColumns + ` FROM ` + refresh + ` WHERE id = ?`,
		// Rotation and the reuse check are the same statement: a token that
		// is already revoked or already rotated matches nothing.
		rotateRefresh: `UPDATE ` + refresh + ` SET revoked = 1, rotated_to = ?
			WHERE id = ? AND revoked = 0 AND rotated_to IS NULL AND expires_at > ?`,
		revokeRefreshByFamily:     `UPDATE ` + refresh + ` SET revoked = 1 WHERE family_id = ? AND revoked = 0`,
		revokeRefreshByClient:     `UPDATE ` + refresh + ` SET revoked = 1 WHERE client_id = ? AND revoked = 0`,
		revokeRefreshByUserClient: `UPDATE ` + refresh + ` SET revoked = 1 WHERE user_id = ? AND client_id = ? AND revoked = 0`,

		insertDevice: `INSERT INTO ` + devices + ` (` + deviceColumns + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceByID:       `SELECT ` + deviceColumns + ` FROM ` + devices + ` WHERE id = ?`,
		deviceByUserCode: `SELECT ` + deviceColumns + ` FROM ` + devices + ` WHERE user_code_hash = ?`,
		// A decision only applies to an undecided, unexpired authorization,
		// so a second approval cannot overwrite the first.
		approveDevice: `UPDATE ` + devices + ` SET approved_at = ?, user_id = ?, scopes = ?
			WHERE user_code_hash = ? AND approved_at IS NULL AND denied_at IS NULL AND expires_at > ?`,
		denyDevice: `UPDATE ` + devices + ` SET denied_at = ?
			WHERE user_code_hash = ? AND approved_at IS NULL AND denied_at IS NULL AND expires_at > ?`,
		// The polling interval, enforced atomically: a poll that arrives
		// before the interval has elapsed matches nothing and is penalised.
		claimDevicePoll: `UPDATE ` + devices + ` SET last_polled_at = ?, poll_count = poll_count + 1
			WHERE id = ? AND (last_polled_at IS NULL OR last_polled_at <= ?)`,
		penaliseDevicePoll: `UPDATE ` + devices + ` SET interval_seconds = interval_seconds + 5,
			last_polled_at = ?, poll_count = poll_count + 1 WHERE id = ?`,
		consumeDevice: `UPDATE ` + devices + ` SET consumed_at = ?
			WHERE id = ? AND consumed_at IS NULL AND approved_at IS NOT NULL AND expires_at > ?`,

		pruneAuthCodes: `DELETE FROM ` + codes + ` WHERE expires_at < ?`,
		pruneAccess:    `DELETE FROM ` + access + ` WHERE expires_at < ?`,
		pruneRefresh:   `DELETE FROM ` + refresh + ` WHERE expires_at < ?`,
		pruneDevices:   `DELETE FROM ` + devices + ` WHERE expires_at < ?`,
	}

	return mapQueries(raw, func(query string) string {
		return rebind(dialect, booleanLiterals(dialect, collapse(query)))
	})
}

// collapse flattens the indentation the statements are written with, so a
// logged query is one line and a golden test compares text rather than
// whitespace.
func collapse(query string) string {
	return strings.Join(strings.Fields(query), " ")
}

// booleanLiterals renders the 0 and 1 the statements are written with as
// PostgreSQL's FALSE and TRUE. SQLite and MySQL take the integers; PostgreSQL
// rejects an integer where a BOOLEAN belongs.
//
// The substitution is on whole words next to a boolean column, not on every
// 0 and 1, because interval_seconds + 5 and poll_count + 1 are arithmetic.
func booleanLiterals(dialect, query string) string {
	if dialect != "postgres" {
		return query
	}
	replacer := strings.NewReplacer(
		"revoked = 0", "revoked = FALSE",
		"revoked = 1", "revoked = TRUE",
	)
	return replacer.Replace(query)
}

// mapQueries applies fn to every statement. Listing the fields once here
// beats repeating the transformation at each of the thirty-odd sites.
func mapQueries(q queries, fn func(string) string) queries {
	for _, field := range q.fields() {
		*field = fn(*field)
	}
	return q
}

func (q *queries) fields() []*string {
	return []*string{
		&q.clientByID, &q.clientsByUser, &q.insertClient, &q.updateClient, &q.revokeClient,
		&q.insertAuthCode, &q.authCodeByID, &q.consumeAuthCode,
		&q.insertAccess, &q.accessByID, &q.accessByUser, &q.revokeAccess,
		&q.revokeAccessByFamily, &q.revokeAccessByClient, &q.revokeAccessByUserClient,
		&q.insertRefresh, &q.refreshByID, &q.rotateRefresh,
		&q.revokeRefreshByFamily, &q.revokeRefreshByClient, &q.revokeRefreshByUserClient,
		&q.insertDevice, &q.deviceByID, &q.deviceByUserCode,
		&q.approveDevice, &q.denyDevice, &q.claimDevicePoll, &q.penaliseDevicePoll, &q.consumeDevice,
		&q.pruneAuthCodes, &q.pruneAccess, &q.pruneRefresh, &q.pruneDevices,
	}
}
