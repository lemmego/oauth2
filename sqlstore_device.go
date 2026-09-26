package oauth2

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *SQLStore) CreateDeviceCode(ctx context.Context, d *DeviceCode) error {
	_, err := s.db.ExecContext(ctx, s.q.insertDevice,
		d.ID, d.UserCodeHash, d.ClientID, nullString(d.UserID), encodeScopes(d.Scopes),
		d.FamilyID, d.IntervalSeconds, d.PollCount, utcPtr(d.LastPolledAt),
		utcPtr(d.ApprovedAt), utcPtr(d.DeniedAt), utcPtr(d.ConsumedAt),
		utc(d.ExpiresAt), utc(d.CreatedAt))
	return s.translateInsertErr(err)
}

func (s *SQLStore) DeviceCodeByUserCode(ctx context.Context, userCodeHash string) (*DeviceCode, error) {
	return scanDevice(s.db.QueryRowContext(ctx, s.q.deviceByUserCode, userCodeHash))
}

func scanDevice(row *sql.Row) (*DeviceCode, error) {
	var (
		d            DeviceCode
		userID       sql.NullString
		scopes       string
		lastPolledAt *time.Time
		approvedAt   *time.Time
		deniedAt     *time.Time
		consumedAt   *time.Time
		expiresAt    time.Time
		createdAt    time.Time
	)
	err := row.Scan(&d.ID, &d.UserCodeHash, &d.ClientID, &userID, &scopes, &d.FamilyID,
		&d.IntervalSeconds, &d.PollCount,
		nullTimeValue{into: &lastPolledAt}, nullTimeValue{into: &approvedAt},
		nullTimeValue{into: &deniedAt}, nullTimeValue{into: &consumedAt},
		timeValue{into: &expiresAt}, timeValue{into: &createdAt})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.UserID = stringFrom(userID)
	d.Scopes = decodeScopes(scopes)
	d.LastPolledAt, d.ApprovedAt, d.DeniedAt, d.ConsumedAt = lastPolledAt, approvedAt, deniedAt, consumedAt
	d.ExpiresAt, d.CreatedAt = expiresAt, createdAt
	return &d, nil
}

// ApproveDeviceCode records the user's decision. The conditional UPDATE
// requires no decision to have been made yet, so a second approval cannot
// overwrite the first — which is what stops a stolen user code from being
// re-approved against a different account.
func (s *SQLStore) ApproveDeviceCode(ctx context.Context, userCodeHash, userID string, scopes Scopes, now time.Time) error {
	result, err := s.db.ExecContext(ctx, s.q.approveDevice,
		utc(now), userID, encodeScopes(scopes), userCodeHash, utc(now))
	if err != nil {
		return err
	}
	return s.decisionOutcome(ctx, result, userCodeHash, now)
}

func (s *SQLStore) DenyDeviceCode(ctx context.Context, userCodeHash string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, s.q.denyDevice, utc(now), userCodeHash, utc(now))
	if err != nil {
		return err
	}
	return s.decisionOutcome(ctx, result, userCodeHash, now)
}

// decisionOutcome says why a decision did not apply: no such code, one that
// already expired, or one already decided.
func (s *SQLStore) decisionOutcome(ctx context.Context, result sql.Result, userCodeHash string, now time.Time) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected > 0 {
		return nil
	}

	existing, err := s.DeviceCodeByUserCode(ctx, userCodeHash)
	if err != nil {
		return err
	}
	switch {
	case existing.ApprovedAt != nil, existing.DeniedAt != nil:
		return ErrAlreadyDecided
	case !existing.ExpiresAt.After(now):
		return ErrExpired
	default:
		return ErrNotFound
	}
}

// PollDeviceCode enforces the polling interval with a conditional UPDATE, so
// two devices polling concurrently cannot both pass it.
//
// The interval check runs before the status check and applies even to a
// finished authorization, so a device cannot escape the rate limit by
// polling a code it knows is ready.
func (s *SQLStore) PollDeviceCode(ctx context.Context, id string, now time.Time) (*DeviceCode, PollOutcome, error) {
	var (
		device  *DeviceCode
		outcome PollOutcome
	)
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		// Read first: the interval to compare against is stored per row and
		// grows, so it cannot be a constant in the statement.
		existing, err := scanDevice(tx.QueryRowContext(ctx, s.q.deviceByID, id))
		if err != nil {
			return err
		}

		earliest := utc(now).Add(-time.Duration(existing.IntervalSeconds) * time.Second)
		result, err := tx.ExecContext(ctx, s.q.claimDevicePoll, utc(now), id, earliest)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			if _, err := tx.ExecContext(ctx, s.q.penaliseDevicePoll, utc(now), id); err != nil {
				return err
			}
			if device, err = scanDevice(tx.QueryRowContext(ctx, s.q.deviceByID, id)); err != nil {
				return err
			}
			outcome = PollSlowDown
			return nil
		}

		if device, err = scanDevice(tx.QueryRowContext(ctx, s.q.deviceByID, id)); err != nil {
			return err
		}
		switch {
		case device.DeniedAt != nil:
			outcome = PollDenied
		case !device.ExpiresAt.After(now):
			outcome = PollExpired
		case device.ConsumedAt != nil:
			outcome = PollExpired
		case device.ApprovedAt != nil:
			outcome = PollReady
		default:
			outcome = PollPending
		}
		return nil
	})
	if err != nil {
		return nil, PollPending, err
	}
	return device, outcome, nil
}

// ExchangeDeviceCode consumes an approved device code with the same
// single-use latch an authorization code uses.
func (s *SQLStore) ExchangeDeviceCode(ctx context.Context, id string, issued Issued, now time.Time) (*DeviceCode, error) {
	var device *DeviceCode
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, s.q.consumeDevice, utc(now), id, utc(now))
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			existing, err := scanDevice(tx.QueryRowContext(ctx, s.q.deviceByID, id))
			if err != nil {
				return err
			}
			device = existing
			switch {
			case existing.ConsumedAt != nil:
				return ErrCodeReplayed
			case existing.ApprovedAt == nil:
				return ErrNotApproved
			default:
				return ErrExpired
			}
		}

		if device, err = scanDevice(tx.QueryRowContext(ctx, s.q.deviceByID, id)); err != nil {
			return err
		}
		return s.writeIssued(ctx, tx, issued)
	})
	if err != nil {
		return device, err
	}
	return device, nil
}
