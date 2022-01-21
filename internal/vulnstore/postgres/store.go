package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/libvuln/driver"
)

// store implements all interfaces in the vulnstore package
type Store struct {
	pool *pgxpool.Pool
	// Initialized is used as an atomic bool for tracking initialization.
	initialized uint32
}

func NewVulnStore(pool *pgxpool.Pool) *Store {
	return &Store{
		pool: pool,
	}
}

var (
	_ vulnstore.Updater       = (*Store)(nil)
	_ vulnstore.Vulnerability = (*Store)(nil)
)

// UpdateVulnerabilities implements vulnstore.Updater.
func (s *Store) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error) {
	return updateVulnerabilites(ctx, s.pool, updater, fingerprint, vulns)
}

// DeleteUpdateOperations implements vulnstore.Updater.
func (s *Store) DeleteUpdateOperations(ctx context.Context, id ...uuid.UUID) (int64, error) {
	const query = `DELETE FROM update_operation WHERE ref = ANY($1::uuid[]);`
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/deleteUpdateOperations"))
	if len(id) == 0 {
		return 0, nil
	}

	// Pgx seems unwilling to do the []uuid.UUID → uuid[] conversion, so we're
	// forced to make some garbage here.
	refStr := make([]string, len(id))
	for i := range id {
		refStr[i] = id[i].String()
	}
	tag, err := s.pool.Exec(ctx, query, refStr)
	if err != nil {
		return 0, fmt.Errorf("failed to delete: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RecordUpdaterUpToDate records that an updater is up to date with vulnerabilities at the last time
func (s *Store) RecordUpdaterUpToDate(ctx context.Context, updater driver.Updater, updateTime time.Time) error {
	return recordUpdaterUpToDate(ctx, s.pool, updater, updateTime)
}

// RecordDistroUpdatersUpToDate records that all updaters for a single distro are up to date with vulnerabilities at this time
func (s *Store) RecordDistroUpdatersUpToDate(ctx context.Context, distro string, updateTime time.Time) error {
	return recordDistroUpdatersUpToDate(ctx, s.pool, distro, updateTime)
}
