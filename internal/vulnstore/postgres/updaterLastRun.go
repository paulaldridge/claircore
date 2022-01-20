package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
)

// recordUpdaterUpToDate records that an updater is up to date with vulnerabilities at the last time
// inserts an updater with last check timestamp, or updates an existing updater with the new time
func recordUpdaterUpToDate(ctx context.Context, pool *pgxpool.Pool, updater driver.Updater, updateTime time.Time) error {
	const (
		// upsert inserts or updates a record of last time updater was checked for new vulns
		upsert = `INSERT INTO updaters_last_run (
			updater_name,
			last_successful_run
		) VALUES (
			$1,
			$2
		)
		ON CONFLICT (updater_name) DO UPDATE
		SET last_successful_run = $2
		RETURNING updater_name;`
	)

	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/recordUpdaterUpToDate"))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var updaterName string

	if err := pool.QueryRow(ctx, upsert, updater.Name(), updateTime).Scan(&updaterName); err != nil {
		return fmt.Errorf("failed to upsert last update time: %w", err)
	}

	zlog.Debug(ctx).
		Str("updater", updater.Name()).
		Msg("Updater last checked time updated")

	return nil
}

// recordDistroUpdatersUpToDate records that all updaters for a single distro are up to date with vulnerabilities at this time
// updates all existing updaters with that distro with the new time
func recordDistroUpdatersUpToDate(ctx context.Context, pool *pgxpool.Pool, distro string, updateTime time.Time) error {
	const (
		update = `UPDATE updaters_last_run
		SET last_successful_run = $1
		WHERE updater_name like $2 || '%'
		RETURNING updater_name;`
	)

	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/recordDistroUpdatersUpToDate"))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var updaterName string

	if err := pool.QueryRow(ctx, update, updateTime, distro).Scan(&updaterName); err != nil {
		return fmt.Errorf("failed to update all last update times for distro %s: %w", distro, err)
	}

	zlog.Debug(ctx).
		Str("updater", distro).
		Msg(fmt.Sprintf("Last checked time updated for all %s updaters", distro))

	return nil
}
