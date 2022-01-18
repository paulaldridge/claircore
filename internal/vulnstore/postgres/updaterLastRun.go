package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
)

// recordSuccessfulUpdate records the latest time an updater is checked for new vulns
// inserts an updater with last check timestamp, or updates an existing updater with the new time
func recordSuccessfulUpdate(ctx context.Context, pool *pgxpool.Pool, updater driver.Updater, updateTime time.Time) error {
	const (
		// upsert inserts or updates a record of last time updater was checked for new vulns
		upsert = `INSERT INTO updaters_last_run (
			updater_name,
			last_successful_run,
			distro
		) VALUES (
			$1,
			$2,
			$3
		)
		ON CONFLICT (updater_name) DO UPDATE
		SET last_successful_run = $2
		RETURNING updater_name;` // TODO do we only want to do this is the last_success_time is newer than the one in db?
	)

	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/recordSuccessfulUpdate"))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	distro := findDistro(updater)
	var updaterName string

	if err := pool.QueryRow(ctx, upsert, updater.Name(), updateTime, distro).Scan(&updaterName); err != nil {
		return fmt.Errorf("failed to upsert last update time: %w, with distro: %s", err, distro)
	}

	zlog.Debug(ctx).
		Str("updater", updater.Name()).
		Msg("Updater last checked time updated")

	return nil
}

// findDistro works out the distro from update name
func findDistro(updater driver.Updater) string {
	if strings.Contains(updater.Name(), "RHEL") {
		return "rhel"
	} else if strings.Contains(updater.Name(), "alpine") {
		return "alpine"
	} else if strings.Contains(updater.Name(), "debian") {
		return "debian"
	} else if strings.Contains(updater.Name(), "ubuntu") {
		return "ubuntu"
	} else {
		return ""
	}
}

// recordNothingToUpdate records the latest time for all updater under one distro have been checked for new vulns
// updates all existing updaters with that distro with the new time
func recordNothingToUpdate(ctx context.Context, pool *pgxpool.Pool, distro string, updateTime time.Time) error {
	const (
		update = `UPDATE updaters_last_run
		SET last_successful_run = $1
		WHERE distro = $2
		RETURNING updater_name;`
	)

	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "internal/vulnstore/postgres/recordNothingToUpdate"))

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("unable to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var updaterName string

	if err := pool.QueryRow(ctx, update, updateTime, distro).Scan(&updaterName); err != nil {
		return fmt.Errorf("failed to update all last update times for distro rhel: %w", err)
	}

	zlog.Debug(ctx).
		Str("updater", "rhel").
		Msg("Last checked time updated for all rhel updaters")

	return nil
}
