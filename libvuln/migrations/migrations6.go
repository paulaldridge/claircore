package migrations

const (
	// this migration modifies the database to add a
	// table to record update times
	migration6 = `
-- update_time is a table keeping a record of when updaters were last checked for new vulnerabilities
CREATE TABLE IF NOT EXISTS update_time (
	updater_name TEXT PRIMARY KEY,
	last_update_time TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- update_time is a table keeping a record of when updaters were last checked for new vulnerabilities
CREATE TABLE IF NOT EXISTS updater_status (
	updater_name TEXT PRIMARY KEY,
	last_update TIMESTAMP WITH TIME ZONE DEFAULT now(),
	last_success TIMESTAMP WITH TIME ZONE,
	success BOOL,
    fingerprint TEXT,
    error TEXT
);
`
)

// 1. Update runs, finds new vulns, successful adds vulns to db - last_attempt, last_success, last_run_success=true, last_fingerprint
// 2. Update run, finds no new vulns - last_attempt, last_success, last_run_success=true, last_fingerprint?-depends if available
// 3. Update fails to run - last_attempt, last_run_success=false, last_fingerprint?-depends if available, err
