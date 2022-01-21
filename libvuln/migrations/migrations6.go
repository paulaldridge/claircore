package migrations

const (
	// this migration modifies the database to add a
	// tabele to record update times
	migration6 = `
-- update_times is a table keeping a record of when the updaters were last successfully checked for new vulnerabilities
CREATE TABLE IF NOT EXISTS update_time (
	updater_name TEXT PRIMARY KEY,
	last_update_time TIMESTAMP WITH TIME ZONE DEFAULT now()
);
`
)
