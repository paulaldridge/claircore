package migrations

const (
	// this migration modifies the database to add a
	// delete cascade constraint to the enrichments FKs
	migration6 = `
-- updaters_last_run is a table keeping a record of when the updaters were last successfully checked for new vulnerabilities
CREATE TABLE IF NOT EXISTS updaters_last_run (
	updater_name TEXT NOT NULL,
	last_successful_run TIMESTAMP WITH TIME ZONE DEFAULT now(),
	distro TEXT
);
`
)
