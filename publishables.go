package oauth2

import (
	"path/filepath"

	"github.com/lemmego/api/app"
	"github.com/lemmego/api/utils"
)

// Publish tags. They are what `lemmego publish --tags` selects on.
const (
	TagConfig     = "config"
	TagMigrations = "migrations"
)

// AddPublishables offers this package's configuration and migration to the
// project, so `lemmego publish` is the one familiar way to get them.
//
// The migration is published rather than run at boot because the schema is
// something the application owns: published, it can be read, edited, rolled
// back alongside every other migration, and found in schema_migrations where
// an operator expects it. Creating the tables silently at startup would put
// five tables in someone's database that nothing in their project mentions.
//
// Paths come from the project's configured directories rather than the
// conventional ones, so a project that moved its migrations gets its files
// where it asked for them. queue and cache both hardcode these and would
// write to the wrong place in such a project.
func (p *Provider) AddPublishables() []*app.Publishable {
	return []*app.Publishable{
		{
			FilePath: filepath.Join(utils.ConfigPath(), "oauth.go"),
			Content:  []byte(ConfigStub),
			Tag:      TagConfig,
		},
		{
			FilePath: filepath.Join(utils.MigrationPath(),
				MigrationVersion+"_create_oauth2_tables.go"),
			Content: []byte(MigrationStub),
			Tag:     TagMigrations,
		},
	}
}
