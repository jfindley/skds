package functions

// This sets up the various common parts for the tests in this package

import (
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

var (
	cfg *shared.Config
)

func init() {
	cfg = new(shared.Config)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"
	cfg.Startup.DB.Driver = "mysql"
}

func setupDB(cfg *shared.Config) (err error) {
	cfg.DB, err = db.Connect(cfg.Startup.DB)
	if err != nil {
		return err
	}

	err = InitTables(cfg.DB)
	if err != nil {
		return err
	}
	err = db.CreateDefaults(cfg.DB)
	if err != nil {
		return err
	}
	return nil
}
