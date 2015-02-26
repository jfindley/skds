package functions

// This sets up the various common parts for the tests in this package

import (
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

var (
	err        error
	cfg        *shared.Config
	testPass   []byte
	testSecret db.MasterSecrets
	testKey    crypto.Key
	testAdmin  db.Users
	authobj    *auth.SessionInfo
)

func init() {
	cfg = new(shared.Config)
	authobj = new(auth.SessionInfo)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"

	authobj.Admin = true
	authobj.UID = 1
	authobj.Super = true
	authobj.GID = 3
}

func setupDB(cfg *shared.Config) error {
	err := cfg.DBConnect()
	if err != nil {
		return err
	}

	err = db.InitDB(cfg)
	if err != nil {
		return err
	}
	err = db.CreateDefaults(cfg)
	if err != nil {
		return err
	}
	return nil
}
