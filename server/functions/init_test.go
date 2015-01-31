package functions

// This sets up the various common parts for the tests in this package

import (
    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/crypto"
    "github.com/jfindley/skds/server/auth"
    "github.com/jfindley/skds/server/db"
)

var (
    err        error
    cfg        *config.Config
    testPass   []byte
    testSecret db.MasterSecrets
    testKey    crypto.Key
    testAdmin  db.Admins
    authobj    *auth.AuthObject
)

func init() {
    cfg = new(config.Config)
    authobj = new(auth.AuthObject)

    cfg.Startup.DB.Database = "skds_test"
    cfg.Startup.DB.Host = "localhost"
    cfg.Startup.DB.User = "root"

    authobj.Admin = true
    authobj.UID = 1
    authobj.Super = true
    authobj.GID = 3
}

func setupDB(cfg *config.Config) error {
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
