package main

import (
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func setup(cfg *shared.Config) (err error) {

	cfg.Log(log.DEBUG, "Creating CA key")
	err = cfg.Runtime.CAKey.Generate()
	if err != nil {
		return
	}
	err = shared.Write(cfg.Runtime.CAKey, cfg.Startup.Crypto.CAKey)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Creating CA cert")
	err = cfg.Runtime.CACert.Generate(
		"SKDS CA",
		true,
		10,
		cfg.Runtime.CAKey.Public(),
		cfg.Runtime.CAKey,
		nil)
	if err != nil {
		return
	}
	err = shared.Write(cfg.Runtime.CACert, cfg.Startup.Crypto.CACert)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Creating server key")
	err = cfg.Runtime.Key.Generate()
	if err != nil {
		return
	}
	err = shared.Write(cfg.Runtime.Key, cfg.Startup.Crypto.Key)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Creating server cert")
	err = cfg.Runtime.Cert.Generate(
		cfg.Startup.Hostname,
		false,
		5,
		cfg.Runtime.Key.Public(),
		cfg.Runtime.CAKey,
		cfg.Runtime.CACert)
	if err != nil {
		return
	}
	err = shared.Write(cfg.Runtime.Cert, cfg.Startup.Crypto.Cert)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Creating database tables")
	err = db.InitTables(cfg.DB)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Creating default users and group")
	err = db.CreateDefaults(cfg.DB)
	if err != nil {
		return
	}

	cfg.Log(log.INFO, "First-run install complete")
	return
}
