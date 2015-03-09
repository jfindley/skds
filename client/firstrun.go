package main

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/jfindley/skds/client/functions"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func setup(cfg *shared.Config) (err error) {

	// We don't use the standard crypto.NewPassword function, because
	// there's no reason for this to be human-readable.
	cfg.Log(log.DEBUG, "Generating a random password")

	cfg.Runtime.Password = make([]byte, 32) // 32 bits of random data is plenty.
	n, err := io.ReadFull(rand.Reader, cfg.Runtime.Password)
	if err != nil || n != 32 {
		return errors.New("Error generating password")
	}

	err = shared.Write(&cfg.Runtime.Password, cfg.Startup.Crypto.Password)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Generating keypair")
	err = cfg.Runtime.Keypair.Generate()
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Fetching server CA Cert")
	ok := functions.GetCA(cfg, "/ca")
	if !ok {
		return errors.New("Failed to fetch server cert")
	}

	cfg.Log(log.INFO, "Registering with server")
	ok = functions.Register(cfg, "/client/register")
	if !ok {
		return errors.New("Failed to register with server")
	}

	cfg.Log(log.INFO, "First-run setup complete")
	return
}
