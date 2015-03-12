package main

import (
	"crypto/rand"
	"errors"
	"io"
	"os"

	"github.com/jfindley/skds/client/functions"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func setup(cfg *shared.Config) (err error) {

	var success bool

	// Remove all created files on exit if something goes wrong.
	defer func() {
		if !success {
			cleanup(cfg)
		}
	}()

	err = os.Mkdir(cfg.Startup.Dir, os.FileMode(0700))
	if err != nil && !os.IsExist(err) {
		return
	}

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

	err = shared.Write(cfg.Runtime.Keypair, cfg.Startup.Crypto.KeyPair)
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Fetching server CA Cert")
	ok := functions.GetCA(cfg)
	if !ok {
		return errors.New("Failed to fetch server cert")
	}

	cfg.Log(log.INFO, "Registering with server")
	ok = functions.Register(cfg)
	if !ok {
		return errors.New("Failed to register with server")
	}

	cfg.Log(log.INFO, "First-run setup complete")
	success = true
	return
}

func cleanup(cfg *shared.Config) {
	cfg.Log(log.WARN, "Setup failed, performing cleanup")

	// We just log if an error occurs - there is nothing more we can do.

	err := os.Remove(cfg.Startup.Crypto.Password)
	if err != nil && !os.IsNotExist(err) {
		cfg.Log(log.ERROR, err)
	}

	err = os.Remove(cfg.Startup.Crypto.KeyPair)
	if err != nil && !os.IsNotExist(err) {
		cfg.Log(log.ERROR, err)
	}

	err = os.Remove(cfg.Startup.Crypto.CACert)
	if err != nil && !os.IsNotExist(err) {
		cfg.Log(log.ERROR, err)
	}
}
