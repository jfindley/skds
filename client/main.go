package main

import (
	"errors"
	"flag"
	"os"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/transport"
)

func loadConfig(cfg *config.Config) (err error) {

	// Ignore extra arguments
	initCfg, install, _ := config.ReadArgs()
	*cfg = initCfg

	if install {
		err = Setup(cfg)
		if err != nil {
			cfg.Fatal(err)
		}
		cfg.Log(2, "Setup complete")
		os.Exit(0)
	} else {
		_, err = os.Stat(cfg.File)
		if err != nil {
			err = errors.New("Cannot read config file")
			return
		}
		err = cfg.Startup.Read(cfg.File)
		if err != nil {
			err = errors.New("Cannot parse config file")
			return
		}

		flag.Visit(config.SetOverrides(cfg))

		// There's no situation where we don't need the private key,
		// so we load it at startup to simplify the Get function.
		err = cfg.ReadFiles(config.CACert(), config.PublicKey(),
			config.PrivateKey(), config.Key(), config.Cert())
		if err != nil {
			return
		}
		cfg.Runtime.Client, err = transport.ClientInit(cfg)

	}
	return
}

func main() {
	cfg := new(config.Config)
	err := loadConfig(cfg)
	if err != nil {
		cfg.Fatal(err)
	}
	err = Get(cfg)
	if err != nil {
		cfg.Log(2, err)
	}
}
