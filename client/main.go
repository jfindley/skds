package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jfindley/skds/client/functions"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

var cfgFile string

func init() {
	flag.StringVar(&cfgFile, "f", "/etc/skds/client.conf", "Config file location.")
}

func readFiles(cfg *shared.Config) (install bool, err error) {

	err = shared.Read(cfg.Runtime.CA, cfg.Startup.Crypto.CACert)
	if os.IsNotExist(err) {
		install = true
	} else if err != nil {
		return
	}

	err = shared.Read(cfg.Runtime.Keypair, cfg.Startup.Crypto.KeyPair)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.KeyPair)
		}
	} else if err != nil {
		return
	}

	err = shared.Read(&cfg.Runtime.Password, cfg.Startup.Crypto.Password)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.KeyPair)
		}
	} else if err != nil {
		return
	}

	return install, nil
}

func main() {
	flag.Parse()

	cfg := new(shared.Config)
	cfg.NewClient()

	err := shared.Read(cfg, cfgFile)
	if err != nil {
		fmt.Println("Cannot read config file:", err)
		os.Exit(2)
	}

	err = cfg.StartLogging()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg.Log(log.DEBUG, "Reading keys and certificates from disk")
	install, err := readFiles(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	if cfg.Startup.Crypto.ServerCert == "" {
		cfg.Log(log.WARN, "Server certificate pinning disabled.  This is strongly discouraged.\n",
			"Please consider configuring a ServerCert location.")
	}

	cfg.Session.New(cfg)

	if install {
		cfg.Log(log.INFO, "Performing first-run install")
		err = setup(cfg)
		if err != nil {
			cfg.Fatal(err)
		}
	}

	err = cfg.Session.Login(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	ok := functions.GetSecrets(cfg, "/client/secrets")
	if !ok {
		os.Exit(1)
	}

	err = cfg.Session.Logout(cfg)
	if err != nil {
		cfg.Fatal(err)
	}
}
