package main

import (
	"os"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/transport"
)

func Setup(cfg *config.Config) (err error) {
	// TODO: we should ship a default config file instead
	loadDefaults(cfg)

	_, err = os.Stat(cfg.Startup.Dir)
	if os.IsNotExist(err) {
		err = os.Mkdir(cfg.Startup.Dir, 0700)
		if err != nil {
			return
		}
	}
	err = cfg.Startup.Write(cfg.File)
	if err != nil {
		return
	}

	cfg.Runtime.Key, err = crypto.GenKey(2048)
	if err != nil {
		return
	}
	cfg.Log(3, "Generated secret key")

	// Temporary self-signed cert
	cfg.Runtime.Cert, err = crypto.GenCert(
		"Registration cert",
		true,
		false,
		1,
		&cfg.Runtime.Key.PublicKey,
		cfg.Runtime.Key,
		nil,
	)
	if err != nil {
		return
	}

	cfg.Log(3, "Connecting to server to retrieve CA Cert...")
	cfg.Runtime.Client, err = transport.ClientInit(cfg)
	if err != nil {
		return
	}
	cfg.Runtime.CACert, err = GetCa(cfg)
	if err != nil {
		return
	}
	err = cfg.WriteFiles(config.CACert(), config.Key())
	if err != nil {
		return
	}

	cfg.Log(3, "Generating unique encryption keys...")
	cfg.Runtime.PublicKey, cfg.Runtime.PrivateKey, err = crypto.GenerateKeypair()
	if err != nil {
		cfg.Fatal("Failed to generate a new secret key", err)
	}

	cfg.Log(3, "Connecting to server to register")
	cfg.Runtime.Client, err = transport.ClientInit(cfg)
	if err != nil {
		return
	}
	cfg.Runtime.Cert, err = Register(cfg)
	if err != nil {
		return
	}
	err = cfg.Runtime.Cert.CheckSignatureFrom(cfg.Runtime.CACert)
	if err != nil {
		return
	}
	err = cfg.WriteFiles(config.Cert(), config.PublicKey(), config.PrivateKey())
	if err != nil {
		return
	}
	cfg.Option(config.CAPool())
	cfg.Log(3, "Reconnecting to server with the signed cert")
	cfg.Runtime.Client, err = transport.ClientInit(cfg)
	if err != nil {
		return
	}
	return
}

func loadDefaults(cfg *config.Config) {
	cfg.Startup.Name = "client1.skds.com"
	cfg.Startup.Address = "server.skds.com:8443"
	cfg.Startup.Crypto.CACert = "ca.crt"
	cfg.Startup.Crypto.Cert = "admin.crt"
	cfg.Startup.Crypto.Key = "admin.key"
	cfg.Startup.Crypto.PrivateKey = "priv_key"
	cfg.Startup.Crypto.PublicKey = "pub_key"
}
