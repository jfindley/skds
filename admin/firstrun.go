package main

import (
	"crypto/x509"
	"os"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/messages"
	"github.com/jfindley/skds/shared"
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
	err = cfg.Startup.Write("skds.conf")
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
	err = cfg.WriteFiles(config.CACert())
	if err != nil {
		return
	}

	cfg.Log(3, "Generating unique encryption keys...")
	err = cfg.Runtime.Keypair.Generate()
	if err != nil {
		cfg.Fatal("Failed to generate a new secret key", err)
	}

	err = cfg.WriteFiles(config.PublicKey(), config.PrivateKey())
	if err != nil {
		return
	}
	cfg.Option(config.CAPool())
	cfg.Runtime.Client, err = transport.ClientInit(cfg)
	if err != nil {
		return
	}
	cfg.Log(3, "Creating supergroup keys")
	err = SuperKeys(cfg)
	if err != nil {
		return
	}
	return
}

func loadDefaults(cfg *config.Config) {
	cfg.Startup.Name = "default_admin"
	cfg.Startup.Address = "server.skds.com:8443"
	cfg.Startup.Crypto.CACert = "ca.crt"
	cfg.Startup.Crypto.PrivateKey = "priv_key"
	cfg.Startup.Crypto.PublicKey = "pub_key"
	cfg.Startup.User = "admin"
}

func GetCa(cfg *config.Config) (*x509.Certificate, error) {
	resp, err := transport.Request(cfg, "/ca", nil)
	if err != nil {
		return nil, err
	}
	return shared.CertDecode(resp.X509.Cert)
}

func SuperKeys(cfg *config.Config) (err error) {
	var msg messages.Message
	// Set the default password
	cfg.Runtime.Password = []byte("password")

	err = transport.NewAdminSession(cfg)
	if err != nil {
		cfg.Log(0, err)
		return
	}

	key := new(crypto.Key)
	err = key.Generate()
	if err != nil {
		cfg.Log(0, err)
	}
	defer key.Zero()
	msg.Key.GroupPub = key.Pub[:]
	msg.Key.GroupPriv = key.Priv[:]
	_, err = transport.Request(cfg, "/setup", msg)
	return
}
