package functions

import (
	"github.com/codegangsta/cli"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func SetSuperKey(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	key := new(crypto.Key)

	err := key.Generate()
	if err != nil {
		cfg.Log(log.ERROR, "Failed to generate super-key")
		return
	}

	defer key.Zero()

	// We encrypt the private part of the key with our own key
	data, err := crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, cfg.Runtime.Keypair)
	if err != nil {
		cfg.Log(log.ERROR, "Failed to encrypt super-key")
		return
	}

	var msg shared.Message

	msg.Key.GroupPriv = data
	msg.Key.GroupPub = key.Pub[:]

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	cfg.Log(log.DEBUG, "Logging out to update session with new key")
	err = cfg.Session.Logout(cfg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	err = cfg.Session.Login(cfg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	cfg.Log(log.DEBUG, "Logged in")

	return true
}
