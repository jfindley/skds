package functions

import (
	"github.com/codegangsta/cli"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func SetSuperKey(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	superKey := new(crypto.Key)

	err := superKey.Generate()
	if err != nil {
		cfg.Log(log.ERROR, "Failed to generate super-key")
		return
	}

	defer superKey.Zero()

	// We encrypt the private part of the key with our own key
	data, err := crypto.Encrypt(superKey.Priv[:], cfg.Runtime.Keypair, cfg.Runtime.Keypair)
	if err != nil {
		cfg.Log(log.ERROR, "Failed to encrypt super-key")
		return
	}

	var msg shared.Message

	msg.Key.GroupPriv = data
	msg.Key.GroupPub = superKey.Pub[:]

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}
