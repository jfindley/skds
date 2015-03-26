package functions

import (
	"github.com/codegangsta/cli"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func GroupNew(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Name is required")
		return
	}

	pubKey, err := superPubKey(cfg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	var msg shared.Message
	msg.User.Group = name
	msg.User.Admin = admin

	var key crypto.Key
	err = key.Generate()
	if err != nil {
		cfg.Log(log.ERROR, "Unable to generate group key")
		return
	}

	defer key.Zero()

	msg.Key.GroupPriv, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, &pubKey)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to encrypt group key")
		return
	}

	msg.Key.GroupPub = key.Pub[:]

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func GroupDel(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Group name is required")
		return
	}

	var msg shared.Message
	msg.User.Group = name
	msg.User.Admin = admin

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	return true
}

func GroupList(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	resp, err := cfg.Session.Get(url)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	cfg.Log(log.INFO, "Group name\t\t\t", "Group type")
	for i := range resp {
		gtype := "client"
		if resp[i].User.Admin {
			gtype = "admin"
		}
		cfg.Log(log.INFO, resp[i].User.Group, "\t\t\t", gtype)
	}
	return true
}

func UserGroupAssign(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	group := ctx.String("group")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "User name is required")
		return
	}

	if group == "" {
		cfg.Log(log.ERROR, "Group name is required")
		return
	}

	pubKey, err := userPubKey(cfg, name, admin)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	privKey, err := groupPrivKey(cfg, group, admin)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	var msg shared.Message

	msg.Key.GroupPriv, err = crypto.Encrypt(privKey.Priv[:], cfg.Runtime.Keypair, &pubKey)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to encrypt group key")
		return
	}

	msg.User.Admin = admin
	msg.User.Name = name
	msg.User.Group = group

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}
