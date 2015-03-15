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

	resp, err := cfg.Session.Get("/key/public/get/super")
	if err != nil {
		cfg.Log(log.ERROR, "Unable to fetch super-group pubkey:", err)
		return
	}

	if len(resp) != 1 {
		cfg.Log(log.ERROR, "Bad response from server")
		return
	}

	pubKey := new(crypto.Key)
	pubKey.Pub = new([32]byte)

	for i := range resp[0].Key.Key {
		pubKey.Pub[i] = resp[0].Key.Key[i]
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

	msg.Key.GroupPriv, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, pubKey)
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

	cfg.Log(log.INFO, "Group name\t\t", "Group type")
	for i := range resp {
		gtype := "client"
		if resp[i].User.Admin {
			gtype = "admin"
		}
		cfg.Log(log.INFO, resp[i].User.Group, "\t\t", gtype)
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

	var msg shared.Message

	msg.User.Name = name
	msg.User.Admin = admin

	resp, err := cfg.Session.Post("/key/public/get/user", msg)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to fetch user pubkey:", err)
		return
	}

	if len(resp) != 1 {
		cfg.Log(log.ERROR, "Bad response from server")
		return
	}

	if resp[0].Key.UserKey == nil {
		cfg.Log(log.ERROR, "User does not have a public key set")
		return
	}

	pubKey := new(crypto.Key)
	pubKey.Pub = new([32]byte)

	for i := range resp[0].Key.UserKey {
		pubKey.Pub[i] = resp[0].Key.UserKey[i]
	}

	msg = shared.Message{}
	msg.User.Admin = admin
	msg.User.Group = group

	resp, err = cfg.Session.Post("/key/private/get/group", msg)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to fetch group privkey:", err)
		return
	}

	if len(resp) != 1 {
		cfg.Log(log.ERROR, "Bad response from server")
		return
	}

	msg.Key.GroupPriv, err = crypto.Encrypt(resp[0].Key.GroupPriv, cfg.Runtime.Keypair, pubKey)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to encrypt group key")
		return
	}

	msg.User.Group = group

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}
