package functions

import (
	"github.com/codegangsta/cli"
	"io/ioutil"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func SecretList(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	resp, err := cfg.Session.Get(url)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	cfg.Log(log.INFO, "Secret name")
	for i := range resp {
		cfg.Log(log.INFO, resp[i].Key.Name)
	}
	return true
}

func SecretListUser(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "User name is required")
		return
	}

	var msg shared.Message
	msg.User.Name = name
	msg.User.Admin = admin

	resp, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	cfg.Log(log.INFO, "Secret name\t\t\tSecret Path")
	for i := range resp {
		cfg.Log(log.INFO, resp[i].Key.Name, resp[i].Key.Path)
	}

	return true
}

func SecretListGroup(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Group name is required")
		return
	}

	var msg shared.Message
	msg.User.Group = name
	msg.User.Admin = admin

	resp, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	cfg.Log(log.INFO, "Secret name\t\t\tSecret Path")
	for i := range resp {
		cfg.Log(log.INFO, resp[i].Key.Name, resp[i].Key.Path)
	}

	return true
}

func SecretNew(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	file := ctx.String("file")

	if name == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	if file == "" {
		cfg.Log(log.ERROR, "Secret file is required")
		return
	}

	var msg shared.Message
	msg.Key.Name = name

	superKey, err := superPubKey(cfg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	defer crypto.Zero(data)

	key := new(crypto.Key)
	key.Generate()

	defer key.Zero()

	msg.Key.Secret, err = crypto.Encrypt(data, cfg.Runtime.Keypair, key)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	msg.Key.Key, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, &superKey)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	msg.Key.UserKey, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, cfg.Runtime.Keypair)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func SecretDel(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")

	if name == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	var msg shared.Message
	msg.Key.Name = name

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func SecretUpdate(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	file := ctx.String("file")

	if name == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	if file == "" {
		cfg.Log(log.ERROR, "Secret file is required")
		return
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	defer crypto.Zero(data)

	key, err := secretPubKey(cfg, name)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	var msg shared.Message

	msg.Key.Name = name

	msg.Key.Secret, err = crypto.Encrypt(data, cfg.Runtime.Keypair, &key)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func SecretAssignUser(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	secret := ctx.String("secret")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "User name is required")
		return
	}

	if secret == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	var msg shared.Message
	msg.Key.Name = secret
	msg.User.Name = name
	msg.User.Admin = admin

	pubKey, err := userPubKey(cfg, name, admin)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	data, err := secretGet(cfg, secret)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	msg.Key.Secret, err = crypto.Encrypt(data, cfg.Runtime.Keypair, &pubKey)
	if err != nil {
		// if Encrypt errored it may not have zeroed the data
		crypto.Zero(data)
		cfg.Log(log.ERROR, err)
		return
	}

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func SecretAssignGroup(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	secret := ctx.String("secret")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Group name is required")
		return
	}

	if secret == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	var msg shared.Message
	msg.Key.Name = secret
	msg.User.Group = name
	msg.User.Admin = admin

	pubKey, err := groupPubKey(cfg, name, admin)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	data, err := secretGet(cfg, secret)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	msg.Key.Secret, err = crypto.Encrypt(data, cfg.Runtime.Keypair, &pubKey)
	if err != nil {
		// if Encrypt errored it may not have zeroed the data
		crypto.Zero(data)
		cfg.Log(log.ERROR, err)
		return
	}

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func SecretRemoveUser(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	secret := ctx.String("secret")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "User name is required")
		return
	}

	if secret == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	var msg shared.Message
	msg.Key.Name = secret
	msg.User.Name = name
	msg.User.Admin = admin

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func SecretRemoveGroup(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	secret := ctx.String("secret")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Group name is required")
		return
	}

	if secret == "" {
		cfg.Log(log.ERROR, "Secret name is required")
		return
	}

	var msg shared.Message
	msg.Key.Name = secret
	msg.User.Group = name
	msg.User.Admin = admin

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}
