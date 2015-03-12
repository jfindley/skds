package functions

import (
	"code.google.com/p/gopass"
	"github.com/codegangsta/cli"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func Password(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	for {
		newPass, err := gopass.GetPass("Please enter a new password:\n")
		if err != nil {
			cfg.Log(log.ERROR, err)
			return
		}

		if cfg.Runtime.Password.Compare([]byte(newPass)) {
			cfg.Log(log.ERROR, "Password must not match previous password")
			continue
		}

		if len(newPass) < crypto.MinPasswordLen {
			cfg.Log(log.ERROR, "Password too short")
			continue
		}

		cfg.Runtime.Password = []byte(newPass)
		break
	}

	var msg shared.Message
	msg.User.Password = cfg.Runtime.Password

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	return true
}

func AdminNew(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")

	if name == "" {
		cfg.Log(log.ERROR, "Name is required")
		return
	}

	var msg shared.Message
	msg.User.Name = name

	resp, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	if len(resp) != 1 {
		cfg.Log(log.ERROR, "Did not recieve valid response from server")
		return
	}

	cfg.Log(log.INFO, "New admin user created:", resp[0].User.Name)
	cfg.Log(log.INFO, "User's password is:", string(resp[0].User.Password))

	return true
}

func AdminSuper(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	return true
}

func UserDel(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Name is required")
	}

	var msg shared.Message
	msg.User.Name = name
	msg.User.Admin = admin

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func UserList(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	admin := ctx.Bool("admin")

	var msg shared.Message
	msg.User.Admin = admin

	resp, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	cfg.Log(log.INFO, "Name\t\t", "Group")
	for i := range resp {
		cfg.Log(log.INFO, resp[i].User.Name, "\t\t", resp[i].User.Group)
	}

	return true
}
