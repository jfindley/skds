package functions

import (
	"bufio"
	"code.google.com/p/gopass"
	"github.com/codegangsta/cli"
	"os"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func Password(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	for {

		var newPass string
		var confirm string

		if (fi.Mode() & os.ModeCharDevice) == 0 {

			// STDIN is not a terminal, do not use gopass

			reader := bufio.NewReader(os.Stdin)
			cfg.Log(log.INFO, "Please enter a new password:")
			newPass, _ = reader.ReadString('\n')

			cfg.Log(log.INFO, "Please enter the password again:")

			confirm, _ = reader.ReadString('\n')

		} else {

			// STDIN is a terminal, use gopass to hide input

			newPass, err = gopass.GetPass("Please enter a new password:\n")
			if err != nil {
				cfg.Log(log.ERROR, err)
				return
			}

			confirm, err = gopass.GetPass("Please enter the password again:\n")
			if err != nil {
				cfg.Log(log.ERROR, err)
				return
			}

		}

		if newPass != confirm {
			cfg.Log(log.ERROR, "Passwords do not match, please try again")
			continue
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

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	return true
}

func SetPubKey(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	var msg shared.Message
	msg.User.Key = cfg.Runtime.Keypair.Pub[:]

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
	name := ctx.String("name")

	if name == "" {
		cfg.Log(log.ERROR, "Name is required")
		return
	}

	if cfg.Session.GroupKey == nil {
		cfg.Log(log.ERROR, "No groupkey in session")
		return
	}

	superKey, err := crypto.Decrypt(cfg.Session.GroupKey, cfg.Runtime.Keypair)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to decrypt super key")
		return
	}

	defer crypto.Zero(superKey)

	pubKey, err := userPubKey(cfg, name, true)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	var msg shared.Message

	msg.Key.GroupPriv, err = crypto.Encrypt(superKey, cfg.Runtime.Keypair, &pubKey)
	if err != nil {
		cfg.Log(log.ERROR, "Unable to encrypt super-key for", name)
		return
	}

	msg.User.Name = name
	msg.User.Admin = true

	_, err = cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func UserDel(cfg *shared.Config, ctx *cli.Context, url string) (ok bool) {
	name := ctx.String("name")
	admin := ctx.Bool("admin")

	if name == "" {
		cfg.Log(log.ERROR, "Name is required")
		return
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

	cfg.Log(log.INFO, "Name\t\t\t", "Group")
	for i := range resp {
		cfg.Log(log.INFO, resp[i].User.Name, "\t\t\t", resp[i].User.Group)
	}

	return true
}
