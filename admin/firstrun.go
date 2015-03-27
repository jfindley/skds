// +build linux darwin

package main

import (
	"bufio"
	"code.google.com/p/gopass"
	"errors"
	"fmt"
	"github.com/codegangsta/cli"
	"os"
	"strings"

	"github.com/jfindley/skds/admin/functions"
	client "github.com/jfindley/skds/client/functions"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func setup(cfg *shared.Config, ctx *cli.Context) (err error) {

	var success bool

	// Remove all created files on exit if something goes wrong.
	defer func() {
		if !success {
			cleanup(cfg)
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter your username:")
	user, _ := reader.ReadString('\n')

	pass, err := gopass.GetPass("Please enter your password:\n")
	if err != nil {
		cfg.Fatal(err)
	}
	cfg.Runtime.Password = []byte(pass)

	fmt.Println("Enter the server hostname:")
	hostname, _ := reader.ReadString('\n')

	fmt.Println("Enter the server port (default 8443):")
	port, _ := reader.ReadString('\n')

	cfg.Startup.Address = strings.TrimSuffix(hostname, "\n") + ":" + strings.TrimSuffix(port, "\n")
	cfg.Startup.NodeName = strings.TrimSuffix(user, "\n")

	err = os.Mkdir(cfg.Startup.Dir, os.FileMode(0700))
	if err != nil && !os.IsExist(err) {
		return
	}

	cfg.Log(log.DEBUG, "Writing config file")
	err = shared.Write(cfg, cfgFile(cfg, "admin.conf"))
	if err != nil {
		return
	}

	cfg.Log(log.DEBUG, "Generating keypair")
	err = cfg.Runtime.Keypair.Generate()
	if err != nil {
		return
	}

	err = shared.Write(cfg.Runtime.Keypair, cfg.Startup.Crypto.KeyPair)
	if err != nil {
		return
	}

	cfg.Session.New(cfg)

	cfg.Log(log.DEBUG, "Fetching server CA Cert")
	ok := client.GetCA(cfg)
	if !ok {
		return errors.New("Failed to fetch server cert")
	}

	err = cfg.Session.Login(cfg)
	if err != nil {
		return
	}

	cfg.Log(log.INFO, "Logged in")

	ok = functions.Password(cfg, ctx, "/admin/password")
	if !ok {
		return errors.New("Failed to change password")
	}

	ok = functions.SetPubKey(cfg, ctx, "/key/public/set")
	if !ok {
		return errors.New("Failed to set public key")
	}

	cfg.Log(log.INFO, "First-run setup complete")
	cfg.Log(log.INFO, "If this is a fresh installation, please run:")
	cfg.Log(log.INFO, "key private set super")
	cfg.Log(log.INFO, "to set the the super-user key")
	success = true
	return
}

func cleanup(cfg *shared.Config) {
	cfg.Log(log.WARN, "Setup failed, performing cleanup")

	// We just log if an error occurs - there is nothing more we can do.

	err := os.Remove(cfgFile(cfg, "admin.conf"))
	if err != nil && !os.IsNotExist(err) {
		cfg.Log(log.ERROR, err)
	}

	err = os.Remove(cfg.Startup.Crypto.KeyPair)
	if err != nil && !os.IsNotExist(err) {
		cfg.Log(log.ERROR, err)
	}

	err = os.Remove(cfg.Startup.Crypto.CACert)
	if err != nil && !os.IsNotExist(err) {
		cfg.Log(log.ERROR, err)
	}
	os.Exit(2)
}
