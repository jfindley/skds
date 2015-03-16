package functions

import (
	"github.com/codegangsta/cli"

	// "github.com/jfindley/skds/crypto"
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
