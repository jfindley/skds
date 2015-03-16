package functions

import (
	"flag"
	"github.com/codegangsta/cli"
	"strings"
	"testing"

	// "github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestSecretList(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	var resp shared.Message
	resp.Key.Name = "test"

	ts := testGet(200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	ctx := cli.NewContext(app, fs, nil)

	ok := SecretList(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}
