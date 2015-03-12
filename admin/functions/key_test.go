package functions

import (
	"flag"
	"github.com/codegangsta/cli"
	"strings"
	"testing"
)

// There's very little we can do to test this function
// as the request is random, and it expects no response.
func TestSetSuperKey(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	cfg.Runtime.Keypair.Generate()

	ts := testGet(204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)

	ctx := cli.NewContext(app, fs, nil)

	ok := SetSuperKey(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}
