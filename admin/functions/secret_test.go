package functions

import (
	"flag"
	"github.com/codegangsta/cli"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestSecretList(t *testing.T) {
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

func TestSecretListUser(t *testing.T) {
	var resp shared.Message
	resp.Key.Name = "test"

	var exp shared.Message
	exp.User.Name = "test"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	*name = "test"

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretListUser(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretListGroup(t *testing.T) {
	var resp shared.Message
	resp.Key.Name = "test"

	var exp shared.Message
	exp.User.Group = "test"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	group := fs.String("name", "", "")
	*group = "test"

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretListGroup(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretNew(t *testing.T) {
	key := new(crypto.Key)
	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var resp shared.Message
	resp.Key.Key = key.Pub[:]

	pubKeyReq := reqDef{
		code:      200,
		url:       "/key/public/get/super",
		responses: []shared.Message{resp},
	}

	// Don't try and check the contents of this request, as it varies each time.
	secretReq := reqDef{
		code: 204,
		url:  "/test",
	}

	ts := multiRequest(pubKeyReq, secretReq)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	file := fs.String("file", "", "")

	*name = "test secret"

	fh, err := ioutil.TempFile(os.TempDir(), "admin_secret")
	if err != nil {
		t.Fatal(err)
	}

	*file = fh.Name()

	_, err = fh.WriteString("secret data")
	if err != nil {
		t.Fatal(err)
	}

	err = fh.Close()
	if err != nil {
		t.Fatal(err)
	}

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretNew(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}

}
