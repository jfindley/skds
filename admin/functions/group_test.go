package functions

import (
	"flag"
	"github.com/codegangsta/cli"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestGroupNew(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	key := new(crypto.Key)
	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Runtime.Keypair.Generate()
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
	groupReq := reqDef{
		code: 204,
		url:  "/test",
	}

	ts := multiRequest(pubKeyReq, groupReq)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	admin := fs.Bool("admin", false, "")
	*name = "test group"
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := GroupNew(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestGroupDel(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	var expected shared.Message
	expected.User.Group = "test group"
	expected.User.Admin = true

	ts := testPost(expected, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	admin := fs.Bool("admin", false, "")
	*name = expected.User.Group
	*admin = expected.User.Admin

	ctx := cli.NewContext(app, fs, nil)

	ok := GroupDel(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestGroupList(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	var resp shared.Message
	resp.User.Group = "test group"
	resp.User.Admin = true

	ts := testGet(200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	ctx := cli.NewContext(app, fs, nil)

	ok := GroupList(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestUserGroupAssign(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	key := new(crypto.Key)
	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Runtime.Keypair.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var resp shared.Message
	resp.Key.UserKey = key.Pub[:]

	var exp shared.Message
	exp.User.Name = "test user"
	exp.User.Admin = true

	pubKeyReq := reqDef{
		expected:  &exp,
		code:      200,
		url:       "/key/public/get/user",
		responses: []shared.Message{resp},
	}

	var privexp shared.Message
	privexp.User.Group = "test group"
	privexp.User.Admin = true

	var privresp shared.Message
	privresp.Key.GroupPriv, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, key)
	if err != nil {
		t.Fatal(err)
	}

	privKeyReq := reqDef{
		expected:  &privexp,
		code:      200,
		url:       "/key/private/get/group",
		responses: []shared.Message{privresp},
	}

	// Don't try and check the contents of this request, as it varies each time.
	groupAssign := reqDef{
		code: 204,
		url:  "/test",
	}

	ts := multiRequest(pubKeyReq, privKeyReq, groupAssign)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	group := fs.String("group", "", "")
	admin := fs.Bool("admin", false, "")
	*name = "test user"
	*group = "test group"
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := UserGroupAssign(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}
