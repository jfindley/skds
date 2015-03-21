package functions

import (
	"flag"
	"github.com/codegangsta/cli"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestAdminNew(t *testing.T) {
	var expected shared.Message
	var resp shared.Message

	expected.User.Name = "new admin user"

	resp.User.Name = expected.User.Name
	resp.User.Password = []byte("sdjfh2374ykdsf")

	ts := testPost(expected, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	*name = expected.User.Name

	ctx := cli.NewContext(app, fs, nil)

	ok := AdminNew(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestAdminSuper(t *testing.T) {
	var userKey crypto.Key
	var err error

	err = userKey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var exp shared.Message
	exp.User.Name = "test admin"
	exp.User.Admin = true

	var resp shared.Message
	resp.Key.UserKey = userKey.Pub[:]

	pubKeyReq := reqDef{
		expected:  &exp,
		code:      200,
		url:       "/key/public/get/user",
		responses: []shared.Message{resp},
	}

	// Don't try and check the contents of this request, as it varies each time.
	superReq := reqDef{
		code: 204,
		url:  "/test",
	}

	ts := multiRequest(pubKeyReq, superReq)

	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	*name = "test admin"

	ctx := cli.NewContext(app, fs, nil)

	ok := AdminSuper(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestUserDel(t *testing.T) {
	var expected shared.Message
	expected.User.Name = "admin user"
	expected.User.Admin = true

	ts := testPost(expected, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	admin := fs.Bool("admin", false, "")
	*name = "admin user"
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := UserDel(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestUserList(t *testing.T) {
	var expected shared.Message
	expected.User.Admin = true

	var resp1 shared.Message
	var resp2 shared.Message
	resp1.User.Name = "user1"
	resp1.User.Group = "default"

	resp2.User.Name = "user2"
	resp2.User.Group = "new group"

	ts := testPost(expected, 200, resp1, resp2)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	admin := fs.Bool("admin", false, "")
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := UserList(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}
