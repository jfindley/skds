package functions

import (
	"flag"
	"github.com/codegangsta/cli"
	"strings"
	"testing"

	"github.com/jfindley/skds/shared"
)

func TestAdminNew(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	var expected shared.Message

	expected.User.Name = "new admin user"

	ts := testPost(expected, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("adminnew", flag.PanicOnError)
	name := fs.String("name", "", "")
	*name = expected.User.Name

	ctx := cli.NewContext(app, fs, nil)

	ok := AdminNew(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestUserDel(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	var expected shared.Message
	expected.User.Name = "admin user"
	expected.User.Admin = true

	ts := testPost(expected, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("adminnew", flag.PanicOnError)
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
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

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

	fs := flag.NewFlagSet("adminnew", flag.PanicOnError)
	admin := fs.Bool("admin", false, "")
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := UserList(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}
