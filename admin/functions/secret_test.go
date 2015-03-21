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

func TestSecretDel(t *testing.T) {
	var exp shared.Message
	exp.Key.Name = "test"

	ts := testPost(exp, 200)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	*name = exp.Key.Name

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretDel(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretUpdate(t *testing.T) {
	key := new(crypto.Key)
	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var resp shared.Message
	resp.Key.Key = key.Pub[:]

	pubKeyReq := reqDef{
		code:      200,
		url:       "/key/public/get/secret",
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

	ok := SecretUpdate(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretAssignUser(t *testing.T) {
	pubKey := new(crypto.Key)
	err := pubKey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var pubResp shared.Message
	pubResp.Key.Key = pubKey.Pub[:]

	pubKeyReq := reqDef{
		code:      200,
		url:       "/key/public/get/user",
		responses: []shared.Message{pubResp},
	}

	key := new(crypto.Key)
	key.Generate()

	var secretResp shared.Message

	secretResp.Key.Secret, err = crypto.Encrypt([]byte("test data"), key, key)
	if err != nil {
		t.Fatal(err)
	}

	secretResp.Key.UserKey, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, cfg.Runtime.Keypair)
	if err != nil {
		t.Fatal(err)
	}

	secretReq := reqDef{
		code:      200,
		url:       "/secret/get",
		responses: []shared.Message{secretResp},
	}

	// Don't try and check the contents of this request, as it varies each time.
	assignReq := reqDef{
		code: 204,
		url:  "/test",
	}

	ts := multiRequest(pubKeyReq, secretReq, assignReq)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	secret := fs.String("secret", "", "")
	path := fs.String("path", "", "")
	admin := fs.Bool("admin", false, "")

	*name = "test user"
	*secret = "test secret"
	*path = ""
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretAssignUser(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretAssignGroup(t *testing.T) {
	pubKey := new(crypto.Key)
	err := pubKey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	var pubResp shared.Message
	pubResp.Key.Key = pubKey.Pub[:]

	pubKeyReq := reqDef{
		code:      200,
		url:       "/key/public/get/group",
		responses: []shared.Message{pubResp},
	}

	key := new(crypto.Key)
	key.Generate()

	var secretResp shared.Message

	secretResp.Key.Secret, err = crypto.Encrypt([]byte("test data"), key, key)
	if err != nil {
		t.Fatal(err)
	}

	secretResp.Key.UserKey, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, cfg.Runtime.Keypair)
	if err != nil {
		t.Fatal(err)
	}

	secretReq := reqDef{
		code:      200,
		url:       "/secret/get",
		responses: []shared.Message{secretResp},
	}

	// Don't try and check the contents of this request, as it varies each time.
	assignReq := reqDef{
		code: 204,
		url:  "/test",
	}

	ts := multiRequest(pubKeyReq, secretReq, assignReq)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	secret := fs.String("secret", "", "")
	path := fs.String("path", "", "")
	admin := fs.Bool("admin", false, "")

	*name = "test group"
	*secret = "test secret"
	*path = ""
	*admin = true

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretAssignGroup(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretRemoveUser(t *testing.T) {
	var exp shared.Message
	exp.User.Name = "test user"
	exp.User.Admin = true
	exp.Key.Name = "test secret"

	ts := testPost(exp, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	secret := fs.String("secret", "", "")
	admin := fs.Bool("admin", false, "")

	*name = exp.User.Name
	*secret = exp.Key.Name
	*admin = exp.User.Admin

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretRemoveUser(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}

func TestSecretRemoveGroup(t *testing.T) {
	var exp shared.Message
	exp.User.Group = "test user"
	exp.User.Admin = true
	exp.Key.Name = "test secret"

	ts := testPost(exp, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	app := cli.NewApp()

	fs := flag.NewFlagSet("testing", flag.PanicOnError)
	name := fs.String("name", "", "")
	secret := fs.String("secret", "", "")
	admin := fs.Bool("admin", false, "")

	*name = exp.User.Group
	*secret = exp.Key.Name
	*admin = exp.User.Admin

	ctx := cli.NewContext(app, fs, nil)

	ok := SecretRemoveGroup(cfg, ctx, "/test")
	if !ok {
		t.Fatal("Failed")
	}
}
