package functions

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestGetCA(t *testing.T) {
	cfg.NewClient()

	key := new(crypto.TLSKey)
	cert := new(crypto.TLSCert)

	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cert.Generate("test", true, 1, key.Public(), key, nil)
	if err != nil {
		t.Fatal(err)
	}

	var resp shared.Message
	resp.X509.Cert, err = cert.Encode()
	if err != nil {
		t.Fatal(err)
	}

	ts := testGet(200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	fh, err := ioutil.TempFile(os.TempDir(), "skds_client")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Startup.Crypto.CACert = fh.Name()

	defer os.Remove(cfg.Startup.Crypto.CACert)

	cfg.Session.New(cfg)

	ok := GetCA(cfg, "/ca")
	if !ok {
		t.Fatal("Failed to get CA")
	}

	data, err := ioutil.ReadFile(cfg.Startup.Crypto.CACert)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(resp.X509.Cert, data) != 0 {
		t.Error("Certificate does not match response.")
	}
}

func TestRegister(t *testing.T) {
	cfg.NewClient()
	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	err := cfg.Runtime.Keypair.Generate()
	if err != nil {
		t.Fatal(err)
	}

	cfg.Runtime.Password = []byte("test password")
	cfg.Startup.NodeName = "test client"

	var expected shared.Message

	expected.User.Name = cfg.Startup.NodeName
	expected.User.Admin = false
	expected.User.Password = cfg.Runtime.Password
	expected.User.Key = cfg.Runtime.Keypair.Pub[:]

	ts := testPost(expected, 204)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	ok := Register(cfg, "/client/register")
	if !ok {
		t.Fatal("Failed to register")
	}
}

func TestGetSecrets(t *testing.T) {
	cfg.NewClient()

	// Skip TLS hostname verification
	cfg.Runtime.CA = nil

	err := cfg.Runtime.Keypair.Generate()
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("secret data")

	super := new(crypto.Key)
	super.Generate()

	master := new(crypto.Key)
	master.Generate()

	group := new(crypto.Key)
	group.Generate()

	masterSec, err := crypto.Encrypt(secret, super, master)
	if err != nil {
		t.Fatal(err)
	}

	enc, err := master.Encode()
	if err != nil {
		t.Fatal(err)
	}

	groupSec, err := crypto.Encrypt(enc, super, group)
	if err != nil {
		t.Fatal(err)
	}

	grpenc, err := group.Encode()
	if err != nil {
		t.Fatal(err)
	}

	userKey, err := crypto.Encrypt(grpenc, super, cfg.Runtime.Keypair)
	if err != nil {
		t.Fatal(err)
	}

	var resp shared.Message

	resp.Key.Secret = masterSec
	resp.Key.Key = groupSec
	resp.Key.GroupPriv = userKey

	fh, err := ioutil.TempFile(os.TempDir(), "skds_client")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(fh.Name())

	resp.Key.Path = fh.Name()

	ts := testGet(200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	ok := GetSecrets(cfg, "/client/secrets")
	if !ok {
		t.Fatal("Failed to get secret")
	}

	data, err := ioutil.ReadFile(fh.Name())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, []byte("secret data")) != 0 {
		t.Fatal("Decrypted secret does not match")
	}
}
