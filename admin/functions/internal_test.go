package functions

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestSuperPubKey(t *testing.T) {
	var resp shared.Message
	resp.Key.Key = []byte("test data")

	ts := testGet(200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	key, err := superPubKey(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key.Pub[:len(resp.Key.Key)], resp.Key.Key) != 0 {
		t.Error("Key does not match")
	}
}

func TestUserPubKey(t *testing.T) {
	var resp shared.Message
	resp.Key.UserKey = []byte("test data")

	var exp shared.Message
	exp.User.Name = "test user"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	key, err := userPubKey(cfg, exp.User.Name, exp.User.Admin)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key.Pub[:len(resp.Key.UserKey)], resp.Key.UserKey) != 0 {
		t.Error("Key does not match")
	}
}

func TestGroupPubKey(t *testing.T) {
	var resp shared.Message
	resp.Key.GroupPub = []byte("test data")

	var exp shared.Message
	exp.User.Group = "test group"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	key, err := groupPubKey(cfg, exp.User.Group, exp.User.Admin)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key.Pub[:len(resp.Key.GroupPub)], resp.Key.GroupPub) != 0 {
		t.Error("Key does not match")
	}
}

func TestGroupPrivKey(t *testing.T) {
	groupKey := []byte("test data")
	var err error
	var resp shared.Message

	resp.Key.GroupPriv, err = crypto.Encrypt(groupKey, superKey, superKey)
	if err != nil {
		t.Fatal(err)
	}

	var exp shared.Message
	exp.User.Group = "test group"
	exp.User.Admin = true

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	key, err := groupPrivKey(cfg, exp.User.Group, exp.User.Admin)
	if err != nil {
		t.Fatal(err)
	}

	// groupKey will have been zeroed, use a new var
	testData := []byte("test data")
	if bytes.Compare(key.Priv[:len(testData)], testData) != 0 {
		t.Error("Key does not match")
	}
}

func TestSecretPubKey(t *testing.T) {
	var err error
	var resp shared.Message

	resp.Key.Key = make([]byte, 32)
	copy(resp.Key.Key, []byte("test data"))

	var exp shared.Message
	exp.Key.Name = "test secret"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	key, err := secretPubKey(cfg, exp.Key.Name)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key.Pub[:], resp.Key.Key) != 0 {
		t.Fatal("Key does not match")
	}
}

func TestSecretPrivKey(t *testing.T) {
	groupKey := []byte("test data")
	var err error
	var resp shared.Message

	resp.Key.GroupPriv, err = crypto.Encrypt(groupKey, superKey, superKey)
	if err != nil {
		t.Fatal(err)
	}

	var exp shared.Message
	exp.Key.Name = "test secret"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	key, err := secretPrivKey(cfg, exp.Key.Name)
	if err != nil {
		t.Fatal(err)
	}

	// groupKey will have been zeroed, use a new var
	testData := []byte("test data")
	if bytes.Compare(key.Priv[:len(testData)], testData) != 0 {
		t.Error("Key does not match")
	}
}

func TestSecretGet(t *testing.T) {
	var err error
	var resp shared.Message

	secret := []byte("test data")
	key := new(crypto.Key)
	key.Generate()

	resp.Key.Secret, err = crypto.Encrypt(secret, key, key)
	if err != nil {
		t.Fatal(err)
	}

	resp.Key.UserKey, err = crypto.Encrypt(key.Priv[:], cfg.Runtime.Keypair, cfg.Runtime.Keypair)
	if err != nil {
		t.Fatal(err)
	}

	var exp shared.Message
	exp.Key.Name = "test secret"

	ts := testPost(exp, 200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	cfg.Session.New(cfg)

	data, err := secretGet(cfg, exp.Key.Name)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, []byte("test data")) != 0 {
		t.Error("Secret data does not match")
	}
}
