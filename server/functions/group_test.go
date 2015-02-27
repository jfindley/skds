package functions

import (
	"bytes"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestGroupNew(t *testing.T) {
	var req shared.Request
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	// We don't bother encrypting the private key for this test, it's not required
	key := new(crypto.Key)
	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg.Key.GroupPriv = key.Priv[:]
	msg.Key.GroupPub = key.Pub[:]

	msg.User.Group = "New admin group"
	ret, resp := AdminGroupNew(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	group := new(db.Groups)
	cfg.DB.Where("name = ?", msg.User.Group).First(group)
	if group.Kind != "admin" {
		t.Error("Group type does not match")
	}
	if bytes.Compare(shared.HexDecode(group.PrivKey), key.Priv[:]) != 0 {
		t.Error("Group priv key does not match")
	}
	if bytes.Compare(shared.HexDecode(group.PubKey), key.Pub[:]) != 0 {
		t.Error("Group pub key does not match")
	}

	msg.User.Group = ""
	msg.Client.Group = "New Client Group"
	ret, resp = AdminGroupNew(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	group = new(db.Groups)
	cfg.DB.Where("name = ?", msg.Client.Group).First(group)
	if group.Kind != "client" {
		t.Error("Group type does not match")
	}
	if bytes.Compare(shared.HexDecode(group.PrivKey), key.Priv[:]) != 0 {
		t.Error("Group priv key does not match")
	}
	if bytes.Compare(shared.HexDecode(group.PubKey), key.Pub[:]) != 0 {
		t.Error("Group pub key does not match")
	}
}

func TestGroupDel(t *testing.T) {
	var req shared.Request
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	group := new(db.Groups)
	groupSecrets := new(db.GroupSecrets)
	group.Name = "New admin group"
	group.Kind = "admin"
	cfg.DB.Create(group)

	groupSecrets.GID = group.Id
	groupSecrets.Sid = 1
	cfg.DB.Create(groupSecrets)

	groupSecrets = new(db.GroupSecrets)
	groupSecrets.GID = group.Id
	groupSecrets.Sid = 2
	cfg.DB.Create(groupSecrets)

	msg.User.Group = group.Name

	ret, resp := AdminGroupDel(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	q := cfg.DB.First(group, group.Id)
	if !q.RecordNotFound() {
		t.Error("Group not deleted")
	}

	q = cfg.DB.First(groupSecrets, group.Id)
	if !q.RecordNotFound() {
		t.Error("Group secret not deleted")
	}
}

func TestGroupList(t *testing.T) {
	var req shared.Request
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	group := new(db.Groups)
	group.Name = "New admin group"
	group.Kind = "admin"
	cfg.DB.Create(group)

	group = new(db.Groups)
	group.Name = "New client group"
	group.Kind = "client"
	cfg.DB.Create(group)

	ret, resp := AdminGroupList(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	// Should list 3 builtin groups plus the 2 we just created
	if len(resp.ResponseData) != 5 {
		t.Fatal("Expected 5 results, got", len(resp.ResponseData))
	}
}
