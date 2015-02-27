package functions

import (
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestGroupNew(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	// We don't bother encrypting the private key for this test, it's not required
	key := new(crypto.Key)
	err = key.Generate()
	if err != nil {
		t.Fatal(err)
	}
	req.Req.Key.GroupPriv = key.Priv[:]
	req.Req.Key.GroupPub = key.Pub[:]

	req.Req.User.Group = "New admin group"
	req.Req.User.Admin = true
	GroupNew(cfg, req)

	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	group := new(db.Groups)
	cfg.DB.Where("name = ?", req.Req.User.Group).First(group)
	if group.Admin != true {
		t.Error("Group type does not match")
	}
	var priv crypto.Binary
	var pub crypto.Binary
	priv.Decode(group.PrivKey)
	pub.Decode(group.PubKey)

	if !priv.Compare(key.Priv[:]) {
		t.Error("Group privkey does not match")
	}
	if !pub.Compare(key.Pub[:]) {
		t.Error("Group pubkey does not match")
	}
}

func TestGroupDel(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	group := new(db.Groups)
	groupSecrets := new(db.GroupSecrets)
	group.Name = "New admin group"
	group.Admin = true
	cfg.DB.Create(group)

	groupSecrets.GID = group.Id
	groupSecrets.SID = 1
	cfg.DB.Create(groupSecrets)

	groupSecrets = new(db.GroupSecrets)
	groupSecrets.GID = group.Id
	groupSecrets.SID = 2
	cfg.DB.Create(groupSecrets)

	req.Req.User.Group = group.Name
	req.Req.User.Admin = true

	GroupDel(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
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
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	group := new(db.Groups)
	group.Name = "New admin group"
	group.Admin = true
	cfg.DB.Create(group)

	group = new(db.Groups)
	group.Name = "New client group"
	group.Admin = false
	cfg.DB.Create(group)

	GroupList(cfg, req)

	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 5 {
		t.Error("Expected 5 messages")
	}
}
