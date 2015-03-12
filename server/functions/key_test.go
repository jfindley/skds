package functions

import (
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestSetPubkey(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.User.Key = []byte("pub key")
	SetPubkey(cfg, req)

	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	user := db.Users{Id: session.UID}

	q := cfg.DB.First(&user)
	if q.Error != nil {
		t.Fatal(err)
	}

	var dbKey crypto.Binary
	err = dbKey.Decode(user.PubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !dbKey.Compare(req.Req.User.Key) {
		t.Error("Key does not match")
	}
}

func TestUserPubKey(t *testing.T) {
	req, resp := respRecorder()

	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	var key crypto.Binary
	key = []byte("test pub key")

	user := new(db.Users)
	user.Name = "test user"
	user.Admin = true
	user.PubKey, err = key.Encode()
	if err != nil {
		t.Fatal(err)
	}

	cfg.DB.Create(user)

	req.Req.User.Name = user.Name
	req.Req.User.Admin = true

	UserPubKey(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Fatal("Expected 1 results, got", len(msgs))
	}

	if !key.Compare(msgs[0].Key.UserKey) {
		t.Error("Key does not match")
	}
}

func TestUserGroupKey(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	var key crypto.Binary
	key = []byte("test group key")

	user := new(db.Users)

	cfg.DB.First(user, req.Session.GetUID())
	user.GroupKey, err = key.Encode()
	if err != nil {
		t.Fatal(err)
	}

	cfg.DB.Save(user)

	UserGroupKey(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Fatal("Expected 1 results, got", len(msgs))
	}

	if !key.Compare(msgs[0].Key.GroupPriv) {
		t.Error("Key does not match")
	}
}

func TestGroupPubKey(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.User.Group = "test admin group"
	req.Req.User.Admin = true

	group := new(db.Groups)
	group.Name = req.Req.User.Group
	group.Admin = req.Req.User.Admin
	group.PubKey, err = crypto.NewBinary([]byte("pub")).Encode()
	if err != nil {
		t.Fatal(err)
	}

	cfg.DB.Create(group)

	GroupPubKey(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Error("Expected 1 message")
	}
}

func TestSuperPubKey(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	var key crypto.Binary
	key = []byte("test pub key")
	enc, err := key.Encode()
	if err != nil {
		t.Fatal(err)
	}

	group := new(db.Groups)
	cfg.DB.First(group, shared.SuperGID).Update("PubKey", enc)

	SuperPubKey(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Fatal("Expected 1 results, got", len(msgs))
	}

	if !key.Compare(msgs[0].Key.Key) {
		t.Error("Key does not match")
	}
}

func TestGroupPrivKey(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.User.Group = "test admin group"
	req.Req.User.Admin = true

	group := new(db.Groups)
	group.Name = req.Req.User.Group
	group.Admin = req.Req.User.Admin
	group.PrivKey, err = crypto.NewBinary([]byte("Priv")).Encode()
	if err != nil {
		t.Fatal(err)
	}

	cfg.DB.Create(group)

	GroupPrivKey(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Error("Expected 1 message")
	}
}

func TestSetSuperKey(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.Key.GroupPub = []byte("public")
	req.Req.Key.GroupPriv = []byte("private")

	SetSuperKey(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.GroupPub = []byte("public")
	req.Req.Key.GroupPriv = []byte("private")

	SetSuperKey(cfg, req)
	if resp.Code != 409 {
		t.Error("Bad response code:", resp.Code)
	}
}
