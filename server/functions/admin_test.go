package functions

import (
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestUserPass(t *testing.T) {
	req, resp := respRecorder()
	var err error

	req.Session = session

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	testPass := []byte("new password string")

	req.Req.User.Password = []byte("new password string")

	UserPass(cfg, req)

	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	var user db.Users

	q := cfg.DB.First(&user, session.UID)
	if q.Error != nil {
		t.Fatal(err)
	}

	var dbHash crypto.Binary
	err = dbHash.Decode(user.Password)
	if err != nil {
		t.Fatal(err)
	}

	if ok, err := crypto.PasswordVerify(testPass, dbHash); !ok || err != nil {
		t.Error("Password not verified")
	}
}

func TestAdminNew(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.User.Name = "New Admin"
	req.Req.User.Admin = true
	AdminNew(cfg, req)

	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	if q := cfg.DB.First(&db.Users{Name: "New Admin", Admin: true, GID: shared.DefAdminGID}); q.RecordNotFound() {
		t.Error("Admin not created in DB")
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if len(msgs) != 1 {
		t.Error("Expected 1 message, got:", len(msgs))
	}

	m := msgs[0]

	if m.User.Name != "New Admin" {
		t.Error("Wrong username returned")
	}

	if m.User.Group != "default" {
		t.Error("Wrong group returned")
	}

	if !m.User.Admin {
		t.Error("Admin bool not set")
	}

	if len(m.User.Password) != crypto.MinPasswordLen {
		t.Error("Bad password length")
	}
}

func TestAdminSuper(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	user := new(db.Users)
	user.Name = "New Admin"
	user.Admin = true
	cfg.DB.Create(user)

	req.Req.User.Name = user.Name
	req.Req.Key.GroupPriv = []byte("super key")

	AdminSuper(cfg, req)

	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	cfg.DB.First(user)
	var dbKey crypto.Binary
	err = dbKey.Decode(user.GroupKey)
	if err != nil {
		t.Fatal(err)
	}

	if !dbKey.Compare(req.Req.Key.GroupPriv) {
		t.Error("Group key does not match")
	}

	if user.GID != shared.SuperGID {
		t.Error("GID does not match superGID")
	}

}

func TestUserPubkey(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.User.Key = []byte("pub key")
	UserPubkey(cfg, req)

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
