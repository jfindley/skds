package functions

import (
	"bytes"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestUserDel(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	user := new(db.Users)
	user.Name = "NewAdmin"
	user.Admin = true
	q := cfg.DB.Create(user)
	if q.Error != nil {
		t.Fatal(q.Error)
	}

	req.Req.User.Name = user.Name
	req.Req.User.Admin = true
	userDel(cfg, req, true)

	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	if q := cfg.DB.Find(&user, "name = ?", user.Name); !q.RecordNotFound() {
		t.Error("Admin still exists after delete", q.Error)
	}
}

func TestUserListAdmin(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	user := new(db.Users)
	user.Name = "New admin user"
	user.Admin = true
	cfg.DB.Create(user)

	user = new(db.Users)
	user.Name = "New client user"
	user.Admin = false
	cfg.DB.Create(user)

	userList(cfg, req, true)

	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// default admin + new admin user
	if len(msgs) != 2 {
		t.Error("Expected 2 messages")
	}
}

func TestUserListClient(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	user := new(db.Users)
	user.Name = "New admin user"
	user.Admin = true
	cfg.DB.Create(user)

	user = new(db.Users)
	user.Name = "New client user"
	user.Admin = false
	cfg.DB.Create(user)

	userList(cfg, req, false)

	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// new client user only
	if len(msgs) != 1 {
		t.Error("Expected 1 messages")
	}
}

func TestUserGroupAssign(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	superKey := new(crypto.Key)
	groupKey := new(crypto.Key)
	adminKey := new(crypto.Key)

	err = superKey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	err = groupKey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	err = adminKey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	groupPriv, err := crypto.Encrypt(groupKey.Priv[:], superKey, superKey)
	if err != nil {
		t.Fatal(err)
	}
	adminPriv, err := crypto.Encrypt(groupKey.Priv[:], superKey, adminKey)
	if err != nil {
		t.Fatal(err)
	}

	admin := new(db.Users)
	group := new(db.Groups)
	admin.Name = "Test Admin"
	admin.Admin = true
	admin.PubKey, err = crypto.NewBinary(adminKey.Pub[:]).Encode()
	if err != nil {
		t.Fatal(err)
	}

	group.Name = "Test group"
	group.Admin = true

	group.PubKey, err = crypto.NewBinary(groupKey.Pub[:]).Encode()
	if err != nil {
		t.Fatal(err)
	}
	group.PrivKey, err = crypto.NewBinary(groupPriv).Encode()
	if err != nil {
		t.Fatal(err)
	}

	cfg.DB.Create(admin)
	cfg.DB.Create(group)

	req.Req.User.Name = admin.Name
	req.Req.User.Admin = true
	req.Req.User.Group = group.Name
	req.Req.Key.GroupPriv = adminPriv

	userGroupAssign(cfg, req, true)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	// Make sure we can decrypt the group key after assignment with the admin key
	admin = new(db.Users)
	cfg.DB.Where("name = ?", req.Req.User.Name).First(admin)

	var dbKey crypto.Binary
	err = dbKey.Decode(admin.GroupKey)
	if err != nil {
		t.Fatal(err)
	}

	groupKeyRaw, err := crypto.Decrypt(dbKey, adminKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(groupKeyRaw, groupKey.Priv[:]) != 0 {
		t.Error("Decrypted key does not match")
	}
}
