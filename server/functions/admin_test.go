package functions

import (
	"bytes"
	"testing"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/messages"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestAdminPass(t *testing.T) {
	var msg messages.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	// The password is hashed on the client before being sent to the server
	testPass := []byte("new password string")
	testHash, err := crypto.PasswordHash(testPass)
	if err != nil {
		t.Fatal(err)
	}

	msg.Admin.Password = testHash

	ret, resp := AdminPass(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	// Make sure we can auth against the new password
	ok, _ := auth.Admin(cfg, "admin", testPass)
	if !ok {
		t.Error("Failed to authenticate with new password")
	}
}

func TestAdminNew(t *testing.T) {
	var msg messages.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	msg.Admin.Name = "New Admin"
	ret, resp := AdminNew(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	// Ensure new admin can log in and is a superadmin
	ok, a := auth.Admin(cfg, msg.Admin.Name, config.DefaultAdminPass)
	if !ok {
		t.Error("Failed to authenticate new admin")
	}
	if a.GID != config.DefAdminGid {
		t.Error("New admin has wrong GID")
	}
	if !a.Admin {
		t.Error("New admin created as client")
	}
}

func TestAdminDel(t *testing.T) {
	var msg messages.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	admin := new(db.Admins)
	admin.Name = "New Admin"
	cfg.DB.Create(admin)

	msg.Admin.Name = admin.Name
	ret, resp := AdminDel(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	if q := cfg.DB.First(admin); !q.RecordNotFound() {
		t.Error("Admin still exists after delete")
	}
}

func TestAdminSuper(t *testing.T) {
	var msg messages.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	admin := new(db.Admins)
	admin.Name = "New Admin"
	cfg.DB.Create(admin)

	msg.Admin.Name = admin.Name
	msg.Key.GroupPriv = []byte("super key")
	ret, resp := AdminSuper(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	cfg.DB.First(admin)
	if bytes.Compare(shared.HexDecode(admin.GroupKey), msg.Key.GroupPriv) != 0 {
		t.Error("Group key does not match")
	}

	if admin.Gid != config.SuperGid {
		t.Error("GID does not match superGID")
	}

}

func TestAdminPubkey(t *testing.T) {
	var msg messages.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	admin := new(db.Admins)
	admin.Id = authobj.UID
	cfg.DB.First(admin)

	msg.Admin.Key = []byte("pub key")
	ret, resp := AdminPubkey(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	cfg.DB.First(admin)
	if bytes.Compare(shared.HexDecode(admin.Pubkey), msg.Admin.Key) != 0 {
		t.Error("Public key does not match")
	}
}

func TestAdminList(t *testing.T) {
	var msg messages.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	msg.Admin.Name = "New Admin"
	ret, resp := AdminNew(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	ret, resp = AdminList(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	if len(resp.ResponseData) != 2 {
		t.Fatal("Expected 2 results, got", len(resp.ResponseData))
	}

	names := []string{"Admin", "New Admin"}
	groups := []string{"super", "default"}
	for i := range resp.ResponseData {
		if resp.ResponseData[i].Admin.Name != names[i] {
			t.Error("Wrong name in response")
		}
		if resp.ResponseData[i].Admin.Group != groups[i] {
			t.Error("Wrong group in response")
		}
	}
}

func TestAdminGroupAssign(t *testing.T) {
	var msg messages.Message
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

	admin := new(db.Admins)
	group := new(db.Groups)
	admin.Name = "Test Admin"
	admin.Pubkey = shared.HexEncode(adminKey.Pub[:])
	group.Name = "Test group"
	group.Kind = "admin"
	group.PubKey = shared.HexEncode(groupKey.Pub[:])
	group.PrivKey = shared.HexEncode(groupPriv)

	cfg.DB.Create(admin)
	cfg.DB.Create(group)

	msg.Admin.Name = admin.Name
	msg.Admin.Group = group.Name
	msg.Key.GroupPriv = adminPriv

	ret, resp := AdminGroupAssign(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	// Make sure we can decrypt the group key after assignment with the admin key
	admin = new(db.Admins)
	cfg.DB.Where("name = ?", msg.Admin.Name).First(admin)

	groupKeyRaw, err := crypto.Decrypt(shared.HexDecode(admin.GroupKey), adminKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(groupKeyRaw, groupKey.Priv[:]) != 0 {
		t.Error("Decrypted key does not match")
	}

}

func TestAdminGroupNew(t *testing.T) {
	var msg messages.Message
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

	msg.Admin.Group = "New admin group"
	ret, resp := AdminGroupNew(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	group := new(db.Groups)
	cfg.DB.Where("name = ?", msg.Admin.Group).First(group)
	if group.Kind != "admin" {
		t.Error("Group type does not match")
	}
	if bytes.Compare(shared.HexDecode(group.PrivKey), key.Priv[:]) != 0 {
		t.Error("Group priv key does not match")
	}
	if bytes.Compare(shared.HexDecode(group.PubKey), key.Pub[:]) != 0 {
		t.Error("Group pub key does not match")
	}

	msg.Admin.Group = ""
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

func TestAdminGroupDel(t *testing.T) {
	var msg messages.Message
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

	groupSecrets.Gid = group.Id
	groupSecrets.Sid = 1
	cfg.DB.Create(groupSecrets)

	groupSecrets = new(db.GroupSecrets)
	groupSecrets.Gid = group.Id
	groupSecrets.Sid = 2
	cfg.DB.Create(groupSecrets)

	msg.Admin.Group = group.Name

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

func TestAdminGroupList(t *testing.T) {
	var msg messages.Message
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
