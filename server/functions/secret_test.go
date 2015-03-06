package functions

import (
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
	"testing"
)

func TestSecretList(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	secret := new(db.MasterSecrets)
	secret.Name = "test secret 1"

	cfg.DB.Create(secret)

	secret = new(db.MasterSecrets)
	secret.Name = "test secret 2"

	cfg.DB.Create(secret)

	SecretList(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// test secret 1 + test secret 2
	if len(msgs) != 2 {
		t.Error("Expected 2 results, got", len(msgs))
	}
}

func TestSecretListUser(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	user := new(db.Users)
	user.Name = "test admin"
	user.GID = 10
	user.Admin = true
	cfg.DB.Create(user)

	secret := new(db.MasterSecrets)
	groupSecret := new(db.GroupSecrets)
	adminSecret := new(db.UserSecrets)

	secret.Name = "test secret 1"
	cfg.DB.Create(secret)

	groupSecret.GID = user.GID
	groupSecret.SID = secret.Id
	cfg.DB.Create(groupSecret)

	secret = new(db.MasterSecrets)
	secret.Name = "test secret 2"
	cfg.DB.Create(secret)

	adminSecret.UID = user.Id
	adminSecret.SID = secret.Id
	adminSecret.Path = "/foo"
	cfg.DB.Create(adminSecret)

	secret = new(db.MasterSecrets)
	secret.Name = "test secret 3"
	cfg.DB.Create(secret)

	req.Req.User.Name = user.Name
	req.Req.User.Admin = false

	SecretListUser(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Req.User.Name = user.Name
	req.Req.User.Admin = true

	SecretListUser(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// test secret 1 + test secret 2
	if len(msgs) != 2 {
		t.Error("Expected 2 results, got", len(msgs))
	}

	if msgs[0].Key.Path == "" && msgs[1].Key.Path == "" {
		t.Error("Missing path")
	}
}

func TestSecretListGroup(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	group := new(db.Groups)
	group.Name = "test group"
	group.Admin = false
	cfg.DB.Create(group)

	secret := new(db.MasterSecrets)
	groupSecret := new(db.GroupSecrets)

	secret.Name = "test secret 1"
	cfg.DB.Create(secret)

	groupSecret.GID = group.Id
	groupSecret.SID = secret.Id
	groupSecret.Path = "/foo"
	cfg.DB.Create(groupSecret)

	secret = new(db.MasterSecrets)
	secret.Name = "test secret 2"
	cfg.DB.Create(secret)

	req.Req.User.Group = group.Name
	req.Req.User.Admin = false

	SecretListGroup(cfg, req)
	if resp.Code != 200 {
		t.Error("Bad response code:", resp.Code)
	}

	msgs, err := shared.ReadResp(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// test secret 1 only
	if len(msgs) != 1 {
		t.Error("Expected 1 results, got", len(msgs))
	}

	if msgs[0].Key.Path != "/foo" {
		t.Error("Missing path")
	}
}

func TestSecretNew(t *testing.T) {
	uid := uint(3)
	req, resp := respRecorder()

	req.Session = unpriv
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	var key crypto.Binary
	var userKey crypto.Binary
	var secret crypto.Binary

	key = []byte("test key")
	userKey = []byte("user key")
	secret = []byte("test secret")

	req.Req.Key.Name = "test key"
	req.Req.Key.Secret = secret
	req.Req.Key.Key = key
	req.Req.Key.UserKey = userKey

	SecretNew(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	masterSecret := new(db.MasterSecrets)
	superSecret := new(db.GroupSecrets)
	adminSecret := new(db.UserSecrets)

	cfg.DB.First(masterSecret)
	cfg.DB.Where("gid = ?", shared.SuperGID).First(superSecret)
	cfg.DB.Where("uid = ?", uid).First(adminSecret)

	if masterSecret.Name != req.Req.Key.Name {
		t.Error("Secret has the wrong name")
	}
	if superSecret.SID != masterSecret.Id {
		t.Error("Supergroup SID does not match secret ID")
	}
	if adminSecret.SID != masterSecret.Id {
		t.Error("Admin SID does not match secret ID")
	}
}

func TestSecretDel(t *testing.T) {
	cfg.DB.LogMode(true)
	req, resp := respRecorder()
	req.Session = unpriv
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	secret := new(db.MasterSecrets)
	userSecret := new(db.UserSecrets)
	groupSecret := new(db.GroupSecrets)

	secret.Name = "Test secret"
	req.Req.Key.Name = secret.Name

	SecretDel(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = unpriv
	req.Req.Key.Name = secret.Name

	q := cfg.DB.Create(secret)
	if q.Error != nil {
		t.Fatal(err)
	}

	SecretDel(cfg, req)
	if resp.Code != 403 {
		t.Error("Bad response code:", resp.Code)
	}

	newUnpriv := unpriv
	newUnpriv.GID = 6

	req, resp = respRecorder()

	req.Session = newUnpriv
	req.Req.Key.Name = secret.Name

	userSecret.SID = secret.Id
	groupSecret.SID = secret.Id
	groupSecret.GID = 6

	q = cfg.DB.Create(userSecret)
	if q.Error != nil {
		t.Fatal(err)
	}

	q = cfg.DB.Create(groupSecret)
	if q.Error != nil {
		t.Fatal(err)
	}

	SecretDel(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	q = cfg.DB.First(secret, secret.Id)
	if !q.RecordNotFound() {
		t.Error("Master secret not deleted")
	}

	q = cfg.DB.First(userSecret, secret.Id)
	if !q.RecordNotFound() {
		t.Error("User secret not deleted")
	}

	q = cfg.DB.First(groupSecret, secret.Id)
	if !q.RecordNotFound() {
		t.Error("Group secret not deleted")
	}
}

func TestSecretUpdate(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	secret := new(db.MasterSecrets)

	SecretUpdate(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	secret.Name = "Test secret"
	cfg.DB.Create(secret)

	req, resp = respRecorder()
	req.Session = session

	req.Req.Key.Name = secret.Name
	req.Req.Key.Secret = []byte("testing payload")

	SecretUpdate(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	cfg.DB.First(secret)

	var dbSecret crypto.Binary
	err = dbSecret.Decode(secret.Secret)
	if err != nil {
		t.Fatal(err)
	}

	if !dbSecret.Compare(req.Req.Key.Secret) {
		t.Error("Secret not updated correctly")
	}
}

func TestSecretAssignUser(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	SecretAssignUser(cfg, req)
	if resp.Code != 400 {
		t.Error("Bad response code:", resp.Code)
	}

	user := new(db.Users)
	secret := new(db.MasterSecrets)

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")

	SecretAssignUser(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = true
	req.Req.Key.Name = "test secret"

	user.GID = shared.SuperGID
	user.Name = req.Req.User.Name
	user.Admin = true

	cfg.DB.Create(user)

	SecretAssignUser(cfg, req)
	if resp.Code != 400 {
		t.Error("Bad response code:", resp.Code)
	}

	user.GID = shared.DefAdminGID
	cfg.DB.Save(user)

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = true
	req.Req.Key.Name = "test secret"

	SecretAssignUser(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = true
	req.Req.Key.Name = "test secret"

	secret.Name = req.Req.Key.Name

	cfg.DB.Create(secret)

	SecretAssignUser(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}
}

func TestSecretAssignGroup(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	SecretAssignGroup(cfg, req)
	if resp.Code != 400 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Group = "test group"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	group := new(db.Groups)
	secret := new(db.MasterSecrets)

	group.Name = "test group"
	group.Admin = false
	cfg.DB.Create(group)

	SecretAssignGroup(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Group = "test group"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	secret.Name = req.Req.Key.Name

	cfg.DB.Create(secret)

	SecretAssignGroup(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}
}

func TestSecretRemoveUser(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	user := new(db.Users)
	secret := new(db.MasterSecrets)
	userSecret := new(db.UserSecrets)

	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	SecretRemoveUser(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	user.GID = shared.SuperGID
	user.Name = req.Req.User.Name

	cfg.DB.Create(user)

	SecretRemoveUser(cfg, req)
	if resp.Code != 403 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	user.GID = shared.DefAdminGID
	cfg.DB.Save(user)

	SecretRemoveUser(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Name = "test user"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	secret.Name = req.Req.Key.Name

	cfg.DB.Create(secret)

	userSecret.SID = secret.Id
	userSecret.UID = user.Id
	cfg.DB.Create(userSecret)

	SecretRemoveUser(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	q := cfg.DB.First(userSecret)
	if !q.RecordNotFound() {
		t.Fatal("Secret access not removed")
	}
}

func TestSecretRemoveGroup(t *testing.T) {
	req, resp := respRecorder()
	req.Session = session
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	group := new(db.Groups)
	secret := new(db.MasterSecrets)
	groupSecret := new(db.GroupSecrets)

	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Group = "test group"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	SecretRemoveGroup(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Group = "super"
	req.Req.User.Admin = true
	req.Req.Key.Name = "test secret"

	SecretRemoveGroup(cfg, req)
	if resp.Code != 403 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Group = "test group"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	group.Name = req.Req.User.Group
	cfg.DB.Create(group)

	SecretRemoveGroup(cfg, req)
	if resp.Code != 404 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Session = session
	req.Req.Key.Secret = []byte("test secret")
	req.Req.User.Group = "test group"
	req.Req.User.Admin = false
	req.Req.Key.Name = "test secret"

	secret.Name = req.Req.Key.Name

	cfg.DB.Create(secret)

	groupSecret.SID = secret.Id
	groupSecret.GID = group.Id
	cfg.DB.Create(groupSecret)

	SecretRemoveGroup(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	q := cfg.DB.First(groupSecret)
	if !q.RecordNotFound() {
		t.Fatal("Secret access not removed")
	}
}
