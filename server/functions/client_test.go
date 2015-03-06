package functions

import (
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestClientGetSecret(t *testing.T) {
	req, resp := respRecorder()
	var err error
	var secretData crypto.Binary

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	secretData = []byte("secret data")

	group := new(db.Groups)
	group.Name = "test group"
	group.Admin = false

	cfg.DB.Create(group)

	user := new(db.Users)
	user.Admin = false
	user.Name = "test client"
	user.GID = group.Id
	user.GroupKey, _ = secretData.Encode()

	cfg.DB.Create(user)

	secret := new(db.MasterSecrets)
	secret.Name = "test secret 1"
	secret.Secret, _ = secretData.Encode()

	cfg.DB.Create(secret)

	userSecret := new(db.UserSecrets)
	userSecret.SID = secret.Id
	userSecret.UID = user.Id
	userSecret.Secret, _ = secretData.Encode()
	userSecret.Path = "test1"

	cfg.DB.Create(userSecret)

	secret = new(db.MasterSecrets)
	secret.Name = "test secret 2"
	secret.Secret, _ = secretData.Encode()

	cfg.DB.Create(secret)

	groupSecret := new(db.GroupSecrets)
	groupSecret.SID = secret.Id
	groupSecret.GID = group.Id
	groupSecret.Secret, _ = secretData.Encode()
	groupSecret.Path = "test2"

	cfg.DB.Create(groupSecret)

	client := new(auth.SessionInfo)
	client.Name = "test client"
	client.UID = user.Id
	client.GID = group.Id
	client.Admin = false

	req.Session = client

	ClientGetSecret(cfg, req)
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

	for i := range msgs {
		if !secretData.Compare(msgs[i].Key.Secret) {
			t.Error("Secret does not match")
		}
		if !secretData.Compare(msgs[i].Key.Key) {
			t.Error("Key does not match")
		}
		if msgs[i].Key.Name == "test secret 2" {
			if !secretData.Compare(msgs[i].Key.GroupPriv) {
				t.Error("Group priv key does not match")
			}
		}
	}
}

func TestClientRegister(t *testing.T) {
	req, resp := respRecorder()
	var err error

	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	req.Req.User.Name = "test client"
	req.Req.User.Password = []byte("test password")
	req.Req.User.Key = []byte("test key")

	ClientRegister(cfg, req)
	if resp.Code != 204 {
		t.Error("Bad response code:", resp.Code)
	}

	req, resp = respRecorder()
	req.Req.User.Name = "test client"
	req.Req.User.Password = []byte("test password 2")
	req.Req.User.Key = []byte("test key 2")

	ClientRegister(cfg, req)
	if resp.Code != 409 {
		t.Error("Bad response code:", resp.Code)
	}

	user := new(db.Users)
	cfg.DB.Find(user, "name = ?", "test client")

	ok, sess := auth.Auth(user, []byte("test password"))
	if !ok {
		t.Fatal("Client auth failed")
	}

	if sess.IsAdmin() {
		t.Error("Client has admin permissions")
	}
}
