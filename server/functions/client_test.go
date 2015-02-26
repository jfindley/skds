package functions

import (
	"bytes"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func TestClientGetKey(t *testing.T) {
	var msg shared.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	authobj.Admin = false
	authobj.UID = shared.DefClientGID

	secret := new(db.MasterSecrets)
	secret.Name = "directly assigned secret"
	secret.Secret = shared.HexEncode([]byte("data 1"))
	cfg.DB.Create(secret)

	sid1 := secret.Id

	secret = new(db.MasterSecrets)
	secret.Name = "group assigned secret"
	secret.Secret = shared.HexEncode([]byte("data 2"))
	cfg.DB.Create(secret)

	sid2 := secret.Id

	group := new(db.Groups)
	group.Kind = "client"
	group.Name = "test group"
	cfg.DB.Create(group)

	client := new(db.Users)
	client.Name = "test client"
	client.GID = group.Id
	client.GroupKey = shared.HexEncode([]byte("group key"))

	clientSecret := new(db.UserSecrets)
	clientSecret.Path = "/tmp/test1"
	clientSecret.Sid = sid1
	clientSecret.Uid = client.Id
	clientSecret.Secret = shared.HexEncode([]byte("client secret"))
	cfg.DB.Create(clientSecret)

	groupSecret := new(db.GroupSecrets)
	groupSecret.GID = group.Id
	groupSecret.Sid = sid2
	groupSecret.Secret = shared.HexEncode([]byte("group secret"))
	cfg.DB.Create(groupSecret)

	authobj.GID = group.Id
	authobj.UID = client.Id

	ret, resp := ClientGetKey(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

}

func TestClientDel(t *testing.T) {
	var msg shared.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	msg.Client.Name = "New Client"
	ret, resp := ClientDel(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	if !cfg.DB.NewRecord(db.Users{Name: msg.Client.Name}) {
		t.Error("Client still exists after delete")
	}
}

func TestClientGroup(t *testing.T) {
	var msg shared.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	superKey := new(crypto.Key)
	groupKey := new(crypto.Key)
	clientKey := new(crypto.Key)

	err = superKey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	err = groupKey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	err = clientKey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	groupPriv, err := crypto.Encrypt(groupKey.Priv[:], superKey, superKey)
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := crypto.Encrypt(groupKey.Priv[:], superKey, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	client := new(db.Users)
	group := new(db.Groups)
	client.Name = "Test Client"
	client.Pubkey = shared.HexEncode(clientKey.Pub[:])
	group.Name = "Test group"
	group.Kind = "client"
	group.PubKey = shared.HexEncode(groupKey.Pub[:])
	group.PrivKey = shared.HexEncode(groupPriv)

	cfg.DB.Create(client)
	cfg.DB.Create(group)

	msg.Client.Name = client.Name
	msg.Client.Group = group.Name
	msg.Key.GroupPriv = clientPriv

	ret, resp := ClientGroup(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	// Make sure we can decrypt the group key after assignment with the client key
	client = new(db.Users)
	cfg.DB.Where("name = ?", msg.Client.Name).First(client)

	groupKeyRaw, err := crypto.Decrypt(shared.HexDecode(client.GroupKey), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(groupKeyRaw, groupKey.Priv[:]) != 0 {
		t.Error("Decrypted key does not match")
	}
}

func TestClientRegister(t *testing.T) {
	var msg shared.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	authobj.Admin = false

	msg.Client.Name = "new client"
	msg.Client.Password = []byte("password")
	msg.Client.Key = []byte("pub key")
	ret, resp := ClientRegister(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	ret, resp = ClientRegister(cfg, authobj, msg)
	if ret != 401 || resp.Response != "Client with this name already exists" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	client := new(db.Users)
	client.Name = msg.Client.Name
	cfg.DB.First(client)

	if client.GID != shared.DefClientGID {
		t.Error("Client created with wrong GID")
	}

	if bytes.Compare(shared.HexDecode(client.Password), msg.Client.Password) != 0 {
		t.Error("Password does not match")
	}

	if bytes.Compare(shared.HexDecode(client.Pubkey), msg.Client.Key) != 0 {
		t.Error("Public key does not match")
	}
}

func TestClientList(t *testing.T) {
	var msg shared.Message
	err = setupDB(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.DB.Close()

	msg.Client.Name = "New Client"
	client := new(db.Users)
	client.Name = msg.Client.Name
	client.GID = shared.DefClientGID
	cfg.DB.Create(client)

	ret, resp := ClientList(cfg, authobj, msg)
	if ret != 0 || resp.Response != "OK" {
		t.Fatal("Bad result :", ret, resp.Response)
	}

	if len(resp.ResponseData) != 1 {
		t.Fatal("Expected 1 results, got", len(resp.ResponseData))
	}

	names := []string{"New Client"}
	groups := []string{"default"}
	for i := range resp.ResponseData {
		if resp.ResponseData[i].Client.Name != names[i] {
			t.Error("Wrong name in response")
		}
		if resp.ResponseData[i].Client.Group != groups[i] {
			t.Error("Wrong group in response")
		}
	}
}
