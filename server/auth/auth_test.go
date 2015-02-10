package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

var (
	err        error
	cfg        *config.Config
	clientPass []byte = []byte("clientpass")
	adminPass  []byte = []byte("adminpass")
)

func init() {
	cfg = new(config.Config)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"

	err := cfg.DBConnect()
	if err != nil {
		panic(err)
	}

	err = db.InitDB(cfg)
	if err != nil {
		panic(err)
	}
	err = db.CreateDefaults(cfg)
	if err != nil {
		panic(err)
	}

	cpass, err := crypto.PasswordHash(clientPass)
	if err != nil {
		panic(err)
	}

	apass, err := crypto.PasswordHash(adminPass)
	if err != nil {
		panic(err)
	}

	client := new(db.Clients)
	client.Name = "client"
	client.Password = cpass
	client.Gid = config.DefClientGid
	cfg.DB.Create(client)

	admin := new(db.Admins)
	admin.Name = "std_admin"
	admin.Password = apass
	admin.Gid = config.DefAdminGid
	cfg.DB.Create(admin)
}

func TestAdmin(t *testing.T) {
	ok, a := Admin(cfg, "doesnotexist", config.DefaultAdminPass)
	if ok {
		t.Error("Auth passed for invalid username")
	}

	ok, a = Admin(cfg, "admin", []byte("invalid"))
	if ok {
		t.Fatal("Auth passed for invalid password")
	}

	// Super admin
	ok, a = Admin(cfg, "admin", config.DefaultAdminPass)
	if !ok {
		t.Fatal("Failed authentication")
	}

	if !a.Admin || !a.Super {
		t.Error("Wrong attributes set")
	}

	if a.UID != 1 || a.GID != config.SuperGid {
		t.Error("UID/GID do not match")
	}

	// Non-super admin
	ok, a = Admin(cfg, "std_admin", adminPass)
	if !ok {
		t.Fatal("Failed authentication")
	}

	if !a.Admin || a.Super {
		t.Error("Wrong attributes set")
	}

	if a.UID != 2 || a.GID != config.DefAdminGid {
		t.Error("UID/GID do not match")
	}
}

func TestClient(t *testing.T) {

	ok, c := Client(cfg, "doesnotexist", clientPass)
	if ok {
		t.Error("Auth passed for invalid username")
	}

	ok, c = Client(cfg, "client", nil)
	if ok {
		t.Fatal("Auth passed for invalid password")
	}

	ok, c = Client(cfg, "client", clientPass)
	if !ok {
		t.Fatal("Failed authentication")
	}

	if c.Admin || c.Super {
		t.Error("Wrong attributes set")
	}

	if c.UID != 1 || c.GID != config.DefClientGid {
		t.Error("UID/GID do not match")
	}
}

func TestPool(t *testing.T) {
	p := new(SessionPool)

	ok, id := p.New(cfg, "std_admin", adminPass, Admin)
	if !ok {
		t.Error("Auth failed")
	}
	if id == 0 {
		t.Error("No ID assigned")
	}

	if p.expired(id) {
		t.Error("Session should not be marked as expired")
	}

	if shared.HexDecode(p.Pool[id].SessionKey) == nil {
		t.Error("Invalid session key")
	}

	oldKey := p.Pool[id].SessionKey
	oldTime := p.Pool[id].SessionTime

	time.Sleep(time.Nanosecond * 5000000) // 5 ms
	p.NextKey(id)
	dur := p.Pool[id].SessionTime.Sub(oldTime)
	if dur.Nanoseconds() <= 5000000 {
		t.Error("Session time not updated")
	}

	if bytes.Compare(p.Pool[id].SessionKey, oldKey) == 0 {
		t.Error("Session key not rotated")
	}

	sessionExpiry = 0

	if !p.expired(id) {
		t.Error("Session should be marked as expired")
	}
}

func TestValidate(t *testing.T) {
	sessionExpiry = 30

	p := new(SessionPool)

	ok, id := p.New(cfg, "std_admin", adminPass, Admin)
	if !ok {
		t.Error("Auth failed")
	}

	msg := []byte("test data")
	fakeMsg := []byte("fake message")

	mac := crypto.NewMAC(p.Pool[id].SessionKey, msg)
	fakeMac := crypto.NewMAC(p.Pool[id].SessionKey, fakeMsg)

	ok = p.Validate(id, mac, msg)
	if !ok {
		t.Error("Message did not validate")
	}

	ok = p.Validate(id, mac, fakeMsg)
	if ok {
		t.Error("Fake message validated")
	}

	ok = p.Validate(id, fakeMac, msg)
	if ok {
		t.Error("Fake message validated")
	}

}
