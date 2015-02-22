package shared

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jfindley/skds/crypto"
)

var (
	err         error
	cfg         *Config
	validPass   []byte = []byte("This is valid")
	invalidPass []byte = []byte("This is not valid")
)

func init() {
	cfg = new(Config)
	cfg.Init()
}

type testcreds struct {
	name string
}

func (t *testcreds) Get(*Config) (d DBCreds, err error) {
	switch t.name {
	case "super":
		d.Admin = true
		d.GID = SuperGid
		d.Password, _ = crypto.PasswordHash(validPass)
		d.UID = 10
	case "admin":
		d.Admin = true
		d.GID = DefAdminGid
		d.Password, _ = crypto.PasswordHash(validPass)
		d.UID = 11
	case "client":
		d.Admin = false
		d.GID = DefClientGid
		d.Password, _ = crypto.PasswordHash(validPass)
		d.UID = 12
	default:
		err = errors.New("Record Not Found")
	}
	return
}

func TestSuper(t *testing.T) {
	c := new(testcreds)
	c.name = "super"

	ok, a := auth(cfg, c, "super", validPass)
	if !ok {
		t.Error("Auth failed")
	}
	if !a.Super {
		t.Error("Not flagged as super")
	}
	if !a.Admin {
		t.Error("Not flagged as admin")
	}
	if a.UID != 10 {
		t.Error("UID incorrect")
	}
	if a.GID != SuperGid {
		t.Error("GID incorrect")
	}

	ok, _ = auth(cfg, c, "super", invalidPass)
	if ok {
		t.Error("Auth passed incorrectly")
	}
}

func TestAdmin(t *testing.T) {
	c := new(testcreds)
	c.name = "admin"

	ok, a := auth(cfg, c, "admin", validPass)
	if !ok {
		t.Error("Auth failed")
	}
	if a.Super {
		t.Error("Flagged as super")
	}
	if !a.Admin {
		t.Error("Not flagged as admin")
	}
	if a.UID != 11 {
		t.Error("UID incorrect")
	}
	if a.GID != DefAdminGid {
		t.Error("GID incorrect")
	}

	ok, _ = auth(cfg, c, "admin", invalidPass)
	if ok {
		t.Error("Auth passed incorrectly")
	}
}

func TestClient(t *testing.T) {
	c := new(testcreds)
	c.name = "client"

	ok, a := auth(cfg, c, "client", validPass)
	if !ok {
		t.Error("Auth failed")
	}
	if a.Super {
		t.Error("Flagged as super")
	}
	if a.Admin {
		t.Error("Flagged as admin")
	}
	if a.UID != 12 {
		t.Error("UID incorrect")
	}
	if a.GID != DefClientGid {
		t.Error("GID incorrect")
	}

	ok, _ = auth(cfg, c, "client", invalidPass)
	if ok {
		t.Error("Auth passed incorrectly")
	}
}

func TestPool(t *testing.T) {
	p := new(SessionPool)
	c := new(testcreds)
	c.name = "admin"

	ok, id := p.New(cfg, "admin", validPass, c)
	if !ok {
		t.Error("Auth failed")
	}
	if id == 0 {
		t.Error("No ID assigned")
	}

	if p.expired(id) {
		t.Error("Session should not be marked as expired")
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
	c := new(testcreds)
	c.name = "admin"

	ok, id := p.New(cfg, "admin", validPass, c)
	if !ok {
		t.Error("Auth failed")
	}

	msg := []byte("test data")
	fakeMsg := []byte("fake message")

	mac := crypto.NewMAC(p.Pool[id].SessionKey, "/login", msg)
	fakeMac := crypto.NewMAC(p.Pool[id].SessionKey, "/login", fakeMsg)

	ok = p.Validate(id, mac, "/login", msg)
	if !ok {
		t.Error("Message did not validate")
	}

	ok = p.Validate(id, mac, "/login", fakeMsg)
	if ok {
		t.Error("Fake message validated")
	}

	ok = p.Validate(id, fakeMac, "/login", msg)
	if ok {
		t.Error("Fake message validated")
	}

}

func TestPrune(t *testing.T) {
	pruneInterval = 1 * time.Millisecond
	sessionExpiry = 1

	p := new(SessionPool)
	c := new(testcreds)
	c.name = "admin"

	go p.Pruner()

	ok, id := p.New(cfg, "admin", validPass, c)
	if !ok {
		t.Error("Auth failed")
	}

	// Enough time for the session to have expired, and the pruner to have
	// plenty of runtime to remove it.
	time.Sleep(1050 * time.Millisecond)

	if _, ok := p.Pool[id]; ok {
		t.Error("Expired entry in pool not pruned")
	}
}
