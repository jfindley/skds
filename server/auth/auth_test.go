package auth

import (
	"bytes"
	"errors"
	"github.com/jinzhu/gorm"
	"testing"
	"time"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

var (
	err         error
	cfg         *shared.Config
	validPass   []byte = []byte("This is valid")
	invalidPass []byte = []byte("This is not valid")
)

func init() {
	cfg = new(shared.Config)
	cfg.Init()
}

type testAcl struct {
	uid uint
	gid uint
}

func (t testAcl) Lookup(db gorm.DB, uid, gid uint) bool {
	if t.uid == uid && t.gid == gid {
		return true
	}
	return false
}

type testCreds struct {
	name string
}

func (t *testCreds) Get(*shared.Config) (d DBCreds, err error) {
	switch t.name {
	case "super":
		d.Admin = true
		d.GID = shared.SuperGID
		d.Password, _ = crypto.PasswordHash(validPass)
		d.UID = 10
	case "admin":
		d.Admin = true
		d.GID = shared.DefAdminGID
		d.Password, _ = crypto.PasswordHash(validPass)
		d.UID = 11
	case "client":
		d.Admin = false
		d.GID = shared.DefClientGID
		d.Password, _ = crypto.PasswordHash(validPass)
		d.UID = 12
	default:
		err = errors.New("Record Not Found")
	}
	return
}

func TestACL(t *testing.T) {
	var db gorm.DB

	good := testAcl{uid: 1, gid: 1}
	bad := testAcl{uid: 2, gid: 2}
	me := AuthObject{UID: 1, GID: 1}

	if !me.CheckACL(db, good) {
		t.Error("ACL should pass")
	}

	if me.CheckACL(db, bad) {
		t.Error("ACL should fail")
	}

	if me.CheckACL(db, good, bad, good) {
		t.Error("ACL should fail")
	}

}

func TestSuper(t *testing.T) {
	c := new(testCreds)
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
	if a.GID != shared.SuperGID {
		t.Error("GID incorrect")
	}

	ok, _ = auth(cfg, c, "super", invalidPass)
	if ok {
		t.Error("Auth passed incorrectly")
	}
}

func TestAdmin(t *testing.T) {
	c := new(testCreds)
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
	if a.GID != shared.DefAdminGID {
		t.Error("GID incorrect")
	}

	ok, _ = auth(cfg, c, "admin", invalidPass)
	if ok {
		t.Error("Auth passed incorrectly")
	}
}

func TestClient(t *testing.T) {
	c := new(testCreds)
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
	if a.GID != shared.DefClientGID {
		t.Error("GID incorrect")
	}

	ok, _ = auth(cfg, c, "client", invalidPass)
	if ok {
		t.Error("Auth passed incorrectly")
	}
}

func TestPool(t *testing.T) {
	p := new(SessionPool)
	c := new(testCreds)
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
	c := new(testCreds)
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
	c := new(testCreds)
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
