package auth

import (
	"bytes"
	"github.com/jinzhu/gorm"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

var (
	cfg         *shared.Config
	validPass   = []byte("This is valid")
	invalidPass = []byte("This is not valid")
)

type closingBuffer struct {
	*bytes.Buffer
}

func (cb closingBuffer) Close() error {
	return nil
}

func init() {
	cfg = new(shared.Config)
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
	name  string
	uid   uint
	gid   uint
	pass  crypto.Binary
	admin bool
	super bool
}

func (t testCreds) GetName() string {
	return t.name
}

func (t testCreds) GetUID() uint {
	return t.uid
}

func (t testCreds) GetGID() uint {
	return t.gid
}

func (t testCreds) GetPass() crypto.Binary {
	return t.pass
}

func (t testCreds) IsAdmin() bool {
	return t.admin
}

func (t testCreds) IsSuper() bool {
	return t.super
}

func TestACL(t *testing.T) {
	var db gorm.DB

	good := testAcl{uid: 1, gid: 1}
	bad := testAcl{uid: 2, gid: 2}
	me := SessionInfo{UID: 1, GID: 1}

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

func TestAuth(t *testing.T) {
	var dbUser testCreds
	var err error

	pass := []byte("password")

	dbUser.name = "admin"
	dbUser.gid = shared.SuperGID
	dbUser.uid = 1
	dbUser.admin = true
	dbUser.pass, err = crypto.PasswordHash(pass)
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := Auth(dbUser, []byte("Bad password"))
	if ok {
		t.Error("Auth passed with bad password")
	}

	ok, sess := Auth(dbUser, pass)
	if !ok {
		t.Error("Failed auth")
	}

	switch {
	case sess.Name != dbUser.name:
		t.Error("Name incorrect")
	case sess.GID != dbUser.gid:
		t.Error("GID incorrect")
	case sess.UID != dbUser.uid:
		t.Error("UID incorrect")
	case !sess.Admin:
		t.Error("Admin status incorrect")
	case !sess.Super:
		t.Error("Superuser status incorrect")
	}

	dbUser.uid = 0
	ok, _ = Auth(dbUser, pass)
	if ok {
		t.Error("Auth passed with bad UID")
	}

}

func TestPool(t *testing.T) {
	var err error

	p := new(SessionPool)
	sess := new(SessionInfo)

	id, err := p.Add(sess)
	if err != nil {
		t.Error(err)
	}
	if id == 0 {
		t.Error("No ID assigned")
	}

	if p.expired(id) {
		t.Error("Session should not be marked as expired")
	}

	oldKey := p.Get(id).SessionKey
	oldTime := p.Get(id).SessionTime

	time.Sleep(time.Nanosecond * 5000000) // 5 ms
	newKey := p.Get(id).NextKey()

	dur := p.Get(id).SessionTime.Sub(oldTime)
	if dur.Nanoseconds() <= 5000000 {
		t.Error("Session time not updated")
	}

	if bytes.Compare(newKey, oldKey) == 0 {
		t.Error("Session key not rotated")
	}

	sessionExpiry = 0

	if !p.expired(id) {
		t.Error("Session should be marked as expired")
	}
}

func TestValidate(t *testing.T) {
	var err error
	sessionExpiry = 30

	p := new(SessionPool)
	sess := new(SessionInfo)

	id, err := p.Add(sess)
	if err != nil {
		t.Error(err)
	}

	// Validate a POST request
	testData := []byte(`{"Request":"Test"}`)

	in := closingBuffer{bytes.NewBuffer(testData)}
	req := new(http.Request)
	req.Body = in

	req.RequestURI = "/test/request"

	mac := crypto.NewMAC(p.Pool[id].SessionKey, "/test/request", testData)

	req.Header = http.Header(make(map[string][]string))
	req.Header.Add(shared.HdrMAC, mac)
	req.Header.Add(shared.HdrSession, strconv.FormatInt(id, 10))

	ok, sid, body := p.Validate(req)
	if !ok {
		t.Fatal("Validation failed")
	}
	if sid != id {
		t.Error("Wrong session ID")
	}
	if bytes.Compare(body, testData) != 0 {
		t.Error("Body does not match")
	}

	// Validate a GET request

	req = new(http.Request)

	req.RequestURI = "/test/request"

	mac = crypto.NewMAC(p.Pool[id].SessionKey, "/test/request", nil)

	req.Header = http.Header(make(map[string][]string))
	req.Header.Add(shared.HdrMAC, mac)
	req.Header.Add(shared.HdrSession, strconv.FormatInt(id, 10))

	ok, sid, body = p.Validate(req)
	if !ok {
		t.Fatal("Validation failed")
	}
	if sid != id {
		t.Error("Wrong session ID")
	}
}

func TestDelete(t *testing.T) {
	var err error
	sessionExpiry = 30

	p := new(SessionPool)
	sess := new(SessionInfo)

	id, err := p.Add(sess)
	if err != nil {
		t.Error(err)
	}

	req := new(http.Request)

	req.RequestURI = "/test/request"

	mac := crypto.NewMAC(p.Pool[id].SessionKey, "/test/request", nil)

	req.Header = http.Header(make(map[string][]string))
	req.Header.Add(shared.HdrMAC, mac)
	req.Header.Add(shared.HdrSession, strconv.FormatInt(id, 10))

	ok, sid, _ := p.Validate(req)
	if !ok {
		t.Fatal("Validation failed")
	}

	req = new(http.Request)

	req.RequestURI = "/test/request"

	mac = crypto.NewMAC(p.Pool[id].SessionKey, "/test/request", nil)

	req.Header = http.Header(make(map[string][]string))
	req.Header.Add(shared.HdrMAC, mac)
	req.Header.Add(shared.HdrSession, strconv.FormatInt(id, 10))

	p.Delete(sid)

	ok, sid, _ = p.Validate(req)
	if ok {
		t.Fatal("Validation passed")
	}

}

func TestPrune(t *testing.T) {
	var err error
	pruneInterval = 1 * time.Millisecond
	sessionExpiry = 1

	p := new(SessionPool)
	sess := new(SessionInfo)

	go p.Pruner()

	id, err := p.Add(sess)
	if err != nil {
		t.Error(err)
	}

	// Enough time for the session to have expired, and the pruner to have
	// plenty of runtime to remove it.
	time.Sleep(1050 * time.Millisecond)

	if p.Get(id) != nil {
		t.Error("Expired entry in pool not pruned")
	}
}
