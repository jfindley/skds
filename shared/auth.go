package shared

import (
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/jfindley/skds/crypto"
)

var authErr = errors.New("Authentication failed")
var sessionExpiry = 30

type Request struct {
	Req    *http.Request
	Body   []byte
	Verify bool
}

type AuthObject struct {
	Name        string
	UID         uint
	GID         uint
	Admin       bool
	Super       bool
	SessionKey  crypto.Binary
	SessionTime time.Time
}

type DBCreds struct {
	Name     string
	Password []byte
	UID      uint
	GID      uint
	Admin    bool
}

type Credentials interface {
	Get(*Config) (DBCreds, error)
}

type SessionPool struct {
	Mu   sync.Mutex
	Pool map[int64]*AuthObject
}

func auth(cfg *Config, creds Credentials, name string, password []byte) (ok bool, a *AuthObject) {
	a = new(AuthObject)

	d, err := creds.Get(cfg)
	if err != nil {
		return
	}

	if d.GID == 0 || d.UID == 0 {
		return
	}

	ok, err = crypto.PasswordVerify(password, d.Password)
	if err != nil {
		ok = false
		return
	}
	a.Name = name
	a.UID = d.UID
	a.GID = d.GID
	a.Admin = d.Admin

	if a.Admin && a.GID == SuperGid {
		a.Super = true
	}
	return
}

func (s *SessionPool) New(cfg *Config, name string, password []byte,
	creds Credentials) (ok bool, id int64) {

	ok, a := auth(cfg, creds, name, password)
	if !ok {
		return
	}

	id, err := s.create(a)
	if err != nil {
		cfg.Log(1, err)
	}
	s.NextKey(id)
	return
}

func (s *SessionPool) NextKey(id int64) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if _, ok := s.Pool[id]; !ok {
		return
	}
	// Chance of collision is negligable, but a collision would break the session
	for {
		buf := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			return
		}
		a := s.Pool[id]
		if !a.SessionKey.Compare(buf) {
			a.SessionKey = buf
			s.Pool[id] = a
			s.Pool[id].SessionTime = time.Now()
			break
		}
	}
	return
}

func (s *SessionPool) Validate(id int64, msgMac string, url string, message []byte) (ok bool) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if _, ok = s.Pool[id]; !ok {
		return
	}
	key := s.Pool[id].SessionKey
	ok = crypto.VerifyMAC(key, msgMac, url, message)
	if !ok {
		return
	}
	if s.expired(id) {
		return false
	}
	return
}

func (s *SessionPool) Pruner() {
	for {
		time.Sleep(time.Second * 90)
		s.Mu.Lock()
		for id := range s.Pool {
			if s.expired(id) {
				delete(s.Pool, id)
			}
		}
		s.Mu.Unlock()
	}
}

func (s *SessionPool) create(a *AuthObject) (id int64, err error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	// We do this in a loop to guarentee uniqueness
	for {
		id, err = crypto.RandomInt()
		if err != nil {
			return
		}
		if _, ok := s.Pool[id]; !ok {
			if s.Pool == nil {
				s.Pool = make(map[int64]*AuthObject)
			}
			s.Pool[id] = a
			break
		}
	}
	s.Pool[id].SessionTime = time.Now()
	return
}

func (s *SessionPool) expired(id int64) bool {
	dur := time.Now().Sub(s.Pool[id].SessionTime)
	if dur.Seconds() >= float64(sessionExpiry) {
		return true
	} else {
		return false
	}
}
