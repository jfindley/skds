package auth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"skds/config"
	"skds/crypto"
	"skds/server/db"
	"skds/shared"
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
	SessionKey  []byte
	SessionTime time.Time
}

type Authfunc func(*config.Config, string, []byte) (bool, AuthObject)

type SessionPool struct {
	Mu   sync.Mutex
	Pool map[int64]*AuthObject
}

func Admin(cfg *config.Config, name string, password []byte) (ok bool, a AuthObject) {
	var admin db.Admins
	q := cfg.Runtime.DB.Where("name = ?", name).First(&admin)
	if q.RecordNotFound() {
		return
	}
	if q.Error != nil {
		cfg.Log(1, q.Error)
		return
	}
	ok, err := crypto.PasswordVerify(password, admin.Password)
	if err != nil {
		cfg.Log(1, err)
		ok = false
		return
	}
	if !ok {
		return
	}

	a.Admin = true
	a.Name = name
	a.UID = admin.Id
	a.GID = admin.Gid
	if admin.Gid == config.SuperGid {
		a.Super = true
	}
	return
}

func Client(cfg *config.Config, name string, password []byte) (ok bool, a AuthObject) {
	var client db.Clients
	q := cfg.Runtime.DB.Where("name = ?", name).First(&client)
	if q.RecordNotFound() {
		return
	}
	if q.Error != nil {
		cfg.Log(1, q.Error)
		return
	}
	ok, err := crypto.PasswordVerify(password, client.Password)
	if err != nil {
		cfg.Log(1, err)
		ok = false
		return
	}
	if !ok {
		return
	}

	a.Admin = false
	a.Name = name
	a.UID = client.Id
	a.GID = client.Gid
	return
}

func (s *SessionPool) New(cfg *config.Config, name string, password []byte,
	authfunc Authfunc) (ok bool, id int64) {

	var a AuthObject

	ok, a = authfunc(cfg, name, password)
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
		newKey := shared.HexEncode(buf)
		if bytes.Compare(a.SessionKey, newKey) != 0 {
			a.SessionKey = newKey
			s.Pool[id] = a
			s.Pool[id].SessionTime = time.Now()
			break
		}
	}
	return
}

func (s *SessionPool) Validate(id int64, msgMac, message []byte) (ok bool) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if _, ok = s.Pool[id]; !ok {
		return
	}
	key := s.Pool[id].SessionKey
	ok = crypto.VerifyMAC(key, msgMac, message)
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

func (s *SessionPool) create(a AuthObject) (id int64, err error) {
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
			s.Pool[id] = &a
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
