// Package auth handles the server-side authentication and session
// management.
package auth

import (
	"crypto/rand"
	"fmt"
	"github.com/jinzhu/gorm"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

var (
	// sessionExpiry is measured in seconds.
	sessionExpiry = 30
	pruneInterval = 90 * time.Second
)

// SessionInfo holds the details of the user of a session.
type SessionInfo struct {
	Name        string
	UID         uint
	GID         uint
	Admin       bool
	Super       bool
	SessionKey  crypto.Binary
	SessionTime time.Time
	mu          sync.Mutex
}

// CheckACL runs the lookup function of the specified object(s) and
// returns true only if the user has access to all objects specified.
func (a *SessionInfo) CheckACL(db gorm.DB, objects ...shared.ACL) bool {
	if a.Super {
		return true
	}
	var ok bool
	for _, o := range objects {
		ok = o.Lookup(db, a.UID, a.GID)
		if !ok {
			return false
		}
	}
	return ok
}

// NextKey rotates the key for a session.  We do this to reduce the window during
// which a key is used.
func (s *SessionInfo) NextKey() crypto.Binary {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Chance of collision is negligable, but a collision would break the session.
	for {
		buf := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, buf)
		if err != nil {
			return nil
		}
		if !s.SessionKey.Compare(buf) {
			s.SessionKey = buf
			s.SessionTime = time.Now()
			break
		}
	}
	return s.SessionKey
}

func (s *SessionInfo) GetName() string {
	return s.Name
}

func (s *SessionInfo) GetUID() uint {
	return s.UID
}

func (s *SessionInfo) GetGID() uint {
	return s.GID
}

func (s *SessionInfo) IsAdmin() bool {
	return s.Admin
}

func (s *SessionInfo) IsSuper() bool {
	return s.Super
}

// Credentials is a generic interface to return the stored credentials for a user.
type Credentials interface {
	GetName() string
	GetUID() uint
	GetGID() uint
	GetPass() crypto.Binary
	IsAdmin() bool
}

// Auth verifies a password avainst a credentials object.
func Auth(creds Credentials, pass []byte) (ok bool, sess *SessionInfo) {
	sess = new(SessionInfo)

	if creds.GetUID() == 0 {
		// User does not exist.
		return
	}

	ok, err := crypto.PasswordVerify(pass, creds.GetPass())
	if err != nil {
		return
	}

	sess.Name = creds.GetName()
	sess.UID = creds.GetUID()
	sess.GID = creds.GetGID()
	sess.Admin = creds.IsAdmin()
	if sess.Admin && sess.GID == shared.SuperGID {
		sess.Super = true
	}
	return
}

// SessionPool is the global pool of all sessions.
type SessionPool struct {
	mu   sync.Mutex
	Pool map[int64]*SessionInfo
}

// Add adds a session to the pool
func (s *SessionPool) Add(sess *SessionInfo) (id int64, err error) {
	id, err = s.create(sess)
	if err != nil {
		return
	}
	s.Pool[id].NextKey()
	return
}

// Get retrieves a session to the pool
func (s *SessionPool) Get(id int64) (sess *SessionInfo) {
	if _, ok := s.Pool[id]; !ok {
		return
	}
	return s.Pool[id]
}

// Validate checks that a message belongs to a session, and returns the session ID and request body.
// func (s *SessionPool) Validate(id int64, msgMac string, url string, message []byte) (ok bool) {
func (s *SessionPool) Validate(r *http.Request) (ok bool, id int64, body []byte) {
	mac := r.Header.Get(shared.HdrMAC)

	session := r.Header.Get(shared.HdrSession)
	if mac == "" || session == "" {
		return
	}
	id, err := strconv.ParseInt(session, 10, 64)
	if err != nil {
		println(err.Error())
		return
	}

	if r.Body != nil {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return
		}

		err = r.Body.Close()
		if err != nil {
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok = s.Pool[id]; !ok {
		return
	}

	ok = crypto.VerifyMAC(s.Pool[id].SessionKey, mac, r.RequestURI, body)
	if !ok {
		fmt.Println(r.Body)
		fmt.Println("bad mac", id, mac, r.RequestURI, body)
		return
	}

	if s.expired(id) {
		ok = false
	}
	return
}

// Pruner is a continuous loop that removes expired sessions.
func (s *SessionPool) Pruner() {
	for {
		time.Sleep(pruneInterval)
		s.mu.Lock()
		for id := range s.Pool {
			if s.expired(id) {
				delete(s.Pool, id)
			}
		}
		s.mu.Unlock()
	}
}

func (s *SessionPool) create(a *SessionInfo) (id int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// We do this in a loop to guarentee uniqueness
	for {
		id, err = crypto.RandomInt()
		if err != nil {
			return
		}
		if _, ok := s.Pool[id]; !ok {
			if s.Pool == nil {
				s.Pool = make(map[int64]*SessionInfo)
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
	}
	return false
}
