package shared

import (
	"encoding/json"
	"github.com/jinzhu/gorm"
	"net/http"
	"strconv"

	"github.com/jfindley/skds/crypto"
)

type Key struct {
	Name      string `json:",omitempty"`
	Client    string `json:",omitempty"`
	Admin     string `json:",omitempty"`
	Path      string `json:",omitempty"`
	Key       []byte `json:",omitempty"`
	Secret    []byte `json:",omitempty"`
	UserKey   []byte `json:",omitempty"`
	GroupPub  []byte `json:",omitempty"`
	GroupPriv []byte `json:",omitempty"`
}

type User struct {
	Name     string `json:",omitempty"`
	Admin    bool   `json:",omitempty"`
	Group    string `json:",omitempty"`
	Password []byte `json:",omitempty"`
	Key      []byte `json:",omitempty"`
}

type X509 struct {
	Name string `json:",omitempty"`
	Cert []byte `json:",omitempty"`
}

type Auth struct {
	Name     string `json:",omitempty"`
	Password []byte `json:",omitempty"`
}

type Message struct {
	Key      Key    `json:",omitempty"`
	User     User   `json:",omitempty"`
	X509     X509   `json:"x509,omitempty"`
	Auth     Auth   `json:",omitempty"`
	Response string `json:",omitempty"`
}

// ACL returns true if the UID/GID pair should be allowed access to the subject.
type ACL interface {
	Lookup(gorm.DB, uint, uint) bool
}

type ClientSession interface {
	GetName() string
	GetUID() uint
	GetGID() uint
	IsAdmin() bool
	IsSuper() bool
	NextKey() crypto.Binary
	CheckACL(gorm.DB, ...ACL) bool
}

type Request struct {
	Req     Message
	Headers http.Header
	Session ClientSession
	writer  http.ResponseWriter
}

// New reads the request body and headers from the client request, and sets the
// response writer.
func (r *Request) Parse(body []byte, resp http.ResponseWriter) bool {
	r.writer = resp
	err := json.Unmarshal(body, &r.Req)
	if err != nil && len(body) > 0 {
		return false
		http.Error(r.writer, "Unable to parse request", http.StatusBadRequest)
	}
	return true
}

func (r *Request) SetSessionID(id int64) {
	r.writer.Header().Set(HdrSession, strconv.FormatInt(id, 10))
}

// Reply sends a response to a request.  We never return anything, as there's
// no useful handling the server can do if our response fails.
func (r *Request) Reply(code int, messages ...Message) {
	var body []byte

	for _, msg := range messages {
		data, err := json.Marshal(msg)
		if err != nil {
			http.Error(r.writer, "Error sending response", http.StatusInternalServerError)
			return
		}
		body = append(body, data...)
	}

	if r.Session != nil {
		key := r.Session.NextKey()
		enc, err := key.Encode()
		if err != nil {
			http.Error(r.writer, "Error sending response", http.StatusInternalServerError)
			return
		}

		r.writer.Header().Set(HdrKey, string(enc))
	}

	r.writer.WriteHeader(code)

	// Although this can fail, there's no sensible way of handling it.
	r.writer.Write(body)
}

// RespMessage creates a message with a given response string.
func RespMessage(r string) (m Message) {
	m.Response = r
	return
}
