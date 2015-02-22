package shared

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
)

var (
	err error
	cfg *Config
)

func init() {
	// httptest doesn't appear to support ECDHE cipher suites
	ciphers = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
	cfg = new(Config)
}

func TestGet(t *testing.T) {
	cfg.Init()

	cfg.Session.sessionKey = []byte("qwerty1234")

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msgMac := r.Header.Get(hdrMAC)

		if !crypto.VerifyMAC(cfg.Session.sessionKey, msgMac, r.RequestURI, nil) {

			t.Error("MAC not valid")
			w.WriteHeader(http.StatusForbidden)

		} else {

			msg := new(Message)
			msg.Response = "Test message"

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatal(err)
			}

			w.Write(data)

		}
	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerCert = ts.TLS.Certificates[0].Certificate[0]

	err = cfg.Session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := cfg.Session.Get("/")
	if err != nil {
		t.Fatal(err)
	}

	if len(resp) != 1 {
		t.Fatal("Bad response count")
	}
	if resp[0].Response != "Test message" {
		t.Error("Bad response body")
	}
}

func TestPost(t *testing.T) {
	cfg.Init()

	cfg.Session.sessionKey = []byte("qwerty1234")

	var req Message
	req.User.Name = "test"

	reqData, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}

		msg := new(Message)
		msg.Response = "Test message"

		resp, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}

		msgMac := r.Header.Get(hdrMAC)

		switch {

		case !crypto.VerifyMAC(cfg.Session.sessionKey, msgMac, r.RequestURI, body):
			t.Error("MAC not valid")
			w.WriteHeader(http.StatusForbidden)

		case bytes.Compare(reqData, body) != 0:
			t.Error("Data does not match")
			w.WriteHeader(http.StatusBadRequest)

		default:
			w.Write(resp)

		}
	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerCert = ts.TLS.Certificates[0].Certificate[0]

	err = cfg.Session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := cfg.Session.Post("/", req)
	if err != nil {
		t.Fatal(err)
	}

	if len(resp) != 1 {
		t.Fatal("Bad response count")
	}
	if resp[0].Response != "Test message" {
		t.Error("Bad response body")
	}

}

func TestLogin(t *testing.T) {
	cfg.Init()

	cfg.Startup.User = "test login"
	cfg.Runtime.Password = []byte("test password")

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := new(Message)
		recieved := new(Message)

		expected.Auth.Name = cfg.Startup.User
		expected.Auth.Password = cfg.Runtime.Password

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(body, recieved)

		switch {
		case err != nil:
			t.Error("Unable to unmarsal response")
			w.WriteHeader(http.StatusForbidden)

		case recieved.Auth.Name != expected.Auth.Name:
			t.Error("Name does not match")
			w.WriteHeader(http.StatusForbidden)

		case bytes.Compare(recieved.Auth.Password, expected.Auth.Password) != 0:
			t.Error("Password does not match")
			w.WriteHeader(http.StatusForbidden)

		default:
			w.Header().Set(hdrSession, "1")
			w.WriteHeader(200)
		}

	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerCert = ts.TLS.Certificates[0].Certificate[0]

	err := cfg.Session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err = cfg.Session.Login(cfg); err != nil {
		t.Error(err)
	}

	if cfg.Session.sessionID == 0 {
		t.Error("SessionID not set")
	}

	if cfg.Session.sessionKey == nil {
		t.Error("SessionKey not set")
	}
}
