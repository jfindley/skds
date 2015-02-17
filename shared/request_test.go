package shared

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func init() {
	// httptest doesn't appear to support ECDHE cipher suites
	ciphers = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}

}

func TestGet(t *testing.T) {
	cfg := new(Config)

	msg := new(Message)
	msg.Response = "Test message"

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerSig = new(Binary)
	cfg.Runtime.ServerSig.New(ts.TLS.Certificates[0].Certificate[0])

	s := new(Session)
	err = s.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := s.Get(ts.URL)
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
	cfg := new(Config)

	msg := new(Message)
	msg.Response = "Test message"

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		if string(body) == "Test request" {
			w.Write(data)
		} else {
			w.Write(nil)
		}
	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerSig = new(Binary)
	cfg.Runtime.ServerSig.New(ts.TLS.Certificates[0].Certificate[0])

	s := new(Session)
	err = s.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := s.Post(ts.URL, []byte("Test request"))
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
