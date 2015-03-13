package shared

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
)

func ret200(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}

func TestNew(t *testing.T) {
	cfg = new(Config)

	cfg.Runtime.Key = new(crypto.TLSKey)
	cfg.Runtime.Cert = new(crypto.TLSCert)
	cfg.Runtime.Key.Generate()
	cfg.Runtime.Cert.Generate("test", false, 1, cfg.Runtime.Key.Public(), cfg.Runtime.Key, nil)

	srv := new(Server)
	srv.New(cfg)

	if srv.Mux == nil {
		t.Error("No mux created")
	}

	if srv.server == nil {
		t.Error("No server created")
	}

	if srv.tls == nil {
		t.Error("No TLS config created")
	}
}

func TestStart(t *testing.T) {
	cfg = new(Config)

	cfg.Runtime.CAKey = new(crypto.TLSKey)
	cfg.Runtime.Key = new(crypto.TLSKey)

	cfg.Runtime.Cert = new(crypto.TLSCert)
	cfg.Runtime.CACert = new(crypto.TLSCert)
	cfg.Runtime.CA = new(crypto.CertPool)

	cfg.Runtime.CAKey.Generate()
	cfg.Runtime.Key.Generate()

	cfg.Runtime.CACert.Generate("test-ca", true, 2, cfg.Runtime.CAKey.Public(), cfg.Runtime.CAKey, nil)
	cfg.Runtime.CA.New(cfg.Runtime.CACert)

	cfg.Runtime.Cert.Generate("localhost", false, 1, cfg.Runtime.Key.Public(), cfg.Runtime.CAKey, cfg.Runtime.CACert)

	cfg.Startup.Address = "localhost:8443"

	data, err := cfg.Runtime.Cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pemData, _ := pem.Decode(data)
	if len(pemData.Bytes) == 0 {
		t.Fatal("Invalid cert data")
	}
	serverCert, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.ServerCert = serverCert.Raw
	cfg.Startup.Crypto.ServerCert = "test"

	srv := new(Server)
	err = srv.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	srv.Mux.HandleFunc("/", ret200)

	srv.Start()

	err = cfg.Session.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cfg.Session.Get("/")
	if err != nil {
		t.Fatal(err)
	}

	srv.Stop()
}

func TestCustomDialer(t *testing.T) {
	cfg = new(Config)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerCert = ts.TLS.Certificates[0].Certificate[0]

	s := new(Session)
	err = s.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := s.client.Get(strings.Replace(ts.URL, "https", "http", 1))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Wrong status code:", resp.StatusCode)
	}
}
