package functions

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func TestGetCA(t *testing.T) {
	key := new(crypto.TLSKey)
	cert := new(crypto.TLSCert)

	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cert.Generate("test", true, 1, key.Public(), key, nil)
	if err != nil {
		t.Fatal(err)
	}

	var resp shared.Message
	resp.X509.Cert, err = cert.Encode()
	if err != nil {
		t.Fatal(err)
	}

	ts := testGet(200, resp)
	defer ts.Close()
	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")

	fh, err := ioutil.TempFile(os.TempDir(), "skds_client")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Startup.Crypto.CACert = fh.Name()

	defer os.Remove(cfg.Startup.Crypto.CACert)

	cfg.Session.New(cfg)

	ok := GetCA(cfg, "/ca")
	if !ok {
		t.Fatal("Failed to get CA")
	}

	data, err := ioutil.ReadFile(cfg.Startup.Crypto.CACert)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(resp.X509.Cert, data) != 0 {
		t.Error("Certificate does not match response.")
	}
}
