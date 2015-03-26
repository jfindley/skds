package shared

import (
	"testing"
)

func TestConfig(t *testing.T) {
	cfg := new(Config)
	cfg.Startup.Dir = "/test"
	cfg.Startup.Address = "127.0.0.1"
	cfg.Startup.Crypto.Key = "keyfile"
	cfg.Startup.Crypto.Cert = "/certfile"
	cfg.Runtime.Password = []byte("test pass")

	data, err := cfg.Encode()
	if err != nil {
		t.Fatal(err)
	}

	readCfg := new(Config)
	err = readCfg.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	if readCfg.Startup.Address != "127.0.0.1" {
		t.Error("Startup not read correctly")
	}

	if readCfg.Startup.Crypto.Key != "/test/keyfile" {
		t.Error("Startup not read correctly")
	}

	if readCfg.Startup.Crypto.Cert != "/certfile" {
		t.Error("Startup not read correctly")
	}

	if readCfg.Runtime.Password != nil {
		t.Error("Runtime data read from file")
	}
}
