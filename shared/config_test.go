package shared

import (
	"testing"
)

func TestConfig(t *testing.T) {
	cfg := new(Config)
	cfg.Startup.Address = "127.0.0.1"
	cfg.Startup.Crypto.Key = "keyfile"
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

	if readCfg.Startup.Crypto.Key != "keyfile" {
		t.Error("Startup not read correctly")
	}

	if readCfg.Runtime.Password != nil {
		t.Error("Runtime data read from file")
	}
}
