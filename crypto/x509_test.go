package crypto

import (
	"bytes"
	"testing"
)

func TestTLSKey(t *testing.T) {
	key1 := new(TLSKey)
	key2 := new(TLSKey)

	err := key1.Generate()
	if err != nil {
		t.Fatal(err)
	}

	data, err := key1.Encode()
	if err != nil {
		t.Fatal(err)
	}

	k1 := make([]byte, len(data))
	copy(k1, data)

	if data == nil {
		t.Fatal("No data returned")
	}

	err = key2.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	if !isZero(data) {
		t.Fatal("PEM data not zeroed")
	}

	k2, err := key2.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(k1, k2) != 0 {
		t.Error("Keys do not match")
	}

}

func TestTLSCert(t *testing.T) {
	key1 := new(TLSKey)
	cert1 := new(TLSCert)
	cert2 := new(TLSCert)

	err := key1.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cert1.Generate("cert1", false, 1, &key1.Key.PublicKey, key1.Key, nil)
	if err != nil {
		t.Fatal(err)
	}

	data, err := cert1.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if data == nil {
		t.Fatal("No data returned")
	}

	err = cert2.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	c2, err := cert2.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, c2) != 0 {
		t.Error("Certs do not match")
	}

}

func TestCertPool(t *testing.T) {
	key1 := new(TLSKey)
	cert1 := new(TLSCert)
	cert2 := new(TLSCert)
	pool := new(CertPool)

	err := key1.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cert1.Generate("cert1", false, 1, &key1.Key.PublicKey, key1.Key, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = cert2.Generate("cert2", false, 1, &key1.Key.PublicKey, key1.Key, nil)
	if err != nil {
		t.Fatal(err)
	}

	data, err := cert1.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cert2.Encode()
	if err != nil {
		t.Fatal(err)
	}

	data = append(data, c2...)

	err = pool.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	p1, err := pool.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, p1) != 0 {
		t.Error("Pool does not match input")
	}

}
