package crypto

import (
	"bytes"
	"crypto/x509"
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

	err = cert1.Generate("cert1", false, 1, key1.Public(), key1, nil)
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
	pool1 := new(CertPool)
	pool2 := new(CertPool)

	err := key1.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = cert1.Generate("cert1", false, 1, key1.Public(), key1, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = cert2.Generate("cert2", false, 1, key1.Public(), key1, nil)
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

	err = pool1.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	p1, err := pool1.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(data, p1) != 0 {
		t.Error("Pool does not match input")
	}

	pool2.New(cert2)

	p2, err := pool2.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(c2, p2) != 0 {
		t.Error("Pool does not match input")
	}
}

func TestCertAuthority(t *testing.T) {
	cakey := new(TLSKey)
	key := new(TLSKey)

	ca := new(TLSCert)
	cert := new(TLSCert)

	pool := new(CertPool)

	err := cakey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	err = ca.Generate("ca", true, 2, cakey.Public(), cakey, nil)
	if err != nil {
		t.Fatal(err)
	}

	pool.New(ca)

	err = cert.Generate("localhost", false, 1, key.Public(), cakey, ca)
	if err != nil {
		t.Fatal(err)
	}

	_, err = cert.cert.Verify(x509.VerifyOptions{Roots: pool.CA})
	if err != nil {
		t.Error(err)
	}
}
