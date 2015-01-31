package crypto

import (
	"crypto/x509"
	"testing"
)

func TestGenKey(t *testing.T) {
	key, err := GenKey()
	if err != nil {
		t.Fatal(err)
	}
	if !key.IsOnCurve(key.X, key.Y) {
		t.Fatal("Key is not on curve")
	}
}

func TestGenCert(t *testing.T) {
	key, err := GenKey()
	if err != nil {
		t.Fatal(err)
	}

	ca, err := GenCert("selfsigned", true, 1, &key.PublicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := GenCert("casigned", false, 1, &key.PublicKey, key, ca)
	if err != nil {
		t.Fatal(err)
	}

	if !ca.IsCA {
		t.Error("CA cert not a CA")
	}

	if cert.IsCA {
		t.Error("Cert is a CA")
	}

	_, err = cert.Verify(x509.VerifyOptions{Roots: CaPool(ca)})
	if err != nil {
		t.Error("Failed to verify cert")
	}
}
