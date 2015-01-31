package shared

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestHex(t *testing.T) {
	testData := []byte("this is some test data")
	hex := HexEncode(testData)
	if bytes.Compare(testData, HexDecode(hex)) != 0 {
		t.Fatal("Hex encode/decode did not preserve data")
	}
}

func TestKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := KeyEncode(key)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := KeyDecode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.IsOnCurve(key.X, key.Y) {
		t.Error("Key not decoded correctly")
	}
}

func TestCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := genCert("test", true, false, 1, &key.PublicKey, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := CertEncode(cert)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := CertDecode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(cert.Raw, dec.Raw) != 0 {
		t.Fatal("Cert encode/decode did not preserve data")
	}
}

// Copied from skds/crypto
func genCert(name string, selfsigned bool, isCa bool, years int,
	pubKey *ecdsa.PublicKey, privKey *ecdsa.PrivateKey, caCert *x509.Certificate) (*x509.Certificate, error) {

	if !selfsigned && caCert == nil {
		return nil, errors.New("Missing CA Cert")
	}

	// Generate a serial from the time in nanoseconds * a random value from 0 to uint16
	now := time.Now()
	serial := new(big.Int).SetInt64(now.UnixNano())
	mul, err := rand.Int(rand.Reader, new(big.Int).SetInt64(1<<16-1))
	if err != nil {
		return nil, err
	}
	serial.Mul(serial, mul)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:    now.Add(-5 * time.Minute).UTC(),
		NotAfter:     now.AddDate(years, 0, 0).UTC(),
		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	if isCa {
		template.BasicConstraintsValid = true
		template.IsCA = true
		template.MaxPathLen = 1 // To allow future upgrades more seamlessly
		template.KeyUsage = x509.KeyUsageCertSign
	}

	if selfsigned {
		caCert = &template
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}
