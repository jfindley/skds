// Package crypto handles all the cryptographical functions for SKDS.
// auth.go handles authentication functions.
// crypto.go handles general purpose encryption/decryption.
// encoding.go handles encoding and decoding of generic binary data.
// x509.go handles x509 certificates and ECDSA keys.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// TLSKey is a ECDSA private key.
type TLSKey struct {
	key *ecdsa.PrivateKey
}

// TLSPubKey is a ECDSA public key.
type TLSPubKey struct {
	key *ecdsa.PublicKey
}

// TLSCert is a x509 certificate.
type TLSCert struct {
	cert *x509.Certificate
}

// CertPool is a Certificate pool.
// We have to maintain our own certs slice as well as the pool object,
// as there's no method to get the original certs out of a pool.
type CertPool struct {
	CA    *x509.CertPool
	certs []*x509.Certificate
}

// Generate generates a new TLSKey
func (t *TLSKey) Generate() (err error) {
	t.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return
}

// Public creates a public key from a private key
func (t *TLSKey) Public() TLSPubKey {
	var pub TLSPubKey
	pub.key = &t.key.PublicKey
	return pub
}

// Encode PEM-encodes a key to be written to disk.
func (t *TLSKey) Encode() (data []byte, err error) {
	der, err := x509.MarshalECPrivateKey(t.key)
	if err != nil {
		return
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der})
	if data == nil {
		return nil, errors.New("Unable to encode key")
	}
	return
}

// Decode reads a PEM-encoded key.
func (t *TLSKey) Decode(data []byte) (err error) {
	defer Zero(data)
	t.key = new(ecdsa.PrivateKey)
	pemData, _ := pem.Decode(data)
	if len(pemData.Bytes) == 0 {
		err = errors.New("Invalid key data")
		return
	}
	t.key, err = x509.ParseECPrivateKey(pemData.Bytes)
	return
}

// Generate generates a new x509 certificate.
// For self-signed certs, leave caCert nil
func (t *TLSCert) Generate(name string, isCa bool, years int, pubKey TLSPubKey,
	privKey *TLSKey, caCert *TLSCert) (err error) {

	now := time.Now()

	template := x509.Certificate{
		// Serial must be unique - however there's no practical chance of collision here
		SerialNumber: new(big.Int).SetInt64(now.UnixNano()),
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
		template.MaxPathLen = 0
		template.KeyUsage = x509.KeyUsageCertSign
	}
	if caCert == nil {
		caCert = new(TLSCert)
		caCert.cert = &template
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert.cert, pubKey.key, privKey.key)
	if err != nil {
		return
	}
	t.cert, err = x509.ParseCertificate(derBytes)
	return
}

// Encode PEM-encodes a certificate to be written to disk.
func (t *TLSCert) Encode() (data []byte, err error) {
	data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.cert.Raw})
	if data == nil {
		return nil, errors.New("Unable to encode cert")
	}
	return
}

// Decode reads a PEM-encoded certificate.
func (t *TLSCert) Decode(data []byte) (err error) {
	t.cert = new(x509.Certificate)
	pemData, _ := pem.Decode(data)
	if len(pemData.Bytes) == 0 {
		err = errors.New("Invalid cert data")
		return
	}
	t.cert, err = x509.ParseCertificate(pemData.Bytes)
	return
}

// TLSCertKeyPair creates a TLS cert object from a cert and key.
func TLSCertKeyPair(cert *TLSCert, key *TLSKey) (tlsCert []tls.Certificate) {
	tlsCert = make([]tls.Certificate, 1)

	tlsCert[0].Certificate = append(tlsCert[0].Certificate, cert.cert.Raw)
	tlsCert[0].PrivateKey = key.key
	return tlsCert
}

// New creates a new certpool from 1 or more certs
func (c *CertPool) New(certs ...*TLSCert) {
	c.CA = x509.NewCertPool()
	c.certs = make([]*x509.Certificate, len(certs))

	for _, cert := range certs {
		c.certs[0] = cert.cert
		c.CA.AddCert(cert.cert)
	}
	return
}

// Encode PEM-encodes a cert pool to be written to disk.
func (c *CertPool) Encode() (data []byte, err error) {
	for i := range c.certs {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.certs[i].Raw})
		if block == nil {
			return nil, errors.New("Unable to encode subject")
		}
		data = append(data, block...)
	}
	return
}

// Decode reads an encoded cert pool.
func (c *CertPool) Decode(data []byte) (err error) {
	// We don't use AppendCertsFromPEM here so we can easily add to c.certs as we go
	c.CA = x509.NewCertPool()
	c.certs = make([]*x509.Certificate, 0)

	// Copy data to avoid modifying our input
	in := data
	for len(in) > 0 {
		var block *pem.Block
		block, in = pem.Decode(in)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		c.CA.AddCert(cert)
		c.certs = append(c.certs, cert)
	}
	if len(c.certs) == 0 {
		return errors.New("Invalid cert data")
	}
	return
}
