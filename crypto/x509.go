// This is essentially a stub that allows us to generate a simple CA and certificate.
// Ultimately I'd like to expand this to provide full end to end x509 management, but
// that can wait for another day.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

type TLSKey struct {
	key *ecdsa.PrivateKey
}

type TLSPubKey struct {
	key *ecdsa.PublicKey
}

type TLSCert struct {
	cert *x509.Certificate
}

// We have to maintain our own certs slice as there's no method
// to get the original certs out of a pool.
type CertPool struct {
	CA    *x509.CertPool
	certs []*x509.Certificate
}

func (t *TLSKey) Generate() (err error) {
	t.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return
}

func (t *TLSKey) Public() TLSPubKey {
	var pub TLSPubKey
	pub.key = &t.key.PublicKey
	return pub
}

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

func (t *TLSCert) Encode() (data []byte, err error) {
	data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.cert.Raw})
	if data == nil {
		return nil, errors.New("Unable to encode cert")
	}
	return
}

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

func (c *CertPool) New(cert *TLSCert) {
	c.CA = x509.NewCertPool()
	c.certs = make([]*x509.Certificate, 1)
	c.certs[0] = cert.cert
	c.CA.AddCert(cert.cert)
	return
}

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

// We don't use AppendCertsFromPEM here so we can easily add to c.certs as we go
func (c *CertPool) Decode(data []byte) (err error) {
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
