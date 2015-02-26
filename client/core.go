package main

import (
	"crypto/x509"
	"encoding/json"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/messages"
	"github.com/jfindley/skds/shared"
	"github.com/jfindley/skds/transport"
)

func GetCa(cfg *config.Config) (cert *x509.Certificate, err error) {
	resp, err := transport.Request(cfg, "ca", nil)
	if err != nil {
		return nil, err
	}
	return shared.CertDecode(resp.Data)
}

// Returns an authorised client certificate
func Register(cfg *config.Config) (cert *x509.Certificate, err error) {
	var msg messages.Client
	msg.Action = "register"
	msg.Auth.Type = "client"
	msg.Auth.Name = cfg.Startup.Name
	msg.Key = cfg.Runtime.PublicKey

	resp, err := transport.Request(cfg, "client", msg)
	if err != nil {
		return nil, err
	}
	return shared.CertDecode(resp.Data)
}

func Get(cfg *config.Config) (err error) {
	var msg messages.Client
	msg.Action = "get"
	msg.Auth.Type = "client"
	msg.Auth.Name = cfg.Startup.Name

	resp, err := transport.Request(cfg, "client", msg)
	if err != nil {
		return
	}
	keyList := make([]messages.Key, 0)
	err = json.Unmarshal(resp.Data, &keyList)
	if err != nil {
		cfg.Log(1, "Unable to parse response")
		return
	}
	for _, k := range keyList {
		rawKey, err := crypto.AsymmetricDecrypt(
			shared.HexDecode(k.Key),
			shared.HexDecode(k.PubKey),
			cfg.Runtime.PrivateKey,
		)
		if err != nil {
			cfg.Log(0, "Unable to decrypt key for", k.Name)
			cfg.Log(3, err)

			cfg.Log(3, string(crypto.Hash(cfg.Runtime.PublicKey)))

			continue
		}
		defer crypto.Zero(rawKey)
		rawSecret, err := crypto.SymmetricDecrypt(
			shared.HexDecode(k.Secret),
			rawKey,
		)
		if err != nil {
			cfg.Log(0, "Unable to decrypt", k.Name)
			cfg.Log(3, err)
			continue
		}
		defer crypto.Zero(rawSecret)
		cfg.Log(2, k.Name, k.Path)
		cfg.Log(2, string(rawSecret))

	}

	return
}
