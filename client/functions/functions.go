package functions

import (
	"bytes"
	"io/ioutil"
	"os"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func GetCA(cfg *shared.Config, url string) bool {
	// We wipe the CA here to skip TLS verification.
	cfg.Runtime.CA = nil
	resp, err := cfg.Session.Get(url)

	if err != nil {
		cfg.Log(log.ERROR, err)
		return false
	}
	if len(resp) == 0 {
		cfg.Log(log.ERROR, "Empty response from server")
		return false
	}
	if len(resp) > 1 {
		cfg.Log(log.ERROR, "Bad response from server")
		return false
	}

	cfg.Runtime.CA = new(crypto.CertPool)

	err = cfg.Runtime.CA.Decode(resp[0].X509.Cert)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return false
	}

	err = shared.Write(cfg.Runtime.CA, cfg.Startup.Crypto.CACert)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return false
	}

	return true
}

func Register(cfg *shared.Config, url string) bool {
	var msg shared.Message

	msg.User.Name = cfg.Startup.Hostname
	msg.User.Admin = false
	msg.User.Password = cfg.Runtime.Password
	msg.User.Key = cfg.Runtime.Keypair.Pub[:]

	_, err := cfg.Session.Post(url, msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return false
	}

	return true
}

func GetSecrets(cfg *shared.Config, url string) (ok bool) {
	resp, err := cfg.Session.Get(url)

	if err != nil {
		cfg.Log(log.ERROR, err)
		return false
	}
	if len(resp) == 0 {
		cfg.Log(log.INFO, "No secrets found")
		return true
	}

	for _, r := range resp {
		secretKey := new(crypto.Key)

		// If there is a group key, first decrypt that, and use it to
		// decrypt the secret key.  Otherwise just decrypt the secret
		// key directly.
		if r.Key.GroupPriv != nil {

			groupKeyEnc, err := crypto.Decrypt(r.Key.GroupPriv, cfg.Runtime.Keypair)
			if err != nil {
				cfg.Log(log.ERROR, "Unable to decrypt group key:", err)
				return false
			}

			groupKey := new(crypto.Key)
			err = groupKey.Decode(groupKeyEnc)
			// No matter what happens, zero the group key at this point
			crypto.Zero(groupKeyEnc)
			if err != nil {
				cfg.Log(log.ERROR, "Error decoding group key:", err)
				return false
			}

			secretKeyEnc, err := crypto.Decrypt(r.Key.Key, groupKey)
			// No matter what happens, zero the group key at this point
			groupKey.Zero()
			if err != nil {
				cfg.Log(log.ERROR, "Unable to decrypt secret key with group key:", err)
				return false
			}

			err = secretKey.Decode(secretKeyEnc)
			// No matter what happens, zero the secret key at this point
			crypto.Zero(secretKeyEnc)
			if err != nil {
				cfg.Log(log.ERROR, "Error decoding secret key:", err)
				return false
			}

		} else {

			secretKeyEnc, err := crypto.Decrypt(r.Key.Key, cfg.Runtime.Keypair)
			if err != nil {
				cfg.Log(log.ERROR, "Unable to decrypt secret key:", err)
				return false
			}

			err = secretKey.Decode(secretKeyEnc)
			// No matter what happens, zero the secret key at this point
			crypto.Zero(secretKeyEnc)
			if err != nil {
				cfg.Log(log.ERROR, "Error decoding secret key:", err)
				return false
			}

		}

		// Now decrypt the secret itself.
		secret, err := crypto.Decrypt(r.Key.Secret, secretKey)
		// No matter what happens, zero the secret key at this point
		secretKey.Zero()

		if err != nil {
			cfg.Log(log.ERROR, "Unable to decrypt secret:", err)
			return false
		}

		defer crypto.Zero(secret)

		cfg.Log(log.DEBUG, "Processing file", r.Key.Path)

		curr, err := ioutil.ReadFile(r.Key.Path)
		switch {

		case os.IsNotExist(err):
			// We don't use the usual shared.Write method here because we want
			// to write the raw secret to the disk, rather than encode it.
			err = ioutil.WriteFile(r.Key.Path, secret, os.FileMode(0600))
			if err != nil {
				cfg.Log(log.ERROR, "Unable to write file:", err)
				return false
			}
			cfg.Log(log.INFO, "Created", r.Key.Path)
			return true

		case err != nil:
			cfg.Log(log.ERROR, "Error opening file", r.Key.Path, err)
			return false

		default:
			if bytes.Compare(curr, secret) != 0 {
				cfg.Log(log.INFO, "Updating", r.Key.Path)
				// We don't use the usual shared.Write method here because we want
				// to write the raw secret to the disk, rather than encode it.
				err = ioutil.WriteFile(r.Key.Path, secret, os.FileMode(0600))
				if err != nil {
					cfg.Log(log.ERROR, "Unable to write file:", err)
					return false
				}
			} else {
				cfg.Log(log.DEBUG, "File", r.Key.Path, "is up to date")
			}

		}

	}

	return true
}
