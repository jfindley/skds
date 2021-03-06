/*
Functions specifies a list of client functions, split out into different files based on API tree.
*/
package functions

import (
	"bytes"
	"io/ioutil"
	"os"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func GetCA(cfg *shared.Config) (ok bool) {
	// We wipe the CA here to skip TLS verification.
	cfg.Runtime.CA = nil
	resp, err := cfg.Session.Get("/ca")

	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	if len(resp) == 0 {
		cfg.Log(log.ERROR, "Empty response from server")
		return
	}
	if len(resp) > 1 {
		cfg.Log(log.ERROR, "Bad response from server")
		return
	}

	cfg.Runtime.CA = new(crypto.CertPool)

	err = cfg.Runtime.CA.Decode(resp[0].X509.Cert)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	err = shared.Write(cfg.Runtime.CA, cfg.Startup.Crypto.CACert)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func Register(cfg *shared.Config) (ok bool) {
	var msg shared.Message

	msg.User.Name = cfg.Startup.NodeName
	msg.User.Admin = false
	msg.User.Password = cfg.Runtime.Password
	msg.User.Key = cfg.Runtime.Keypair.Pub[:]

	_, err := cfg.Session.Post("/client/register", msg)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func GetSecrets(cfg *shared.Config) (ok bool) {
	resp, err := cfg.Session.Get("/client/secrets")

	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	if len(resp) == 0 {
		cfg.Log(log.INFO, "No secrets found")
		return true
	}

	for _, r := range resp {
		secretKey := new(crypto.Key)
		secretKey.Priv = new([32]byte)

		// If there is a group key, first decrypt that, and use it to
		// decrypt the secret key.  Otherwise just decrypt the secret
		// key directly.
		if r.Key.GroupPriv != nil {

			groupBuf, err := crypto.Decrypt(r.Key.GroupPriv, cfg.Runtime.Keypair)
			if err != nil {
				cfg.Log(log.ERROR, "Unable to decrypt group key:", err)
				return
			}

			groupKey := new(crypto.Key)
			groupKey.Priv = new([32]byte)

			copy(groupKey.Priv[:], groupBuf)
			crypto.Zero(groupBuf)

			buf, err := crypto.Decrypt(r.Key.Key, groupKey)
			// No matter what happens, zero the group key at this point
			groupKey.Zero()
			if err != nil {
				cfg.Log(log.ERROR, "Unable to decrypt secret key with group key:", err)
				return
			}

			copy(secretKey.Priv[:], buf)
			crypto.Zero(buf)

		} else {

			buf, err := crypto.Decrypt(r.Key.Key, cfg.Runtime.Keypair)
			if err != nil {
				cfg.Log(log.ERROR, "Unable to decrypt secret key:", err)
				return
			}

			copy(secretKey.Priv[:], buf)
			crypto.Zero(buf)

		}

		// Now decrypt the secret itself.
		secret, err := crypto.Decrypt(r.Key.Secret, secretKey)
		// No matter what happens, zero the secret key at this point
		secretKey.Zero()

		if err != nil {
			cfg.Log(log.ERROR, "Unable to decrypt secret:", err)
			return
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
				return
			}
			cfg.Log(log.INFO, "Created", r.Key.Path)
			return true

		case err != nil:
			cfg.Log(log.ERROR, "Error opening file", r.Key.Path, err)
			return

		default:
			if bytes.Compare(curr, secret) != 0 {
				cfg.Log(log.INFO, "Updating", r.Key.Path)
				// We don't use the usual shared.Write method here because we want
				// to write the raw secret to the disk, rather than encode it.
				err = ioutil.WriteFile(r.Key.Path, secret, os.FileMode(0600))
				if err != nil {
					cfg.Log(log.ERROR, "Unable to write file:", err)
					return
				}
			} else {
				cfg.Log(log.DEBUG, "File", r.Key.Path, "is up to date")
			}

		}

	}

	return true
}
