package functions

import (
	"errors"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

func superPubKey(cfg *shared.Config) (key crypto.Key, err error) {
	resp, err := cfg.Session.Get("/key/public/get/super")
	if err != nil {
		return
	}

	if len(resp) != 1 {
		return key, errors.New("Bad response from server")
	}

	key.Pub = new([32]byte)

	for i := range resp[0].Key.Key {
		key.Pub[i] = resp[0].Key.Key[i]
	}
	return
}

func userPubKey(cfg *shared.Config, name string, admin bool) (key crypto.Key, err error) {
	var msg shared.Message

	msg.User.Name = name
	msg.User.Admin = admin

	resp, err := cfg.Session.Post("/key/public/get/user", msg)
	if err != nil {
		return
	}

	if len(resp) != 1 {
		return key, errors.New("Bad response from server")
	}

	key.Pub = new([32]byte)

	for i := range resp[0].Key.UserKey {
		key.Pub[i] = resp[0].Key.UserKey[i]
	}
	return
}

func groupPubKey(cfg *shared.Config, name string, admin bool) (key crypto.Key, err error) {
	var msg shared.Message

	msg.User.Group = name
	msg.User.Admin = admin

	resp, err := cfg.Session.Post("/key/public/get/group", msg)
	if err != nil {
		return
	}

	if len(resp) != 1 {
		return key, errors.New("Bad response from server")
	}

	key.Pub = new([32]byte)

	for i := range resp[0].Key.GroupPub {
		key.Pub[i] = resp[0].Key.GroupPub[i]
	}
	return
}

func groupPrivKey(cfg *shared.Config, name string, admin bool) (key crypto.Key, err error) {
	var msg shared.Message

	msg.User.Group = name
	msg.User.Admin = admin

	resp, err := cfg.Session.Post("/key/private/get/group", msg)
	if err != nil {
		return
	}

	if len(resp) != 1 {
		return key, errors.New("Bad response from server")
	}

	buf, err := crypto.Decrypt(cfg.Session.GroupKey, cfg.Runtime.Keypair)
	if err != nil {
		return key, errors.New("Unable to decrypt super key")
	}

	defer crypto.Zero(buf)

	superKey := new(crypto.Key)

	superKey.Priv = new([32]byte)

	for i := range buf {
		superKey.Priv[i] = buf[i]
	}

	defer superKey.Zero()

	privKey, err := crypto.Decrypt(resp[0].Key.GroupPriv, superKey)
	if err != nil {
		return key, errors.New("Unable to decrypt group key")
	}

	defer crypto.Zero(privKey)

	key.Priv = new([32]byte)

	for i := range privKey {
		key.Priv[i] = privKey[i]
	}
	return
}

func secretPrivKey(cfg *shared.Config, name string) (key crypto.Key, err error) {
	var msg shared.Message
	msg.Key.Name = name

	resp, err := cfg.Session.Post("/key/private/get/secret", msg)
	if err != nil {
		return
	}

	if len(resp) != 1 {
		return key, errors.New("Bad response from server")
	}

	var data []byte
	defer crypto.Zero(data)

	if resp[0].Key.UserKey != nil {
		data, err = crypto.Decrypt(resp[0].Key.UserKey, cfg.Runtime.Keypair)
	} else {
		buf, err := crypto.Decrypt(cfg.Session.GroupKey, cfg.Runtime.Keypair)
		if err != nil {
			return key, errors.New("Unable to decrypt group key")
		}

		defer crypto.Zero(buf)

		if len(buf) != 32 {
			return key, errors.New("Group key not 32 bytes")
		}

		groupKey := new(crypto.Key)
		groupKey.Priv = new([32]byte)
		for i := range buf {
			groupKey.Priv[i] = buf[i]
		}

		defer groupKey.Zero()

		data, err = crypto.Decrypt(resp[0].Key.GroupPriv, groupKey)
	}
	if err != nil {
		return key, errors.New("Unable to decrypt private key")
	}

	key.Priv = new([32]byte)
	for i := range data {
		key.Priv[i] = data[i]
	}

	return
}
