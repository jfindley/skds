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

func secretPubKey(cfg *shared.Config, name string) (key crypto.Key, err error) {
	var msg shared.Message
	msg.Key.Name = name

	resp, err := cfg.Session.Post("/key/public/get/secret", msg)
	if err != nil {
		return
	}

	if len(resp) != 1 {
		return key, errors.New("Bad response from server")
	}

	copy(key.Pub[:], resp[0].Key.Key)

	return
}
