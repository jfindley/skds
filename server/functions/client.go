/*
Functions specifies a list of server functions, split out into different files based on API tree.
Because the description of each function already exists in the dictionary package, until such a time
as the dictionary is removed, the purpose of a function will be documented in the dictionary package,
not here.
We do, however document the message we expect to recieve for each function.  All input messages are
shared.Message messages.
*/
package functions

import (
	"database/sql"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func ClientGetSecret(cfg *shared.Config, r shared.Request) {
	var err error

	// Get the group key
	var user db.Users
	q := cfg.DB.First(&user, r.Session.GetUID())
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	var groupPriv crypto.Binary
	err = groupPriv.Decode(user.GroupKey)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	// We select secrets owned directly and inherited via groups separately,
	// to make our SQL less confusing to follow.
	rows, err := cfg.DB.Table("MasterSecrets").Select(
		"MasterSecrets.name, MasterSecrets.secret, UserSecrets.path, UserSecrets.secret").Where(
		"UserSecrets.uid = ?", r.Session.GetUID()).Joins(
		"left join UserSecrets on MasterSecrets.id = UserSecrets.sid").Rows()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	userSecrets, err := clientSecretScanner(rows, nil)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	rows, err = cfg.DB.Table("MasterSecrets").Select(
		"MasterSecrets.name, MasterSecrets.secret, GroupSecrets.path, GroupSecrets.secret").Where(
		"GroupSecrets.gid = ?", r.Session.GetGID()).Joins(
		"left join GroupSecrets on MasterSecrets.id = GroupSecrets.sid").Rows()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	groupSecrets, err := clientSecretScanner(rows, groupPriv)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	secrets := make([]shared.Message, len(userSecrets)+len(groupSecrets))
	copy(secrets, userSecrets)
	copy(secrets[len(userSecrets):], groupSecrets)

	r.Reply(200, secrets...)
	return
}

/*
User.Name => name
User.Password => encrypted password
User.Key => public part of local key
*/
func ClientRegister(cfg *shared.Config, r shared.Request) {
	var user db.Users

	hash, err := crypto.PasswordHash(r.Req.User.Password)

	user.Name = r.Req.User.Name
	user.Admin = false

	if !newUser(cfg, user.Name, user.Admin) {
		r.Reply(409, shared.RespMessage("Username already exists"))
		return
	}

	user.Password, err = hash.Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	user.PubKey, err = crypto.NewBinary(r.Req.User.Key).Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	q := cfg.DB.Create(&user)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	r.Reply(204)
	return
}

func clientSecretScanner(rows *sql.Rows, groupKey []byte) (msgs []shared.Message, err error) {
	for rows.Next() {
		var m shared.Message
		var encSecret []byte
		var encKey []byte
		var secret crypto.Binary
		var key crypto.Binary

		err = rows.Scan(&m.Key.Name, &encSecret, &m.Key.Path, &encKey)
		if err != nil {
			return
		}

		err = secret.Decode(encSecret)
		if err != nil {
			return
		}

		err = key.Decode(encKey)
		if err != nil {
			return
		}

		m.Key.Secret = secret
		m.Key.Key = key

		if groupKey != nil {
			m.Key.GroupPriv = groupKey
		}
		msgs = append(msgs, m)
	}
	return
}

func newUser(cfg *shared.Config, name string, admin bool) bool {
	q := cfg.DB.Where("name = ? and admin = ?", name, admin).First(&db.Users{})
	if !q.RecordNotFound() {
		return false
	} else if q.Error != nil && !q.RecordNotFound() {
		cfg.Log(log.ERROR, q.Error)
		return false
	}
	return true
}
