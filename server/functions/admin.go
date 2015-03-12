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
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

func GetCA(cfg *shared.Config, r shared.Request) {
	var err error
	var msg shared.Message
	msg.X509.Cert, err = cfg.Runtime.CACert.Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	r.Reply(200, msg)
}

/*
User.Name => name
*/
func AdminNew(cfg *shared.Config, r shared.Request) {
	user := new(db.Users)
	var resp shared.Message

	user.Name = r.Req.User.Name
	user.Admin = true

	if !newUser(cfg, user.Name, user.Admin) {
		r.Reply(409, shared.RespMessage("Username already exists"))
		return
	}

	pass, err := crypto.NewPassword()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	resp.User.Password = pass

	hash, err := crypto.PasswordHash(pass)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	user.Password, err = hash.Encode()
	if err != nil {
		r.Reply(500)
		return
	}

	q := cfg.DB.Create(user)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	resp.User.Name = user.Name
	resp.User.Group = "default"
	resp.User.Admin = true

	r.Reply(200, resp)
	return
}

/*
User.Name => name
Key.GroupPriv => Copy of the supergroup private key, encrypted with the public key of the target admin
*/
func AdminSuper(cfg *shared.Config, r shared.Request) {
	var err error
	if r.Req.Key.GroupPriv == nil {
		r.Reply(400, shared.RespMessage("Encrypted supergroup key not provided"))
		return
	}

	user := new(db.Users)

	q := cfg.DB.Where("Name = ? and Admin = ?", r.Req.User.Name, true).First(user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("User does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	if user.GID == shared.SuperGID {
		r.Reply(200, shared.RespMessage("User already superuser"))
	}

	user.GID = shared.SuperGID
	user.GroupKey, err = crypto.NewBinary(r.Req.Key.GroupPriv).Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	q = cfg.DB.Save(user)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Password => new password.
*/
func UserPass(cfg *shared.Config, r shared.Request) {
	defer crypto.Zero(r.Req.User.Password)

	encrypted, err := crypto.PasswordHash(r.Req.User.Password)
	if err != nil {
		r.Reply(500)
		return
	}

	enc, err := encrypted.Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	q := cfg.DB.First(&db.Users{}, r.Session.GetUID()).Update("Password", enc)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Name => name
User.Admin => admin/client user
*/
func UserDel(cfg *shared.Config, r shared.Request) {
	user := new(db.Users)
	q := cfg.DB.Where("Name = ? and Admin = ?", r.Req.User.Name, r.Req.User.Admin).First(user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("No such user"))
		return
	} else if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	q = cfg.DB.Delete(user)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Admin => admin/client users
*/
func UserList(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("users").Select(
		"users.name, groups.name").Where(
		"users.admin = ?", r.Req.User.Admin).Joins(
		"left join groups on users.gid = groups.id").Rows()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.User.Name, &m.User.Group)
		if err != nil {
			cfg.Log(log.ERROR, err)
			r.Reply(500)
			return
		}
		list = append(list, m)
	}
	r.Reply(200, list...)
	return
}
