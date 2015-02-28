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
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

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
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	q := cfg.DB.First(&db.Users{}, r.Session.GetUID()).Update("Password", enc)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Name => name
*/
func AdminNew(cfg *shared.Config, r shared.Request) {
	user := new(db.Users)
	var resp shared.Message

	pass, err := crypto.NewPassword()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	resp.User.Password = pass

	hash, err := crypto.PasswordHash(pass)
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	user.Name = r.Req.User.Name
	user.Admin = true
	user.Password, err = hash.Encode()
	if err != nil {
		r.Reply(500)
		return
	}

	if !cfg.DB.NewRecord(user) {
		r.Reply(200, shared.RespMessage("Username already exists"))
		return
	}

	q := cfg.DB.Create(user)
	if q.Error != nil {
		cfg.Log(1, q.Error)
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
*/
func AdminDel(cfg *shared.Config, r shared.Request) {
	userDel(cfg, r, true)
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
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if user.GID == shared.SuperGID {
		r.Reply(200, shared.RespMessage("User already superuser"))
	}

	user.GID = shared.SuperGID
	user.GroupKey, err = crypto.NewBinary(r.Req.Key.GroupPriv).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	q = cfg.DB.Save(user)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Key => public part of local key
*/
func UserPubkey(cfg *shared.Config, r shared.Request) {
	enc, err := crypto.NewBinary(r.Req.User.Key).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	q := cfg.DB.First(&db.Users{}, r.Session.GetUID()).Update("PubKey", enc)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
No input
*/
func AdminList(cfg *shared.Config, r shared.Request) {
	userList(cfg, r, true)
}

/*
User.Name => name
User.Group => name of group
Key.GroupPriv => Copy of the group private key, encrypted with the public key of the target admin
*/
func AdminGroupAssign(cfg *shared.Config, r shared.Request) {
	// This function relies on the client sending a pre-computed group key.
	// We can't do this on the server as it would involve having the ability to decrypt keys.
	if r.Req.User.Group == "super" {
		r.Reply(400, shared.RespMessage("Please use the super function to make an admin a superuser"))
		return
	}
	userGroupAssign(cfg, r, true)
}
