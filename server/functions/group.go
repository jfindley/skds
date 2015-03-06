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
User.Group => group name
User.Admin => group type
Key.GroupPub => Public key for group
Key.GroupPriv => Private key for group, encrypted with supergroup key
*/
func GroupNew(cfg *shared.Config, r shared.Request) {
	if r.Req.User.Group == "" {
		r.Reply(400, shared.RespMessage("Please specify a group name"))
		return
	}
	if r.Req.Key.GroupPub == nil || r.Req.Key.GroupPriv == nil {
		r.Reply(400, shared.RespMessage("Please provide a keypair"))
		return
	}

	var err error
	group := new(db.Groups)
	group.Name = r.Req.User.Group
	group.Admin = r.Req.User.Admin

	group.PubKey, err = crypto.NewBinary(r.Req.Key.GroupPub).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}
	group.PrivKey, err = crypto.NewBinary(r.Req.Key.GroupPriv).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	q := cfg.DB.Where("name = ? and admin = ?", group.Name, group.Admin).First(&db.Groups{})
	if !db.NotFound(q.Error) {
		r.Reply(200, shared.RespMessage("Group already exists"))
		return
	}

	q = cfg.DB.Create(group)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Group => group name
User.Admin => group type
*/
func GroupDel(cfg *shared.Config, r shared.Request) {
	if r.Req.User.Group == "" {
		r.Reply(400, shared.RespMessage("Please specify a group name"))
		return
	}

	group := new(db.Groups)
	group.Name = r.Req.User.Group
	group.Admin = r.Req.User.Admin

	if group.Name == "default" || group.Name == "super" {
		r.Reply(400, shared.RespMessage("Builtin groups cannot be deleted"))
		return
	}

	tx := cfg.DB.Begin()
	if tx.Error != nil {
		cfg.Log(1, tx.Error)
		r.Reply(500)
		return
	}
	var commit bool

	// Avoid having to manually rollback for each error
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	q := tx.Where("name = ? and admin = ?", group.Name, group.Admin).First(group)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("No such group"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = tx.Delete(group)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	groupSecrets := new(db.GroupSecrets)
	q = tx.Where("GID = ?", group.Id).Delete(groupSecrets)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = tx.Commit()
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}
	commit = true

	r.Reply(204)
	return
}

/*
No input
*/
func GroupList(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("groups").Select("name, admin").Rows()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.User.Group, &m.User.Admin)
		if err != nil {
			cfg.Log(1, err)
			r.Reply(500)
			return
		}
		list = append(list, m)
	}
	r.Reply(200, list...)
	return
}

/*
This function relies on the client sending a pre-encrypted group key.
We can't do this on the server as it would involve having the ability to decrypt keys.

User.Name => name
User.Admin => admin/client user
User.Group => name of group
Key.GroupPriv => Copy of the group private key, encrypted with the public key of the target admin
*/
func UserGroupAssign(cfg *shared.Config, r shared.Request) {
	if r.Req.User.Group == "super" {
		r.Reply(400, shared.RespMessage("Please use the super function to make an admin a superuser"))
		return
	}

	var err error
	if r.Req.Key.GroupPriv == nil && r.Req.User.Group != "default" {
		r.Reply(400, shared.RespMessage("No group key provided, unable to assign group"))
		return
	}

	var user db.Users
	var group db.Groups

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Name, r.Req.User.Admin).First(&user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("No such user"))
		return
	} else if q.Error != nil {
		r.Reply(500)
		return
	}

	q = cfg.DB.Where("name = ? and admin = ?", r.Req.User.Group, r.Req.User.Admin).First(&group)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("No such group"))
		return
	} else if q.Error != nil {
		r.Reply(500)
		return
	}

	if user.GID == group.Id {
		r.Reply(200, shared.RespMessage("User already member of this group"))
		return
	}

	if !r.Session.CheckACL(cfg.DB, user, group) {
		r.Reply(403)
		return
	}

	user.GID = group.Id

	if r.Req.User.Group == "default" {
		user.GroupKey = nil
	} else {
		user.GroupKey, err = crypto.NewBinary(r.Req.Key.GroupPriv).Encode()
		if err != nil {
			cfg.Log(1, err)
			r.Reply(500)
			return
		}
	}

	q = cfg.DB.Save(user)
	if q.Error != nil {
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}
