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
	"github.com/jfindley/skds/server/auth"
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

	group.PubKey, err = crypto.Binary(r.Req.Key.GroupPub).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}
	group.PrivKey, err = crypto.Binary(r.Req.Key.GroupPriv).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	if !cfg.DB.NewRecord(group) {
		r.Reply(200, shared.RespMessage("Group already exists"))
		return
	}

	q := cfg.DB.Create(group)
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
		return genericFailure(cfg, tx.Error)
	}
	var commit bool

	// Avoid having to manually rollback for each error
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	q := tx.Where("name = ? and kind = ?", group.Name, group.Kind).First(group)
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
