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

func userDel(cfg *shared.Config, r shared.Request, admin bool) {
	q := cfg.DB.Where("Name = ? and Admin = ?", r.Req.User.Name, admin).Delete(&db.Users{})
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("No such user"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

func userList(cfg *shared.Config, r shared.Request, admin bool) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("users").Select(
		"users.name, groups.name").Where(
		"users.admin = ?", admin).Joins(
		"left join groups on users.gid = groups.id").Rows()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.User.Name, &m.User.Group)
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

// This function relies on the client sending a pre-computed group key.
// We can't do this on the server as it would involve having the ability to decrypt keys.
// ACL checking should be done prior to calling this function.
func userGroupAssign(cfg *shared.Config, r shared.Request, admin bool) {
	var err error
	if r.Req.Key.GroupPriv == nil && r.Req.User.Group != "default" {
		r.Reply(400, shared.RespMessage("No group key provided, unable to assign group"))
		return
	}

	user := new(db.Users)
	group := new(db.Groups)

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Name, admin).First(user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("No such user"))
		return
	} else if q.Error != nil {
		r.Reply(500)
		return
	}

	q = cfg.DB.Where("name = ? and admin = ?", r.Req.User.Group, admin).First(group)
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
