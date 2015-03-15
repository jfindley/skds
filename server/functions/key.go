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

/*
User.Key => public part of local key
*/
func SetPubkey(cfg *shared.Config, r shared.Request) {
	enc, err := crypto.NewBinary(r.Req.User.Key).Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	q := cfg.DB.First(&db.Users{}, r.Session.GetUID()).Update("PubKey", enc)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	r.Reply(204)
	return
}

/*
User.Name => user name
User.Admin => admin/client user
*/
func UserPubKey(cfg *shared.Config, r shared.Request) {
	var user db.Users
	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Name, r.Req.User.Admin).First(&user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Client does not exist"))
		return
	}
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	var key crypto.Binary
	var msg shared.Message

	err := key.Decode(user.PubKey)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	msg.Key.UserKey = key
	r.Reply(200, msg)
	return
}

/*
User.Group => group name
User.Admin => admin/client group
*/
func GroupPubKey(cfg *shared.Config, r shared.Request) {
	var group db.Groups
	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Group, r.Req.User.Admin).First(&group)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	}
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	var key crypto.Binary
	var msg shared.Message

	err := key.Decode(group.PubKey)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	msg.Key.GroupPub = key
	r.Reply(200, msg)
	return
}

/*
No input
*/
func SuperPubKey(cfg *shared.Config, r shared.Request) {
	group := new(db.Groups)
	q := cfg.DB.First(group, shared.SuperGID)
	if q.RecordNotFound() || q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	var key crypto.Binary
	var msg shared.Message
	err := key.Decode(group.PubKey)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}
	msg.Key.Key = key
	r.Reply(200, msg)
	return
}

/*
User.Group => group name
User.Admin => admin/client group
*/
func GroupPrivKey(cfg *shared.Config, r shared.Request) {
	var group db.Groups

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Group, r.Req.User.Admin).First(&group)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	}
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	if !r.Session.CheckACL(cfg.DB, group) {
		r.Reply(403)
		return
	}

	var key crypto.Binary
	var msg shared.Message

	err := key.Decode(group.PrivKey)
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	msg.Key.GroupPriv = key
	r.Reply(200, msg)
	return
}

/*
Key.GroupPub => supergroup public key
Key.GroupPriv => supergroup private key encrypted by the calling admin
*/
func SetSuperKey(cfg *shared.Config, r shared.Request) {
	var group db.Groups
	var user db.Users
	var err error

	tx := cfg.DB.Begin()
	if tx.Error != nil {
		cfg.Log(log.ERROR, tx.Error)
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

	q := tx.First(&group, shared.SuperGID)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	if group.PubKey != nil {
		r.Reply(409)
		return
	}

	q = tx.First(&user, r.Session.GetUID())
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	group.PubKey, err = crypto.NewBinary(r.Req.Key.GroupPub).Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	user.GroupKey, err = crypto.NewBinary(r.Req.Key.GroupPriv).Encode()
	if err != nil {
		cfg.Log(log.ERROR, err)
		r.Reply(500)
		return
	}

	q = tx.Save(&group)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	q = tx.Save(&user)
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}

	q = tx.Commit()
	if q.Error != nil {
		cfg.Log(log.ERROR, q.Error)
		r.Reply(500)
		return
	}
	commit = true

	r.Reply(204)
}
