package functions

import (
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

/*
User.Password => new password.
*/
func AdminPass(cfg *shared.Config, r shared.Request) {
	defer crypto.Zero(r.Req.User.Password)

	admin := new(db.Users)

	encrypted, err := crypto.PasswordHash(r.Req.User.Password)
	if err != nil {
		r.Reply(500)
	}

	q := cfg.DB.First(admin, r.Session.GetUID)
	if q.Error != nil || q.RecordNotFound() {
		return genericFailure(cfg, q.Error)
	}

	admin.Password = msg.User.Password
	q = cfg.DB.Save(admin)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	resp.Response = "OK"
	return
}

/*
User.Name => name
*/
func AdminNew(cfg *shared.Config, r shared.Request) {
	admin := new(db.Users)
	var err error

	admin.Password, err = crypto.PasswordHash(shared.DefaultAdminPass)
	if err != nil {
		return genericFailure(cfg, err)
	}

	admin.Name = msg.User.Name
	admin.GID = shared.DefAdminGID

	if !cfg.DB.NewRecord(admin) {
		return namedFailure(400, "Admin already exists")
	}

	q := cfg.DB.Create(admin)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	resp.Response = "OK"
	resp.User.Password = []byte(shared.DefaultAdminPass)
	return
}

/*
User.Name => name
*/
func AdminDel(cfg *shared.Config, r shared.Request) {
	q := cfg.DB.Where("name = ?", msg.User.Name).Delete(db.Users{})
	if q.RecordNotFound() {
		resp.Response = "No such user"
		ret = 404
		return
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	resp.Response = "OK"
	return
}

/*
User.Name => name
Key.GroupPriv => Copy of the supergroup private key, encrypted with the public key of the target admin
*/
func AdminSuper(cfg *shared.Config, r shared.Request) {
	if msg.Key.GroupPriv == nil {
		return namedFailure(400, "Supergroup key must be set")
	}

	admin := new(db.Users)

	q := cfg.DB.Where("name = ?", msg.User.Name).First(admin)
	if q.RecordNotFound() {
		return namedFailure(400, "No such admin")
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	if admin.GID == shared.SuperGID {
		return namedFailure(200, "Admin already super")
	}

	admin.GID = shared.SuperGID
	admin.GroupKey = shared.HexEncode(msg.Key.GroupPriv)

	q = cfg.DB.Save(admin)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	resp.Response = "OK"
	return
}

/*
User.Key => public part of local key
*/
func AdminPubkey(cfg *shared.Config, r shared.Request) {
	admin := new(db.Users)

	admin.Id = authobj.UID
	q := cfg.DB.First(admin)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	admin.Pubkey = shared.HexEncode(msg.User.Key)
	q = cfg.DB.Save(admin)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	resp.Response = "OK"
	return
}

/*
No input
*/
func AdminList(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("admins").Select("admins.name, groups.name").Joins("left join groups on admins.gid = groups.id").Rows()
	if err != nil {
		return genericFailure(cfg, err)
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.User.Name, &m.User.Group)
		if err != nil {
			return genericFailure(cfg, err)
		}
		list = append(list, m)
	}
	resp.ResponseData = list
	resp.Response = "OK"
	return
}

/*
User.Name => name
User.Group => name of group
Key.GroupPriv => Copy of the group private key, encrypted with the public key of the target admin
*/
func AdminGroupAssign(cfg *shared.Config, r shared.Request) {
	// This function relies on the client sending a pre-computed group key.
	// We can't do this on the server as it would involve having the ability to decrypt keys.
	if msg.User.Group == "super" {
		return namedFailure(400, "Please use the super function to make an admin a superuser")
	}

	if msg.Key.GroupPriv == nil && msg.User.Group != "default" {
		return namedFailure(400, "No group key provided, unable to assign group")
	}

	admin := new(db.Users)
	group := new(db.Groups)

	q := cfg.DB.Where("name = ?", msg.User.Name).First(admin)
	if q.RecordNotFound() {
		return namedFailure(400, "No such admin")
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	q = cfg.DB.Where("name = ? and kind = ?", msg.User.Group, "admin").First(group)
	if q.RecordNotFound() {
		return namedFailure(400, "No such group")
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	if admin.GID == group.Id {
		return namedFailure(200, "Admin already member of this group")
	}

	admin.GID = group.Id

	if msg.User.Group == "default" {
		admin.GroupKey = nil
	} else {
		admin.GroupKey = shared.HexEncode(msg.Key.GroupPriv)
	}

	q = cfg.DB.Save(admin)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	resp.Response = "OK"
	return
}

/*
User.Group => group name
Key.GroupPub => Public key for group
Key.GroupPriv => Private key for group, encrypted with supergroup key
*/
func AdminGroupNew(cfg *shared.Config, r shared.Request) {
	if len(msg.User.Group) == 0 && len(msg.Client.Group) == 0 {
		return namedFailure(400, "Please specify a group name")
	}
	if len(msg.User.Group) > 0 && len(msg.Client.Group) > 0 {
		return namedFailure(400, "Please specify either admin or client group, not both")
	}
	if msg.Key.GroupPub == nil || msg.Key.GroupPriv == nil {
		return namedFailure(400, "No keys provided")
	}

	group := new(db.Groups)

	if len(msg.User.Group) > 0 {
		group.Kind = "admin"
		group.Name = msg.User.Group
	} else {
		group.Kind = "client"
		group.Name = msg.Client.Group
	}
	group.PubKey = shared.HexEncode(msg.Key.GroupPub)
	group.PrivKey = shared.HexEncode(msg.Key.GroupPriv)

	if !cfg.DB.NewRecord(group) {
		return namedFailure(400, "Group already exists")
	}

	q := cfg.DB.Create(group)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	resp.Response = "OK"
	return
}

/*
User.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
*/
func AdminGroupDel(cfg *shared.Config, r shared.Request) {
	if len(msg.User.Group) == 0 && len(msg.Client.Group) == 0 {
		return namedFailure(400, "Please specify a group name")
	}
	if len(msg.User.Group) > 0 && len(msg.Client.Group) > 0 {
		return namedFailure(400, "Please specify either admin or client group, not both")
	}

	group := new(db.Groups)

	if len(msg.User.Group) > 0 {
		group.Kind = "admin"
		group.Name = msg.User.Group
	} else {
		group.Kind = "client"
		group.Name = msg.Client.Group
	}

	if group.Name == "default" || group.Name == "super" {
		return namedFailure(400, "Builtin groups cannot be deleted")
	}

	tx := cfg.DB.Begin()
	if tx.Error != nil {
		return genericFailure(cfg, tx.Error)
	}
	var commit bool

	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	q := tx.Where("name = ? and kind = ?", group.Name, group.Kind).First(group)
	if q.RecordNotFound() {
		resp.Response = "No such group"
		ret = 404
		return
	} else if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	q = tx.Delete(group)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	groupSecrets := new(db.GroupSecrets)
	q = tx.Where("GID = ?", group.Id).Delete(groupSecrets)
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}

	q = tx.Commit()
	if q.Error != nil {
		return genericFailure(cfg, q.Error)
	}
	commit = true

	resp.Response = "OK"
	return
}

/*
No input
*/
func AdminGroupList(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("groups").Select("name, kind").Rows()
	if err != nil {
		return genericFailure(cfg, err)
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.User.Name, &m.User.Group)
		if err != nil {
			return genericFailure(cfg, err)
		}
		list = append(list, m)
	}
	resp.ResponseData = list
	resp.Response = "OK"
	return
}
