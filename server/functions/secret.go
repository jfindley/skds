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
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

/*
No input
*/
func SecretList(cfg *shared.Config, r shared.Request) {
	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("MasterSecrets").Select("name").Rows()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	for rows.Next() {
		var m shared.Message
		err = rows.Scan(&m.Key.Name)
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
User.Name => name
User.Admin => admin/client user
*/
func SecretListUser(cfg *shared.Config, r shared.Request) {
	var user db.Users

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Name, r.Req.User.Admin).First(&user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("User does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("MasterSecrets").Select(
		"name, UserSecrets.path, GroupSecrets.path").Where(
		"UserSecrets.uid = ? or GroupSecrets.gid = ?", user.Id, user.GID).Joins(
		`left join GroupSecrets on MasterSecrets.id = GroupSecrets.sid
		left join UserSecrets on MasterSecrets.id = UserSecrets.sid`).Rows()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	for rows.Next() {
		var m shared.Message
		var p1 sql.NullString
		var p2 sql.NullString
		err = rows.Scan(&m.Key.Name, &p1, &p2)
		if err != nil {
			cfg.Log(1, err)
			r.Reply(500)
			return
		}
		if p1.Valid {
			m.Key.Path = p1.String
		} else if p2.Valid {
			m.Key.Path = p2.String
		}
		list = append(list, m)
	}
	r.Reply(200, list...)
	return
}

/*
User.Group => group name
User.Admin => admin/client group
*/
func SecretListGroup(cfg *shared.Config, r shared.Request) {
	group := new(db.Groups)

	q := cfg.DB.Find(group, "name = ? and admin = ?", r.Req.User.Group, r.Req.User.Admin)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	list := make([]shared.Message, 0)

	rows, err := cfg.DB.Table("MasterSecrets").Select("name, GroupSecrets.path").Where(
		"GroupSecrets.gid = ?", group.Id).Joins(
		"left join GroupSecrets on MasterSecrets.id = GroupSecrets.sid").Rows()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	for rows.Next() {
		var m shared.Message
		var p sql.NullString
		err = rows.Scan(&m.Key.Name, &p)
		if err != nil {
			cfg.Log(1, err)
			r.Reply(500)
			return
		}
		if p.Valid {
			m.Key.Path = p.String
		}
		list = append(list, m)
	}
	r.Reply(200, list...)
	return
}

/*
Key.Name => name
Key.Secret => encrypted payload
Key.Key => unique encryption key for payload encrypted with the supergroup pubkey
Key.UserKey (only required if called by non-super admin) => copy of above key, encrypted with admin local key
*/
func SecretNew(cfg *shared.Config, r shared.Request) {
	tx := cfg.DB.Begin()
	if tx.Error != nil {
		cfg.Log(1, tx.Error)
		r.Reply(500)
		return
	}
	var commit bool

	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	if r.Req.Key.Name == "" || r.Req.Key.Secret == nil || r.Req.Key.Key == nil {
		r.Reply(400, shared.RespMessage("Incomplete request"))
		return
	}
	if !r.Session.IsSuper() && r.Req.Key.UserKey == nil {
		r.Reply(400, shared.RespMessage("Incomplete request"))
		return
	}

	key := new(db.MasterSecrets)
	groupKey := new(db.GroupSecrets)

	key.Name = r.Req.Key.Name

	if !tx.NewRecord(key) {
		r.Reply(409, shared.RespMessage("Duplicate key name"))
		return
	}

	var secret crypto.Binary
	var superKey crypto.Binary
	var err error

	secret = r.Req.Key.Secret
	superKey = r.Req.Key.Key

	key.Secret, err = secret.Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}
	groupKey.Secret, err = superKey.Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	q := tx.Create(key)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	groupKey.GID = shared.SuperGID
	groupKey.SID = key.Id // Set when the record is created

	if !tx.NewRecord(groupKey) {
		cfg.Log(1, "Duplicate supergroup key")
		r.Reply(500)
		return
	}

	q = tx.Create(groupKey)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if !r.Session.IsSuper() {
		var userKey crypto.Binary
		userKey = r.Req.Key.UserKey

		adminSecret := new(db.UserSecrets)
		adminSecret.SID = key.Id
		adminSecret.UID = r.Session.GetUID()
		adminSecret.Secret, err = userKey.Encode()
		if err != nil {
			cfg.Log(1, err)
			r.Reply(500)
			return
		}

		q = tx.Create(adminSecret)
		if q.Error != nil {
			cfg.Log(1, q.Error)
			r.Reply(500)
			return
		}
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
Key.Name => name
*/
func SecretDel(cfg *shared.Config, r shared.Request) {
	tx := cfg.DB.Begin()
	if tx.Error != nil {
		cfg.Log(1, tx.Error)
		r.Reply(500)
		return
	}
	var commit bool

	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	var secret db.MasterSecrets

	q := tx.Where("name = ?", r.Req.Key.Name).First(&secret)
	if q.RecordNotFound() {
		r.Reply(404)
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if !r.Session.CheckACL(cfg.DB, secret) {
		r.Reply(403)
		return
	}

	q = tx.Where("SID = ?", secret.Id).Delete(&db.UserSecrets{})
	if q.Error != nil && !q.RecordNotFound() {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = tx.Where("SID = ?", secret.Id).Delete(&db.GroupSecrets{})
	if q.Error != nil && !q.RecordNotFound() {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = tx.Delete(secret)
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
Key.Name => name
Key.Secret => encrypted payload
*/
func SecretUpdate(cfg *shared.Config, r shared.Request) {
	secret := new(db.MasterSecrets)
	var err error

	q := cfg.DB.Where("name = ?", r.Req.Key.Name).First(secret)
	if q.RecordNotFound() {
		r.Reply(404)
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if !r.Session.CheckACL(cfg.DB, secret) {
		r.Reply(403)
		return
	}

	secret.Secret, err = crypto.NewBinary(r.Req.Key.Secret).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
		return
	}

	q = cfg.DB.Save(secret)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	r.Reply(204)
	return
}

/*
User.Name => user name
User.Admin => admin/client user
Key.Name => secret name
Key.Secret => secret encoded with the public key of the target admin
*/
func SecretAssignUser(cfg *shared.Config, r shared.Request) {
	var err error
	var user db.Users
	var secret db.MasterSecrets
	var userSecret db.UserSecrets

	if len(r.Req.Key.Secret) == 0 {
		r.Reply(400, shared.RespMessage("No secret provided"))
		return
	}

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Name, r.Req.User.Admin).First(&user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if user.GID == shared.SuperGID {
		r.Reply(400, shared.RespMessage("Cannot assign a key to a superuser"))
		return
	}

	q = cfg.DB.Where("name = ?", r.Req.Key.Name).First(&secret)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Secret does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if !r.Session.CheckACL(cfg.DB, secret, user) {
		r.Reply(403)
		return
	}

	userSecret.Secret, err = crypto.NewBinary(r.Req.Key.Secret).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
	}
	userSecret.SID = secret.Id
	userSecret.UID = user.Id

	q = cfg.DB.Create(&userSecret)
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
User.Admin => admin/client group
Key.Name => secret name
Key.Secret => secret encoded with the public key of the target group
*/
func SecretAssignGroup(cfg *shared.Config, r shared.Request) {
	var err error
	var group db.Groups
	var secret db.MasterSecrets
	var groupSecret db.GroupSecrets

	if len(r.Req.Key.Secret) == 0 {
		r.Reply(400, shared.RespMessage("No secret provided"))
		return
	}

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Group, r.Req.User.Admin).First(&group)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = cfg.DB.Where("name = ?", r.Req.Key.Name).First(&secret)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Secret does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if !r.Session.CheckACL(cfg.DB, secret, group) {
		r.Reply(403)
		return
	}

	groupSecret.Secret, err = crypto.NewBinary(r.Req.Key.Secret).Encode()
	if err != nil {
		cfg.Log(1, err)
		r.Reply(500)
	}
	groupSecret.SID = secret.Id
	groupSecret.GID = group.Id

	q = cfg.DB.Create(&groupSecret)
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	r.Reply(204)
	return
}

/*
User.Name => user name
User.Admin => admin/client user
Key.Name => secret name
*/
func SecretRemoveUser(cfg *shared.Config, r shared.Request) {
	var user db.Users
	var secret db.MasterSecrets

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Name, r.Req.User.Admin).First(&user)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if user.GID == shared.SuperGID {
		r.Reply(403, shared.RespMessage("Cannot remove a key from a superuser"))
		return
	}

	if !r.Session.CheckACL(cfg.DB, user) {
		r.Reply(403)
		return
	}

	q = cfg.DB.Where("name = ?", r.Req.Key.Name).First(&secret)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Secret does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = cfg.DB.Where("sid = ? and uid = ?", secret.Id, user.Id).Delete(&db.UserSecrets{})
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
User.Admin => admin/client group
Key.Name => secret name
*/
func SecretRemoveGroup(cfg *shared.Config, r shared.Request) {
	var group db.Groups
	var secret db.MasterSecrets

	q := cfg.DB.Where("name = ? and admin = ?", r.Req.User.Group, r.Req.User.Admin).First(&group)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Group does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	if group.Id == shared.SuperGID {
		r.Reply(403, shared.RespMessage("Cannot remove a key from the supergroup"))
		return
	}

	if !r.Session.CheckACL(cfg.DB, group) {
		r.Reply(403)
		return
	}

	q = cfg.DB.Where("name = ?", r.Req.Key.Name).First(&secret)
	if q.RecordNotFound() {
		r.Reply(404, shared.RespMessage("Secret does not exist"))
		return
	} else if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	q = cfg.DB.Where("sid = ? and gid = ?", secret.Id, group.Id).Delete(&db.GroupSecrets{})
	if q.Error != nil {
		cfg.Log(1, q.Error)
		r.Reply(500)
		return
	}

	r.Reply(204)
	return
}
