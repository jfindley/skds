package functions

import (
    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/crypto"
    "github.com/jfindley/skds/messages"
    "github.com/jfindley/skds/server/auth"
    "github.com/jfindley/skds/server/db"
    "github.com/jfindley/skds/shared"
)

/*
Admin.Password => new password.  Should be pre-encrypted.
*/
func AdminPass(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)
    defer crypto.Zero(msg.Admin.Password)

    q := cfg.DB.First(admin, authobj.UID)
    if q.Error != nil || q.RecordNotFound() {
        return genericFailure(cfg, q.Error)
    }

    admin.Password = msg.Admin.Password
    q = cfg.DB.Save(admin)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}

/*
Admin.Name => name
*/
func AdminNew(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)
    var err error

    admin.Password, err = crypto.PasswordHash(config.DefaultAdminPass)
    if err != nil {
        return genericFailure(cfg, err)
    }

    admin.Name = msg.Admin.Name
    admin.Gid = config.DefAdminGid

    if !cfg.DB.NewRecord(admin) {
        return namedFailure(400, "Admin already exists")
    }

    q := cfg.DB.Create(admin)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    resp.Admin.Password = []byte(config.DefaultAdminPass)
    return
}

/*
Admin.Name => name
*/
func AdminDel(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    q := cfg.DB.Where("name = ?", msg.Admin.Name).Delete(db.Admins{})
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
Admin.Name => name
Key.GroupPriv => Copy of the supergroup private key, encrypted with the public key of the target admin
*/
func AdminSuper(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    if msg.Key.GroupPriv == nil {
        return namedFailure(400, "Supergroup key must be set")
    }

    admin := new(db.Admins)

    q := cfg.DB.Where("name = ?", msg.Admin.Name).First(admin)
    if q.RecordNotFound() {
        return namedFailure(400, "No such admin")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if admin.Gid == config.SuperGid {
        return namedFailure(200, "Admin already super")
    }

    admin.Gid = config.SuperGid
    admin.GroupKey = shared.HexEncode(msg.Key.GroupPriv)

    q = cfg.DB.Save(admin)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }
    resp.Response = "OK"
    return
}

/*
Admin.Key => public part of local key
*/
func AdminPubkey(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)

    admin.Id = authobj.UID
    q := cfg.DB.First(admin)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    admin.Pubkey = shared.HexEncode(msg.Admin.Key)
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
func AdminList(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    list := make([]messages.Message, 0)

    rows, err := cfg.DB.Table("admins").Select("admins.name, groups.name").Joins("left join groups on admins.gid = groups.id").Rows()
    if err != nil {
        return genericFailure(cfg, err)
    }

    for rows.Next() {
        var m messages.Message
        err = rows.Scan(&m.Admin.Name, &m.Admin.Group)
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
Admin.Name => name
Admin.Group => name of group
Key.GroupPriv => Copy of the group private key, encrypted with the public key of the target admin
*/
func AdminGroupAssign(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    // This function relies on the client sending a pre-computed group key.
    // We can't do this on the server as it would involve having the ability to decrypt keys.
    if msg.Admin.Group == "super" {
        return namedFailure(400, "Please use the super function to make an admin a superuser")
    }

    if msg.Key.GroupPriv == nil && msg.Admin.Group != "default" {
        return namedFailure(400, "No group key provided, unable to assign group")
    }

    admin := new(db.Admins)
    group := new(db.Groups)

    q := cfg.DB.Where("name = ?", msg.Admin.Name).First(admin)
    if q.RecordNotFound() {
        return namedFailure(400, "No such admin")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = cfg.DB.Where("name = ? and kind = ?", msg.Admin.Group, "admin").First(group)
    if q.RecordNotFound() {
        return namedFailure(400, "No such group")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if admin.Gid == group.Id {
        return namedFailure(200, "Admin already member of this group")
    }

    admin.Gid = group.Id

    if msg.Admin.Group == "default" {
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
Admin.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
Key.GroupPub => Public key for group
Key.GroupPriv => Private key for group, encrypted with supergroup key
*/
func AdminGroupNew(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    if len(msg.Admin.Group) == 0 && len(msg.Client.Group) == 0 {
        return namedFailure(400, "Please specify a group name")
    }
    if len(msg.Admin.Group) > 0 && len(msg.Client.Group) > 0 {
        return namedFailure(400, "Please specify either admin or client group, not both")
    }
    if msg.Key.GroupPub == nil || msg.Key.GroupPriv == nil {
        return namedFailure(400, "No keys provided")
    }

    group := new(db.Groups)

    if len(msg.Admin.Group) > 0 {
        group.Kind = "admin"
        group.Name = msg.Admin.Group
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
Admin.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
*/
func AdminGroupDel(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    if len(msg.Admin.Group) == 0 && len(msg.Client.Group) == 0 {
        return namedFailure(400, "Please specify a group name")
    }
    if len(msg.Admin.Group) > 0 && len(msg.Client.Group) > 0 {
        return namedFailure(400, "Please specify either admin or client group, not both")
    }

    group := new(db.Groups)

    if len(msg.Admin.Group) > 0 {
        group.Kind = "admin"
        group.Name = msg.Admin.Group
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
func AdminGroupList(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    list := make([]messages.Message, 0)

    rows, err := cfg.DB.Table("groups").Select("name, kind").Rows()
    if err != nil {
        return genericFailure(cfg, err)
    }

    for rows.Next() {
        var m messages.Message
        err = rows.Scan(&m.Admin.Name, &m.Admin.Group)
        if err != nil {
            return genericFailure(cfg, err)
        }
        list = append(list, m)
    }
    resp.ResponseData = list
    resp.Response = "OK"
    return
}
