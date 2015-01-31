package functions

import (
    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/messages"
    "github.com/jfindley/skds/server/auth"
    "github.com/jfindley/skds/server/db"
    "github.com/jfindley/skds/shared"
)

/*
No input
*/
func KeyList(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    list := make([]messages.Message, 0)

    rows, err := cfg.Runtime.DB.Table("master_secrets").Select("name").Rows()
    if err != nil {
        return genericFailure(cfg, err)
    }

    for rows.Next() {
        var m messages.Message
        err = rows.Scan(&m.Key.Name)
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
*/
func KeyListAdmin(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    list := make([]messages.Message, 0)

    admin := new(db.Admins)
    q := cfg.Runtime.DB.Where("name = ?", msg.Admin.Name).First(admin)
    if q.RecordNotFound() {
        return namedFailure(404, "No such admin")
    }
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    rows, err := cfg.Runtime.DB.Table("master_secrets").Select(
        "master_secrets.name").Where(
        "group_secrets.gid = ? or admin_secrets.uid = ?", admin.Gid, admin.Id).Joins(
        "left join group_secrets on master_secrets.id = group_secrets.sid left join admin_secrets on master_secrets.id = admin_secrets.sid").Rows()
    if err != nil {
        return genericFailure(cfg, err)
    }

    for rows.Next() {
        var m messages.Message
        err = rows.Scan(&m.Key.Name)
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
Client.Name => name
*/
func KeyListClient(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    list := make([]messages.Message, 0)

    client := new(db.Clients)
    q := cfg.Runtime.DB.Where("name = ?", msg.Client.Name).First(client)
    if q.RecordNotFound() {
        return namedFailure(404, "No such client")
    }
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    rows, err := cfg.Runtime.DB.Table("master_secrets").Select(
        "master_secrets.name, group_secrets.path, client_secrets.path").Where(
        "group_secrets.gid = ? or client_secrets.uid = ?", client.Gid, client.Id).Joins(
        "left join group_secrets on master_secrets.id = group_secrets.sid left join client_secrets on master_secrets.id = client_secrets.sid").Rows()
    if err != nil {
        return genericFailure(cfg, err)
    }

    for rows.Next() {
        var m messages.Message
        var (
            cpath []byte
            gpath []byte
        )
        err = rows.Scan(&m.Key.Name, &gpath, &cpath)
        if err != nil {
            println(err.Error())
            return genericFailure(cfg, err)
        }
        if len(gpath) > 1 {
            m.Key.Path = string(gpath)
        } else {
            m.Key.Path = string(cpath)
        }
        list = append(list, m)
    }
    resp.ResponseData = list
    resp.Response = "OK"
    return
}

/*
Admin.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
*/
func KeyListGroup(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    list := make([]messages.Message, 0)

    group, ret, err := dbGroupFromMessage(cfg, msg)
    if err != nil {
        return errorFailure(ret, err)
    }

    rows, err := cfg.Runtime.DB.Table("master_secrets").Where(
        "group_secrets.gid = ?", group.Id).Select(
        "master_secrets.name").Joins(
        "left join group_secrets on master_secrets.id = group_secrets.sid").Rows()
    if err != nil {
        return genericFailure(cfg, err)
    }

    for rows.Next() {
        var m messages.Message
        err = rows.Scan(&m.Key.Name)
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
Client.Name => client name
*/
func KeyPubClient(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    client := new(db.Clients)
    q := cfg.Runtime.DB.Where("name = ?", msg.Client.Name).First(client)
    if q.RecordNotFound() {
        return namedFailure(404, "No such client")
    }
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }
    resp.Client.Key = shared.HexDecode(client.Pubkey)
    resp.Response = "OK"
    return
}

/*
No input
*/
func KeyPubAdmin(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)
    q := cfg.Runtime.DB.Where("name = ?", msg.Admin.Name).First(admin)
    if q.RecordNotFound() {
        return namedFailure(404, "No such admin")
    }
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }
    resp.Admin.Key = shared.HexDecode(admin.Pubkey)
    resp.Response = "OK"
    return
}

/*
No input
*/
func KeySuper(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    group := new(db.Groups)
    q := cfg.Runtime.DB.First(group, config.SuperGid)
    if q.RecordNotFound() || q.Error != nil {
        return genericFailure(cfg, q.Error)
    }
    resp.Key.GroupPub = shared.HexDecode(group.PubKey)
    resp.Response = "OK"
    return
}

/*
Key.Name => name
Key.Secret => encrypted payload
Key.Key => unique encryption key for payload encrypted with the supergroup pubkey
Key.Userkey (only required if called by non-super admin) => copy of above key, encrypted with admin local key
*/
func KeyNew(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    tx := cfg.Runtime.DB.Begin()
    if tx.Error != nil {
        return genericFailure(cfg, tx.Error)
    }
    var commit bool

    defer func() {
        if !commit {
            tx.Rollback()
        }
    }()

    if msg.Key.Name == "" || msg.Key.Secret == nil || msg.Key.Key == nil {
        return namedFailure(400, "Invalid key")
    }
    if !authobj.Super && msg.Key.Userkey == nil {
        return namedFailure(400, "Invalid key")
    }

    key := new(db.MasterSecrets)
    groupKey := new(db.GroupSecrets)

    key.Name = msg.Key.Name

    if !tx.NewRecord(key) {
        return namedFailure(400, "Key already exists")
    }

    key.Secret = shared.HexEncode(msg.Key.Secret)

    q := tx.Create(key)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    groupKey.Secret = shared.HexEncode(msg.Key.Key)
    groupKey.Gid = config.SuperGid
    groupKey.Sid = key.Id // Set when the record is created

    if !tx.NewRecord(groupKey) {
        return namedFailure(400, "Supergroup key already exists")
    }

    q = tx.Create(groupKey)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if !authobj.Super {
        adminSecret := new(db.AdminSecrets)
        adminSecret.Sid = key.Id
        adminSecret.Uid = authobj.UID
        adminSecret.Secret = msg.Key.Userkey

        q = tx.Create(adminSecret)
        if q.Error != nil {
            return genericFailure(cfg, q.Error)
        }
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
Key.Name => name
This can be called by a non-super admin, but requires that a non-superadmin has an AdminSecrets entry for that key.
*/
func KeyDel(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    tx := cfg.Runtime.DB.Begin()
    if tx.Error != nil {
        return genericFailure(cfg, tx.Error)
    }
    var commit bool

    defer func() {
        if !commit {
            tx.Rollback()
        }
    }()

    secret := new(db.MasterSecrets)
    adminSecret := new(db.AdminSecrets)
    clientSecret := new(db.ClientSecrets)
    groupSecret := new(db.GroupSecrets)

    q := tx.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if !authobj.Super {
        q := tx.Where("Sid = ?", secret.Id).First(adminSecret)
        if q.RecordNotFound() {
            return namedFailure(403, "You do not have access to this secret")
        }
    }

    q = tx.Delete(secret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = tx.Where("Sid = ? ", secret.Id).Delete(adminSecret)
    if q.Error != nil && !q.RecordNotFound() {
        return genericFailure(cfg, q.Error)
    }

    q = tx.Where("Sid = ? ", secret.Id).Delete(clientSecret)
    if q.Error != nil && !q.RecordNotFound() {
        return genericFailure(cfg, q.Error)
    }

    q = tx.Where("Sid = ? ", secret.Id).Delete(groupSecret)
    if q.Error != nil && !q.RecordNotFound() {
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
Key.Name => name
Key.Secret => encrypted payload
Same access rules apply as for KeyDel
*/
func KeyUpdate(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    secret := new(db.MasterSecrets)

    q := cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if !authobj.Super {
        adminSecret := new(db.AdminSecrets)
        q := cfg.Runtime.DB.Where("Sid = ?", secret.Id).First(adminSecret)
        if q.RecordNotFound() {
            return namedFailure(403, "You do not have access to this secret")
        }
    }

    secret.Secret = shared.HexEncode(msg.Key.Secret)
    q = cfg.Runtime.DB.Save(secret)
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
func KeyPubGroup(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    group, ret, err := dbGroupFromMessage(cfg, msg)
    if err != nil {
        return errorFailure(ret, err)
    }

    resp.Key.GroupPub = shared.HexDecode(group.PubKey)

    resp.Response = "OK"
    return
}

/*
Admin.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
*/
func KeyPrivGroup(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    group, ret, err := dbGroupFromMessage(cfg, msg)
    if err != nil {
        return errorFailure(ret, err)
    }

    resp.Key.GroupPriv = shared.HexDecode(group.PrivKey)

    resp.Response = "OK"
    return
}

/*
Admin.Name => admin name
Key.Name => secret name
Key.Secret => secret encoded with the public key of the target admin
*/
func KeyAssignAdmin(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)
    secret := new(db.MasterSecrets)
    adminSecret := new(db.AdminSecrets)

    if len(msg.Key.Secret) == 0 {
        return namedFailure(400, "No secret provided")
    }

    q := cfg.Runtime.DB.Where("name = ?", msg.Admin.Name).First(admin)
    if q.RecordNotFound() {
        return namedFailure(404, "Admin not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if admin.Gid == config.SuperGid {
        return namedFailure(400, "Cannot assign a key to a superadmin")
    }

    q = cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    adminSecret.Secret = shared.HexEncode(msg.Key.Secret)
    adminSecret.Sid = secret.Id
    adminSecret.Uid = admin.Id

    q = cfg.Runtime.DB.Create(adminSecret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}

/*
Client.Name => client name
Key.Name => secret name
Key.Secret => secret encoded with the public key of the target group
*/
func KeyAssignClient(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    client := new(db.Clients)
    secret := new(db.MasterSecrets)
    clientSecret := new(db.ClientSecrets)

    if len(msg.Key.Secret) == 0 {
        return namedFailure(400, "No secret provided")
    }

    q := cfg.Runtime.DB.Where("name = ?", msg.Client.Name).First(client)
    if q.RecordNotFound() {
        return namedFailure(404, "Client not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    clientSecret.Secret = shared.HexEncode(msg.Key.Secret)
    clientSecret.Sid = secret.Id
    clientSecret.Uid = client.Id

    q = cfg.Runtime.DB.Create(clientSecret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}

/*
Admin.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
Key.Name => secret name
Key.Secret => secret encoded with the public key of the target group
*/
func KeyAssignGroup(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    if len(msg.Key.Secret) == 0 {
        return namedFailure(400, "No secret provided")
    }

    group, ret, err := dbGroupFromMessage(cfg, msg)
    if err != nil {
        return errorFailure(ret, err)
    }

    secret := new(db.MasterSecrets)
    groupSecret := new(db.GroupSecrets)

    q := cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    groupSecret.Secret = shared.HexEncode(msg.Key.Secret)
    groupSecret.Sid = secret.Id
    groupSecret.Gid = group.Id

    q = cfg.Runtime.DB.Create(groupSecret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}

/*
Admin.Name => admin name
Key.Name => secret name
*/
func KeyRemoveAdmin(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)
    secret := new(db.MasterSecrets)
    adminSecret := new(db.AdminSecrets)

    q := cfg.Runtime.DB.Where("name = ?", msg.Admin.Name).First(admin)
    if q.RecordNotFound() {
        return namedFailure(404, "Admin not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    if admin.Gid == config.SuperGid {
        return namedFailure(400, "Cannot remove a key from a superadmin")
    }

    q = cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = cfg.Runtime.DB.Where("sid = ? and uid = ?", secret.Id, admin.Id).Delete(adminSecret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}

/*
Client.Name => client name
Key.Name => secret name
*/
func KeyRemoveClient(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    client := new(db.Clients)
    secret := new(db.MasterSecrets)
    clientSecret := new(db.ClientSecrets)

    q := cfg.Runtime.DB.Where("name = ?", msg.Client.Name).First(client)
    if q.RecordNotFound() {
        return namedFailure(404, "Client not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = cfg.Runtime.DB.Where("sid = ? and uid = ?", secret.Id, client.Id).Delete(clientSecret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}

/*
Admin.Group (optional - for an admin group) => group name
Client.Group (optional - for a client group) => group name
Key.Name => secret name
*/
func KeyRemoveGroup(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    group, ret, err := dbGroupFromMessage(cfg, msg)
    if err != nil {
        return errorFailure(ret, err)
    }

    secret := new(db.MasterSecrets)
    groupSecret := new(db.GroupSecrets)

    q := cfg.Runtime.DB.Where("name = ?", msg.Key.Name).First(secret)
    if q.RecordNotFound() {
        return namedFailure(404, "Secret not found")
    } else if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    q = cfg.Runtime.DB.Where("sid = ? and gid = ?", secret.Id, group.Id).Delete(groupSecret)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }

    resp.Response = "OK"
    return
}
