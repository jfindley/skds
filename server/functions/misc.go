package functions

import (
    "errors"

    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/messages"
    "github.com/jfindley/skds/server/auth"
    "github.com/jfindley/skds/server/db"
    "github.com/jfindley/skds/shared"
)

func genericFailure(cfg *config.Config, err error) (int, messages.Message) {
    cfg.Log(1, err)
    return 500, messages.Message{Response: "Operation failed"}
}

func errorFailure(ret int, err error) (int, messages.Message) {
    return ret, messages.Message{Response: err.Error()}
}

func namedFailure(ret int, resp string) (int, messages.Message) {
    return ret, messages.Message{Response: resp}
}

func dbGroupFromMessage(cfg *config.Config, msg messages.Message) (db.Groups, int, error) {
    var group db.Groups
    if len(msg.Admin.Group) == 0 && len(msg.Client.Group) == 0 {
        return group, 400, errors.New("Please specify a group name")
    }
    if len(msg.Admin.Group) > 0 && len(msg.Client.Group) > 0 {
        return group, 400, errors.New("Please specify either admin or client group, not both")
    }

    kind := "admin"
    name := msg.Admin.Group

    if len(msg.Client.Group) > 0 {
        kind = "client"
        name = msg.Client.Group
    }

    q := cfg.DB.Where("name = ? and kind = ?", name, kind).First(&group)
    if q.RecordNotFound() {
        return group, 404, errors.New("Group not found")
    } else if q.Error != nil {
        return group, 500, q.Error
    }
    return group, 0, nil
}

/*
No input
*/
func GetCA(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    var err error
    resp.X509.Cert, err = shared.CertEncode(cfg.Runtime.CACert)
    if err != nil {
        ret = 500
        resp.Response = err.Error()
        return
    }
    resp.Response = "OK"
    return
}

/*
No input
*/
func Test(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    resp.Response = "TEST OK.  Server version " + config.SkdsVersion
    return
}

/*
Key.GroupPub => supergroup public key
Key.Key => default admin copy of supergroup private key (enc with local key)
*/
func Setup(cfg *config.Config, authobj *auth.AuthObject, msg messages.Message) (ret int, resp messages.Message) {
    admin := new(db.Admins)
    group := new(db.Groups)

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

    q := tx.First(group, config.SuperGid)
    if q.Error != nil || q.RecordNotFound() {
        return genericFailure(cfg, q.Error)
    }
    group.PubKey = shared.HexEncode(msg.Key.GroupPub)
    q = tx.Save(group)
    if q.Error != nil {
        return genericFailure(cfg, q.Error)
    }
    q = tx.First(admin, authobj.UID)
    if q.Error != nil || q.RecordNotFound() {
        // This shouldn't really happen
        return genericFailure(cfg, q.Error)
    }
    // The client should send this encrypted - no need to zero it.
    admin.GroupKey = shared.HexEncode(msg.Key.Key)
    q = tx.Save(admin)
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
