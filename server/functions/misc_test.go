package functions

import (
    "bytes"
    "testing"

    "skds/config"
    "skds/crypto"
    "skds/messages"
    "skds/server/db"
    "skds/shared"
)

func TestgenericFailure(t *testing.T) {
    var err error

    ret, resp := genericFailure(cfg, err)
    if ret != 500 || resp.Response != "Operation failed" {
        t.Error("Invalid response")
    }
}

func TestdbGroupFromMessage(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    _, ret, err := dbGroupFromMessage(cfg, msg)
    if ret != 400 || err.Error() != "Please specify a group name" {
        t.Fatal("Bad result :", ret, err.Error())
    }

    msg.Admin.Group = "test admin group"
    _, ret, err = dbGroupFromMessage(cfg, msg)
    if ret != 404 || err.Error() != "Group not found" {
        t.Fatal("Bad result :", ret, err.Error())
    }

    msg.Client.Group = "test client group"
    _, ret, err = dbGroupFromMessage(cfg, msg)
    if ret != 400 || err.Error() != "Please specify either admin or client group, not both" {
        t.Fatal("Bad result :", ret, err.Error())
    }

    msg.Client.Group = ""

    group := new(db.Groups)
    group.Name = msg.Admin.Group
    group.Kind = "admin"
    cfg.Runtime.DB.Create(group)

    retGroup, ret, err := dbGroupFromMessage(cfg, msg)
    if ret != 0 || err != nil {
        t.Fatal("Bad result :", ret, err.Error())
    }

    if retGroup.Kind != group.Kind || retGroup.Name != group.Name {
        t.Error("Group in DB does not match group in message")
    }

    group = new(db.Groups)
    group.Name = "test client group"
    group.Kind = "client"
    cfg.Runtime.DB.Create(group)

    msg.Client.Group = group.Name
    msg.Admin.Group = ""

    retGroup, ret, err = dbGroupFromMessage(cfg, msg)
    if ret != 0 || err != nil {
        t.Fatal("Bad result :", ret, err.Error())
    }

    if retGroup.Kind != group.Kind || retGroup.Name != group.Name {
        t.Error("Group in DB does not match group in message")
    }
}

func TestGetCA(t *testing.T) {
    var msg messages.Message

    key, err := crypto.GenKey(2048)
    if err != nil {
        t.Fatal(err)
    }
    cfg.Runtime.CACert, err = crypto.GenCert("test", true, true, 1, &key.PublicKey, key, nil)
    if err != nil {
        t.Fatal(err)
    }

    ret, resp := GetCA(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Error("Invalid response")
    }

    respCert, err := shared.CertDecode(resp.X509.Cert)
    if err != nil {
        t.Fatal(err)
    }

    if bytes.Compare(respCert.Raw, cfg.Runtime.CACert.Raw) != 0 {
        t.Error("Returned CA cert does not match")
    }

}

func TestSetup(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    localkey, err := crypto.GenerateKey()
    if err != nil {
        t.Fatal(err)
    }
    superkey, err := crypto.GenerateKey()
    if err != nil {
        t.Fatal(err)
    }

    msg.Key.GroupPub = superkey.Pub
    msg.Key.Key, err = crypto.Encrypt(superkey.Priv, localkey, localkey.Pub)
    if err != nil {
        t.Fatal(err)
    }

    ret, resp := Setup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    admin := new(db.Admins)
    group := new(db.Groups)
    cfg.Runtime.DB.First(admin, authobj.UID)
    cfg.Runtime.DB.First(group, config.SuperGid)

    if bytes.Compare(shared.HexDecode(admin.GroupKey), msg.Key.Key) != 0 {
        t.Error("Stored value does not match input")
    }

    if bytes.Compare(shared.HexDecode(group.PubKey), msg.Key.GroupPub) != 0 {
        t.Error("Stored value does not match input")
    }
}
