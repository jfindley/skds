package functions

import (
    "bytes"
    "testing"

    "skds/config"
    "skds/messages"
    "skds/server/db"
    "skds/shared"
)

func TestKeyList(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    secret := new(db.MasterSecrets)
    secret.Name = "test secret 1"

    cfg.Runtime.DB.Create(secret)

    secret = new(db.MasterSecrets)
    secret.Name = "test secret 2"

    cfg.Runtime.DB.Create(secret)

    ret, resp := KeyList(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if len(resp.ResponseData) != 2 {
        t.Error("Expected 2 results, got", len(resp.ResponseData))
    }
}

func TestKeyListAdmin(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    admin := new(db.Admins)
    admin.Name = "test admin"
    admin.Gid = 10
    cfg.Runtime.DB.Create(admin)

    secret := new(db.MasterSecrets)
    groupSecret := new(db.GroupSecrets)
    adminSecret := new(db.AdminSecrets)

    secret.Name = "test secret 1"
    cfg.Runtime.DB.Create(secret)

    groupSecret.Gid = admin.Gid
    groupSecret.Sid = secret.Id
    cfg.Runtime.DB.Create(groupSecret)

    secret = new(db.MasterSecrets)
    secret.Name = "test secret 2"
    cfg.Runtime.DB.Create(secret)

    adminSecret.Uid = admin.Id
    adminSecret.Sid = secret.Id
    cfg.Runtime.DB.Create(adminSecret)

    secret = new(db.MasterSecrets)
    secret.Name = "test secret 3"
    cfg.Runtime.DB.Create(secret)

    msg.Admin.Name = admin.Name

    ret, resp := KeyListAdmin(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if len(resp.ResponseData) != 2 {
        t.Error("Expected 2 results, got", len(resp.ResponseData))
    }

    k := resp.ResponseData[0].Key
    if k.Name != "test secret 1" {
        t.Error("Secret 1 does not match")
    }

    k = resp.ResponseData[1].Key
    if k.Name != "test secret 2" {
        t.Error("Secret 2 does not match")
    }
}

func TestKeyListClient(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    client := new(db.Clients)
    client.Name = "test client"
    client.Gid = 10
    cfg.Runtime.DB.Create(client)

    secret := new(db.MasterSecrets)
    groupSecret := new(db.GroupSecrets)
    clientSecret := new(db.ClientSecrets)

    secret.Name = "test secret 1"
    cfg.Runtime.DB.Create(secret)

    groupSecret.Gid = client.Gid
    groupSecret.Sid = secret.Id
    groupSecret.Path = "/group/path"
    cfg.Runtime.DB.Create(groupSecret)

    secret = new(db.MasterSecrets)
    secret.Name = "test secret 2"
    cfg.Runtime.DB.Create(secret)

    clientSecret.Uid = client.Id
    clientSecret.Sid = secret.Id
    clientSecret.Path = "/client/path"
    cfg.Runtime.DB.Create(clientSecret)

    secret = new(db.MasterSecrets)
    secret.Name = "test secret 3"
    cfg.Runtime.DB.Create(secret)

    msg.Client.Name = client.Name

    ret, resp := KeyListClient(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if len(resp.ResponseData) != 2 {
        t.Error("Expected 2 results, got", len(resp.ResponseData))
    }

    k := resp.ResponseData[0].Key
    if k.Path != groupSecret.Path || k.Name != "test secret 1" {
        t.Error("Secret 1 does not match")
    }

    k = resp.ResponseData[1].Key
    if k.Path != clientSecret.Path || k.Name != "test secret 2" {
        t.Error("Secret 2 does not match")
    }
}

func TestKeyListGroup(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    group := new(db.Groups)
    group.Name = "test group"
    group.Kind = "client"
    cfg.Runtime.DB.Create(group)

    client := new(db.Clients)
    client.Name = "test client"
    client.Gid = group.Id
    cfg.Runtime.DB.Create(client)

    secret := new(db.MasterSecrets)
    groupSecret := new(db.GroupSecrets)

    secret.Name = "test secret 1"
    cfg.Runtime.DB.Create(secret)

    groupSecret.Gid = client.Gid
    groupSecret.Sid = secret.Id
    cfg.Runtime.DB.Create(groupSecret)

    secret = new(db.MasterSecrets)
    secret.Name = "test secret 2"
    cfg.Runtime.DB.Create(secret)

    msg.Client.Name = client.Name
    msg.Client.Group = group.Name

    ret, resp := KeyListGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if len(resp.ResponseData) != 1 {
        t.Error("Expected 1 results, got", len(resp.ResponseData))
    }

    k := resp.ResponseData[0].Key
    if k.Name != "test secret 1" {
        t.Error("Secret 1 does not match")
    }
}

func TestKeyPubClient(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    key := []byte("test pub key")

    client := new(db.Clients)
    client.Name = "test client"
    client.Pubkey = shared.HexEncode(key)

    cfg.Runtime.DB.Create(client)

    msg.Client.Name = client.Name

    ret, resp := KeyPubClient(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    if bytes.Compare(key, resp.Client.Key) != 0 {
        t.Error("Public key does not match")
    }
}

func TestKeyPubAdmin(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    key := []byte("test pub key")

    admin := new(db.Admins)
    admin.Name = "test admin"
    admin.Pubkey = shared.HexEncode(key)

    cfg.Runtime.DB.Create(admin)

    msg.Admin.Name = admin.Name

    ret, resp := KeyPubAdmin(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    if bytes.Compare(key, resp.Admin.Key) != 0 {
        t.Error("Public key does not match")
    }
}

func TestKeySuper(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    key := []byte("test pub key")

    group := new(db.Groups)
    cfg.Runtime.DB.First(group, config.SuperGid).Update("PubKey", shared.HexEncode(key))

    ret, resp := KeySuper(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if bytes.Compare(resp.Key.GroupPub, key) != 0 {
        t.Fatal("Stored value does not match input")
    }
}

func TestKeyNew(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    key := []byte("test key")
    enc := []byte("test secret")

    msg.Key.Name = "test key"
    msg.Key.Secret = enc
    msg.Key.Key = key

    ret, resp := KeyNew(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret := new(db.MasterSecrets)
    groupKey := new(db.GroupSecrets)

    cfg.Runtime.DB.First(secret)
    cfg.Runtime.DB.First(groupKey)

    if secret.Name != msg.Key.Name {
        t.Error("Secret has the wrong name")
    }
    if groupKey.Sid != secret.Id {
        t.Error("Groupkey SID does not match secret ID")
    }
    if bytes.Compare(shared.HexDecode(secret.Secret), enc) != 0 {
        t.Error("Stored value does not match input")
    }
    if bytes.Compare(shared.HexDecode(groupKey.Secret), key) != 0 {
        t.Error("Stored value does not match input")
    }
}

func TestKeyDel(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    secret := new(db.MasterSecrets)
    adminSecret := new(db.AdminSecrets)
    clientSecret := new(db.ClientSecrets)
    groupSecret := new(db.GroupSecrets)

    secret.Name = "Test secret"
    msg.Key.Name = secret.Name

    ret, resp := KeyDel(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    cfg.Runtime.DB.Create(secret)

    authobj.Super = false

    ret, resp = KeyDel(cfg, authobj, msg)
    if ret != 403 || resp.Response != "You do not have access to this secret" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    authobj.Super = true

    adminSecret.Sid = secret.Id
    clientSecret.Sid = secret.Id
    groupSecret.Sid = secret.Id
    cfg.Runtime.DB.Create(adminSecret)
    cfg.Runtime.DB.Create(clientSecret)
    cfg.Runtime.DB.Create(groupSecret)

    ret, resp = KeyDel(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    q := cfg.Runtime.DB.First(secret, secret.Id)
    if !q.RecordNotFound() {
        t.Error("Secret not deleted")
    }

    q = cfg.Runtime.DB.First(adminSecret, secret.Id)
    if !q.RecordNotFound() {
        t.Error("Admin secret not deleted")
    }

    q = cfg.Runtime.DB.First(clientSecret, secret.Id)
    if !q.RecordNotFound() {
        t.Error("Client secret not deleted")
    }

    q = cfg.Runtime.DB.First(groupSecret, secret.Id)
    if !q.RecordNotFound() {
        t.Error("Group secret not deleted")
    }
}

func TestKeyUpdate(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    secret := new(db.MasterSecrets)

    ret, resp := KeyUpdate(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = "Test secret"
    cfg.Runtime.DB.Create(secret)

    msg.Key.Name = secret.Name
    msg.Key.Secret = []byte("testing payload")

    authobj.Super = false

    ret, resp = KeyUpdate(cfg, authobj, msg)
    if ret != 403 || resp.Response != "You do not have access to this secret" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    authobj.Super = true

    ret, resp = KeyUpdate(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    cfg.Runtime.DB.First(secret)

    if bytes.Compare(msg.Key.Secret, shared.HexDecode(secret.Secret)) != 0 {
        t.Error("Secret not updated correctly")
    }
}

func TestKeyPubGroup(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    msg.Admin.Group = "test admin group"

    group := new(db.Groups)
    group.Name = msg.Admin.Group
    group.Kind = "admin"
    group.PubKey = shared.HexEncode([]byte("pub"))

    cfg.Runtime.DB.Create(group)

    ret, resp := KeyPubGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if bytes.Compare(shared.HexDecode(group.PubKey), resp.Key.GroupPub) != 0 {
        t.Error("Public key does not match")
    }

    group = new(db.Groups)
    group.Name = "test client group"
    group.Kind = "client"
    group.PubKey = shared.HexEncode([]byte("pub"))

    msg.Admin.Group = ""
    msg.Client.Group = group.Name

    cfg.Runtime.DB.Create(group)

    ret, resp = KeyPubGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if bytes.Compare(shared.HexDecode(group.PubKey), resp.Key.GroupPub) != 0 {
        t.Error("Public key does not match")
    }
}

func TestKeyPrivGroup(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    msg.Admin.Group = "test admin group"

    group := new(db.Groups)
    group.Name = msg.Admin.Group
    group.Kind = "admin"
    group.PrivKey = shared.HexEncode([]byte("priv"))

    cfg.Runtime.DB.Create(group)

    ret, resp := KeyPrivGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if bytes.Compare(shared.HexDecode(group.PrivKey), resp.Key.GroupPriv) != 0 {
        t.Error("Private key does not match")
    }

    group = new(db.Groups)
    group.Name = "test client group"
    group.Kind = "client"
    group.PrivKey = shared.HexEncode([]byte("priv"))

    msg.Admin.Group = ""
    msg.Client.Group = group.Name

    cfg.Runtime.DB.Create(group)

    ret, resp = KeyPrivGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
    if bytes.Compare(shared.HexDecode(group.PrivKey), resp.Key.GroupPriv) != 0 {
        t.Error("Private key does not match")
    }
}

func TestKeyAssignAdmin(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    ret, resp := KeyAssignAdmin(cfg, authobj, msg)
    if ret != 400 || resp.Response != "No secret provided" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    admin := new(db.Admins)
    secret := new(db.MasterSecrets)

    msg.Key.Secret = []byte("test secret")

    ret, resp = KeyAssignAdmin(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Admin not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    msg.Admin.Name = "test admin"
    msg.Key.Name = "test secret"

    admin.Gid = config.SuperGid
    admin.Name = msg.Admin.Name

    cfg.Runtime.DB.Create(admin)

    ret, resp = KeyAssignAdmin(cfg, authobj, msg)
    if ret != 400 || resp.Response != "Cannot assign a key to a superadmin" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    admin.Gid = config.DefAdminGid
    cfg.Runtime.DB.Save(admin)

    ret, resp = KeyAssignAdmin(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = msg.Key.Name

    cfg.Runtime.DB.Create(secret)

    ret, resp = KeyAssignAdmin(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
}

func TestKeyAssignClient(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    ret, resp := KeyAssignClient(cfg, authobj, msg)
    if ret != 400 || resp.Response != "No secret provided" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    client := new(db.Clients)
    secret := new(db.MasterSecrets)

    msg.Key.Secret = []byte("test secret")

    ret, resp = KeyAssignClient(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Client not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    msg.Client.Name = "test client"
    msg.Key.Name = "test secret"

    client.Name = msg.Client.Name

    cfg.Runtime.DB.Create(client)

    ret, resp = KeyAssignClient(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = msg.Key.Name

    cfg.Runtime.DB.Create(secret)

    ret, resp = KeyAssignClient(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
}

func TestKeyAssignGroup(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    ret, resp := KeyAssignGroup(cfg, authobj, msg)
    if ret != 400 || resp.Response != "No secret provided" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    msg.Key.Secret = []byte("test secret")
    msg.Admin.Group = "test admin group"

    group := new(db.Groups)
    secret := new(db.MasterSecrets)

    msg.Key.Name = "test secret"
    group.Name = msg.Admin.Group
    group.Kind = "admin"
    cfg.Runtime.DB.Create(group)

    ret, resp = KeyAssignGroup(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = msg.Key.Name

    cfg.Runtime.DB.Create(secret)

    ret, resp = KeyAssignGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    group = new(db.Groups)
    group.Name = "test client group"
    group.Kind = "client"
    cfg.Runtime.DB.Create(group)

    msg.Admin.Group = ""
    msg.Client.Group = group.Name

    ret, resp = KeyAssignGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }
}

func TestKeyRemoveAdmin(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    admin := new(db.Admins)
    secret := new(db.MasterSecrets)
    adminSecret := new(db.AdminSecrets)

    msg.Key.Secret = []byte("test secret")

    ret, resp := KeyRemoveAdmin(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Admin not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    msg.Admin.Name = "test admin"
    msg.Key.Name = "test secret"

    admin.Gid = config.SuperGid
    admin.Name = msg.Admin.Name

    cfg.Runtime.DB.Create(admin)

    ret, resp = KeyRemoveAdmin(cfg, authobj, msg)
    if ret != 400 || resp.Response != "Cannot remove a key from a superadmin" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    admin.Gid = config.DefAdminGid
    cfg.Runtime.DB.Save(admin)

    ret, resp = KeyRemoveAdmin(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = msg.Key.Name

    cfg.Runtime.DB.Create(secret)

    adminSecret.Sid = secret.Id
    adminSecret.Uid = admin.Id
    cfg.Runtime.DB.Create(adminSecret)

    ret, resp = KeyRemoveAdmin(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    q := cfg.Runtime.DB.First(adminSecret)
    if !q.RecordNotFound() {
        t.Fatal("Secret access not removed")
    }
}

func TestKeyRemoveClient(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    client := new(db.Clients)
    secret := new(db.MasterSecrets)
    clientSecret := new(db.ClientSecrets)

    msg.Key.Secret = []byte("test secret")

    ret, resp := KeyRemoveClient(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Client not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    msg.Client.Name = "test client"
    msg.Key.Name = "test secret"

    client.Name = msg.Client.Name

    cfg.Runtime.DB.Create(client)

    cfg.Runtime.DB.Save(client)

    ret, resp = KeyRemoveClient(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = msg.Key.Name

    cfg.Runtime.DB.Create(secret)

    clientSecret.Sid = secret.Id
    clientSecret.Uid = client.Id
    cfg.Runtime.DB.Create(clientSecret)

    ret, resp = KeyRemoveClient(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    q := cfg.Runtime.DB.First(clientSecret)
    if !q.RecordNotFound() {
        t.Fatal("Secret access not removed")
    }
}

func TestKeyRemoveGroup(t *testing.T) {
    var msg messages.Message
    err = setupDB(cfg)
    if err != nil {
        t.Fatal(err)
    }
    defer cfg.Runtime.DB.Close()

    msg.Admin.Group = "test admin group"

    group := new(db.Groups)
    secret := new(db.MasterSecrets)
    groupSecret := new(db.GroupSecrets)

    ret, resp := KeyRemoveGroup(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Group not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    msg.Key.Name = "test secret"
    group.Name = msg.Admin.Group
    group.Kind = "admin"
    cfg.Runtime.DB.Create(group)

    ret, resp = KeyRemoveGroup(cfg, authobj, msg)
    if ret != 404 || resp.Response != "Secret not found" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    secret.Name = msg.Key.Name

    cfg.Runtime.DB.Create(secret)

    groupSecret.Gid = group.Id
    groupSecret.Sid = secret.Id
    cfg.Runtime.DB.Create(groupSecret)

    ret, resp = KeyRemoveGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    q := cfg.Runtime.DB.First(groupSecret)
    if !q.RecordNotFound() {
        t.Fatal("Secret access not removed")
    }

    group = new(db.Groups)
    groupSecret = new(db.GroupSecrets)

    group.Name = "test client group"
    group.Kind = "client"
    cfg.Runtime.DB.Create(group)

    groupSecret.Gid = group.Id
    groupSecret.Sid = secret.Id
    cfg.Runtime.DB.Create(groupSecret)

    msg.Admin.Group = ""
    msg.Client.Group = group.Name

    ret, resp = KeyRemoveGroup(cfg, authobj, msg)
    if ret != 0 || resp.Response != "OK" {
        t.Fatal("Bad result :", ret, resp.Response)
    }

    q = cfg.Runtime.DB.First(groupSecret)
    if !q.RecordNotFound() {
        t.Fatal("Secret access not removed")
    }
}
