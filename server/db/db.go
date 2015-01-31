package db

import (
	"strings"

	"skds/config"
	"skds/crypto"
)

type Acl struct {
	Id        uint
	AdminGid  uint
	ClientGid uint
}

type Admins struct {
	Id       uint
	Gid      uint
	Name     string `sql:"not null;unique"`
	Pubkey   []byte
	Password []byte
	GroupKey []byte
}

type Clients struct {
	Id       uint
	Gid      uint
	Name     string `sql:"not null;unique"`
	Pubkey   []byte
	Password []byte
	GroupKey []byte
}

// The secrets tables bear a little explanation.
// MasterSecrets holds the master copy of each encrypted payload.
// This is encrypted with an individual keypair.
// The supergroup (gid 1) always has a copy of this keypair, as do any other groups
// or users who have access to the key.

// If a secret is assigned directly to a user, the keypair will live in AdminSecrets
// or ClientSecrets, encrypted with the user's keypair (which is not on the server).

// If a secret is assigned to a group, the secret's keypair will be encrypted with
// the groups key, which is static for the group.
// So that a user can read this, a copy of the private key for the group is stored
// in GroupSecrets encrypted with the users keypair.

// All this kerfluffle means that we only store each secret in one place, making
// updates easy, but still get to have different encryption keys for each secret,
// so that leakage of a single decryption key does not affect more than one secret.

// NOTE: At no point is anything present on the server that can decrypt the master
// secret.  This means we don't need to zero out memory in here.
// Unencrypted passwords never get as far as these functions either.

type AdminSecrets struct {
	Id     uint
	Sid    uint
	Uid    uint
	Secret []byte
}

type ClientSecrets struct {
	Id     uint
	Sid    uint
	Uid    uint
	Path   string `sql:"type:varchar(2048)"`
	Secret []byte
}

type MasterSecrets struct {
	Id     uint
	Name   string `sql:"not null;unique"`
	Secret []byte `sql:"type:blob"` // Unlimited size
}

type Groups struct {
	Id      uint
	Name    string
	Kind    string
	PubKey  []byte
	PrivKey []byte // Key encrypted with supergroup key
}

type GroupSecrets struct {
	Id     uint
	Gid    uint
	Sid    uint
	Secret []byte
	Path   string `sql:"type:varchar(2048)"`
}

// A list of all DB tables

var tableList = map[string]interface{}{
	"Acl":           Acl{},
	"Admins":        Admins{},
	"Clients":       Clients{},
	"AdminSecrets":  AdminSecrets{},
	"ClientSecrets": ClientSecrets{},
	"MasterSecrets": MasterSecrets{},
	"Groups":        Groups{},
	"GroupSecrets":  GroupSecrets{},
}

var compoundIndexes = map[string][]string{
	"Acl":           []string{"admin_gid", "client_gid"},
	"AdminSecrets":  []string{"Sid", "Uid"},
	"ClientSecrets": []string{"Sid", "Uid"},
	"Groups":        []string{"Name", "Kind"},
	"GroupSecrets":  []string{"Gid", "Sid"},
}

func InitDB(cfg *config.Config) error {
	for _, table := range tableList {
		q := cfg.Runtime.DB.DropTableIfExists(table)
		if q.Error != nil {
			return q.Error
		}
		q = cfg.Runtime.DB.CreateTable(table)
		if q.Error != nil {
			return q.Error
		}
	}
	for table, cols := range compoundIndexes {
		q := cfg.Runtime.DB.Model(tableList[table]).AddUniqueIndex("idx_"+strings.Join(cols, "_"), cols...)
		if q.Error != nil {
			return q.Error
		}
	}
	return nil
}

func CreateDefaults(cfg *config.Config) error {
	defClientGrp := Groups{Id: config.DefClientGid, Name: "default", Kind: "client"}

	q := cfg.Runtime.DB.Create(&defClientGrp)
	if q.Error != nil {
		return q.Error
	}

	defAdminGrp := Groups{Id: config.DefAdminGid, Name: "default", Kind: "admin"}

	q = cfg.Runtime.DB.Create(&defAdminGrp)
	if q.Error != nil {
		return q.Error
	}

	superGrp := Groups{Id: config.SuperGid, Name: "super", Kind: "admin"}

	q = cfg.Runtime.DB.Create(&superGrp)
	if q.Error != nil {
		return q.Error
	}
	pass, err := crypto.PasswordHash(config.DefaultAdminPass)
	if err != nil {
		return err
	}
	admin := Admins{Gid: config.SuperGid, Name: "Admin", Password: pass}

	q = cfg.Runtime.DB.Create(&admin)
	if q.Error != nil {
		return q.Error
	}
	return nil
}
