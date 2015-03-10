package db

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"strings"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

// ACL controls for individual users
type UserACLs struct {
	Id       uint
	UID      uint `gorm:"column:uid"`
	GID      uint `gorm:"column:gid"`
	TargetID uint `gorm:"column:targetid"`
}

func (_ UserACLs) TableName() string {
	return "UserACLs"
}

// ACL controls for groups
type GroupACLs struct {
	Id       uint
	UID      uint `gorm:"column:uid"`
	GID      uint `gorm:"column:gid"`
	TargetID uint `gorm:"column:targetid"`
}

func (_ GroupACLs) TableName() string {
	return "GroupACLs"
}

type Users struct {
	Id       uint
	GID      uint   `gorm:"column:gid"`
	Name     string `sql:"not null;unique"`
	PubKey   []byte
	Password []byte
	GroupKey []byte
	Admin    bool
}

func (_ Users) TableName() string {
	return "Users"
}

// ACL lookup function for users
func (u Users) Lookup(db gorm.DB, uid, gid uint) bool {
	q := db.Where("UID = ? and GID = ? and TargetID = ?", uid, gid, u.Id).First(&UserACLs{})
	if q.Error != nil {
		return false
	}
	return true
}

// Get finds a user by name
func (u *Users) Get(db gorm.DB, name string) error {
	q := db.Where("name = ?", name).First(u)
	if q.RecordNotFound() {
		// Make sure to wipe the user structure
		u = &Users{}
		return nil
	}
	return q.Error
}

// Functions to statisfy the auth credentials interface.
func (u *Users) GetName() string {
	return u.Name
}

func (u *Users) GetUID() uint {
	return u.Id
}

func (u *Users) GetGID() uint {
	return u.GID
}

func (u *Users) GetPass() crypto.Binary {
	var pass crypto.Binary
	pass.Decode(u.Password)
	return pass
}

func (u *Users) IsAdmin() bool {
	return u.Admin
}

// Set the default group
func (u *Users) BeforeCreate() (err error) {
	if u.GID == 0 {
		if u.Admin {
			u.GID = shared.DefAdminGID
		} else {
			u.GID = shared.DefClientGID
		}
	}
	return
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

type UserSecrets struct {
	Id     uint
	SID    uint   `gorm:"column:sid"`
	UID    uint   `gorm:"column:uid"`
	Path   string `sql:"type:varchar(2048)"`
	Secret []byte
}

func (_ UserSecrets) TableName() string {
	return "UserSecrets"
}

type MasterSecrets struct {
	Id     uint
	Name   string `sql:"not null;unique"`
	Secret []byte `sql:"type:blob"` // Unlimited size
}

// Lookup just checks if a user has any form of access to a key.
// It does not distinguish between user-access and group-access.
func (m MasterSecrets) Lookup(db gorm.DB, uid, gid uint) bool {
	q := db.Where("UID = ? and SID = ?", uid, m.Id).First(&UserSecrets{})
	if q.Error == nil {
		return true
	}
	q = db.Where("GID = ? and SID = ?", gid, m.Id).First(&GroupSecrets{})
	if q.Error != nil {
		return false
	}
	return true
}

func (_ MasterSecrets) TableName() string {
	return "MasterSecrets"
}

type Groups struct {
	Id      uint
	Name    string
	Admin   bool
	PubKey  []byte
	PrivKey []byte // Key encrypted with supergroup key
}

func (g Groups) Lookup(db gorm.DB, uid, gid uint) bool {
	q := db.Where("UID = ? and GID = ? and TargetID = ?", uid, gid, g.Id).First(&GroupACLs{})
	if q.Error != nil {
		return false
	}
	return true
}

func (_ Groups) TableName() string {
	return "Groups"
}

type GroupSecrets struct {
	Id     uint
	GID    uint `gorm:"column:gid"`
	SID    uint `gorm:"column:sid"`
	Secret []byte
	Path   string `sql:"type:varchar(2048)"`
}

func (_ GroupSecrets) TableName() string {
	return "GroupSecrets"
}

// A list of all DB tables

var tableList = map[string]interface{}{
	"UserACLs":      UserACLs{},
	"GroupACLs":     GroupACLs{},
	"Users":         Users{},
	"UserSecrets":   UserSecrets{},
	"MasterSecrets": MasterSecrets{},
	"Groups":        Groups{},
	"GroupSecrets":  GroupSecrets{},
}

var compoundIndexes = map[string][]string{
	"UserSecrets":  []string{"SID", "UID"},
	"Groups":       []string{"Name", "Admin"},
	"GroupSecrets": []string{"GID", "SID"},
}

func Connect(cfg shared.DBSettings) (db gorm.DB, err error) {
	var uri string
	if cfg.Host == "localhost" {
		uri = fmt.Sprintf("%s:%s@/%s", cfg.User,
			cfg.Pass, cfg.Database)
	} else {
		uri = fmt.Sprintf("%s:%s@(%s:%s)/%s", cfg.User,
			cfg.Pass, cfg.Host, cfg.Port,
			cfg.Database)
	}
	db, err = gorm.Open(cfg.Driver, uri)
	if err != nil {
		return
	}
	// Test we sucessfully connected and set limits
	err = db.DB().Ping()
	db.DB().SetMaxIdleConns(10)
	db.DB().SetMaxOpenConns(100)
	db.SingularTable(true)
	return
}

func InitTables(db gorm.DB) error {
	for _, table := range tableList {
		q := db.DropTableIfExists(table)
		if q.Error != nil {
			return q.Error
		}
		q = db.CreateTable(table)
		if q.Error != nil {
			return q.Error
		}
	}
	for table, cols := range compoundIndexes {
		q := db.Model(tableList[table]).AddUniqueIndex("idx_"+strings.Join(cols, "_"), cols...)
		if q.Error != nil {
			return q.Error
		}
	}
	return nil
}

func CreateDefaults(db gorm.DB) error {
	defClientGrp := Groups{Id: shared.DefClientGID, Name: "default", Admin: false}

	q := db.Create(&defClientGrp)
	if q.Error != nil {
		return q.Error
	}

	defAdminGrp := Groups{Id: shared.DefAdminGID, Name: "default", Admin: true}

	q = db.Create(&defAdminGrp)
	if q.Error != nil {
		return q.Error
	}

	superGrp := Groups{Id: shared.SuperGID, Name: "super", Admin: true}

	q = db.Create(&superGrp)
	if q.Error != nil {
		return q.Error
	}
	pass, err := crypto.PasswordHash(shared.DefaultAdminPass)
	if err != nil {
		return err
	}
	enc, err := pass.Encode()
	if err != nil {
		return err
	}
	admin := Users{GID: shared.SuperGID, Name: "Admin", Password: enc, Admin: true}

	q = db.Create(&admin)
	if q.Error != nil {
		return q.Error
	}
	return nil
}

func NotFound(err error) bool {
	switch err {
	case nil:
		return false
	case gorm.RecordNotFound:
		return true
	default:
		return false
	}
}
