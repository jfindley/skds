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
type UserACL struct {
	Id       uint
	UID      uint `gorm:"column:UID"`
	GID      uint `gorm:"column:GID"`
	TargetID uint `gorm:"column:TargetID"`
}

func (_ UserACL) TableName() string {
	return "UserACL"
}

// ACL controls for groups
type GroupACL struct {
	Id       uint
	UID      uint `gorm:"column:UID"`
	GID      uint `gorm:"column:GID"`
	TargetID uint `gorm:"column:TargetID"`
}

func (_ GroupACL) TableName() string {
	return "GroupACL"
}

type Users struct {
	Id       uint
	GID      uint   `gorm:"column:GID"`
	Name     string `sql:"not null;unique"`
	Pubkey   []byte
	Password []byte
	GroupKey []byte
	Admin    bool
}

func (_ Users) TableName() string {
	return "Users"
}

// ACL lookup function for users
func (u Users) Lookup(db gorm.DB, uid, gid uint) bool {
	q := db.Where("UID = ?, GID = ?, TargetID = ?", uid, gid, u.Id).First(&UserACL{})
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

func (u *Users) GetAdmin() bool {
	return u.Admin
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
	SID    uint   `gorm:"column:SID"`
	UID    uint   `gorm:"column:UID"`
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
	q := db.Where("UID = ?, SID = ?", uid, m.Id).First(&UserSecrets{})
	if q.Error == nil {
		return true
	}
	q = db.Where("GID = ?, SID = ?", gid, m.Id).First(&GroupSecrets{})
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
	q := db.Where("UID = ?, GID = ?, TargetID = ?", uid, gid, g.Id).First(&GroupACL{})
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
	GID    uint `gorm:"column:GID"`
	SID    uint `gorm:"column:SID"`
	Secret []byte
	Path   string `sql:"type:varchar(2048)"`
}

func (_ GroupSecrets) TableName() string {
	return "GroupSecrets"
}

// A list of all DB tables

var tableList = map[string]interface{}{
	"UserACL":       UserACL{},
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

// InitDB completes wipes and re-creates the main and test DBs.
// This closes the DB handler, and it must be re-opened if needed.
func InitDB(db gorm.DB) error {
	_, err := db.DB().Exec("drop database if exists skds")
	if err != nil {
		return err
	}
	_, err = db.DB().Exec("drop database if exists skds_test")
	if err != nil {
		return err
	}

	_, err = db.DB().Exec("create database skds")
	if err != nil {
		return err
	}
	_, err = db.DB().Exec("create database skds_test")
	if err != nil {
		return err
	}
	return db.Close()
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
	admin := Users{GID: shared.SuperGID, Name: "Admin", Password: pass, Admin: true}

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
