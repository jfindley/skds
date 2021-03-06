package db

import (
	"fmt"
	"os"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
)

var (
	cfg *shared.Config
	err error
)

func init() {
	cfg = new(shared.Config)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"

	cfg.Startup.DB.File = fmt.Sprintf("%s%s%s", os.TempDir(), string(os.PathSeparator), "skds_db_test")
}

func TestMysql(t *testing.T) {

	cfg.Startup.DB.Driver = "mysql"

	var err error

	cfg.DB, err = Connect(cfg.Startup.DB)
	if err != nil {
		t.Fatal(err)
	}

	err = InitTables(cfg.DB)
	if err != nil {
		t.Error(err)
	}

	err = CreateDefaults(cfg.DB)
	if err != nil {
		t.Error(err)
	}

	group := new(Groups)
	q := cfg.DB.Where("name = ? and admin = ?", "default", false).First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != shared.DefClientGID {
		t.Error("Default client group created with wrong ID:", group.Id)
	}

	group = new(Groups)
	q = cfg.DB.Where("name = ? and admin = ?", "default", true).First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != shared.DefAdminGID {
		t.Error("Default admin group created with wrong ID:", group.Id)
	}

	group = new(Groups)
	q = cfg.DB.Where("name = ? and admin = ?", "super", true).First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != shared.SuperGID {
		t.Error("Supergroup created with wrong ID:", group.Id)
	}

	admin := new(Users)
	q = cfg.DB.Where("name = ?", "admin").First(admin)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if admin.Id != 1 {
		t.Error("Initial admin wrong UID:", admin.Id)
	}
	var dbPass crypto.Binary
	err = dbPass.Decode(admin.Password)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := crypto.PasswordVerify(shared.DefaultAdminPass, dbPass)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Failed to verify initial admin password")
	}

	cfg.DB.Close()
}

func TestSQLite(t *testing.T) {
	cfg.Startup.DB.Driver = "sqlite3"

	var err error

	cfg.DB, err = Connect(cfg.Startup.DB)
	if err != nil {
		t.Fatal(err)
	}

	err = InitTables(cfg.DB)
	if err != nil {
		t.Error(err)
	}

	err = CreateDefaults(cfg.DB)
	if err != nil {
		t.Error(err)
	}

	group := new(Groups)
	q := cfg.DB.Where("name = ? and admin = ?", "default", false).First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != shared.DefClientGID {
		t.Error("Default client group created with wrong ID:", group.Id)
	}

	group = new(Groups)
	q = cfg.DB.Where("name = ? and admin = ?", "default", true).First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != shared.DefAdminGID {
		t.Error("Default admin group created with wrong ID:", group.Id)
	}

	group = new(Groups)
	q = cfg.DB.Where("name = ? and admin = ?", "super", true).First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != shared.SuperGID {
		t.Error("Supergroup created with wrong ID:", group.Id)
	}

	admin := new(Users)
	q = cfg.DB.Where("name = ?", "admin").First(admin)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if admin.Id != 1 {
		t.Error("Initial admin wrong UID:", admin.Id)
	}
	var dbPass crypto.Binary
	err = dbPass.Decode(admin.Password)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := crypto.PasswordVerify(shared.DefaultAdminPass, dbPass)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Failed to verify initial admin password")
	}

	cfg.DB.Close()

	os.Remove(cfg.Startup.DB.File)
}
