package db

import (
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
}

func TestConnect(t *testing.T) {
	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"
	cfg.Startup.DB.Driver = "mysql"

	var err error

	cfg.DB, err = Connect(cfg.Startup.DB)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInitDB(t *testing.T) {
	err = InitDB(cfg.DB)
	if err != nil {
		t.Error(err)
	}
	cfg.DB, err = Connect(cfg.Startup.DB)
	if err != nil {
		t.Fatal(err)
	}
	err = InitTables(cfg.DB)
	if err != nil {
		t.Error(err)
	}

	for name, table := range tableList {
		if !cfg.DB.HasTable(table) {
			t.Error("Table missing:", name)
		}
	}
}

func TestCreateDefaults(t *testing.T) {
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
	ok, err := crypto.PasswordVerify(shared.DefaultAdminPass, admin.Password)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Failed to verify initial admin password")
	}
}
