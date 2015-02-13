package db

import (
	"testing"

	"github.com/jfindley/skds/crypto"
)

var (
	cfg *config.Config
	err error
)

func init() {
	cfg = new(config.Config)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"

	err := cfg.DBConnect()
	if err != nil {
		panic(err)
	}
}

func TestInitDB(t *testing.T) {
	err = InitDB(cfg)
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
	err = CreateDefaults(cfg)
	if err != nil {
		t.Error(err)
	}

	group := new(Groups)
	q := cfg.DB.Where("name = ? and kind = ?", "default", "client").First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != config.DefClientGid {
		t.Error("Default client group created with wrong ID:", group.Id)
	}

	group = new(Groups)
	q = cfg.DB.Where("name = ? and kind = ?", "default", "admin").First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != config.DefAdminGid {
		t.Error("Default admin group created with wrong ID:", group.Id)
	}

	group = new(Groups)
	q = cfg.DB.Where("name = ? and kind = ?", "super", "admin").First(group)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if group.Id != config.SuperGid {
		t.Error("Supergroup created with wrong ID:", group.Id)
	}

	admin := new(Admins)
	q = cfg.DB.Where("name = ?", "admin").First(admin)
	if q.Error != nil {
		t.Error(q.Error)
	}
	if admin.Id != 1 {
		t.Error("Initial admin wrong UID:", admin.Id)
	}
	ok, err := crypto.PasswordVerify(config.DefaultAdminPass, admin.Password)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Failed to verify initial admin password")
	}
}
