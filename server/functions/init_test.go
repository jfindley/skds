package functions

// This sets up the various common parts for the tests in this package

import (
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
	"net/http"
	"net/http/httptest"
)

var (
	cfg *shared.Config
)

func init() {
	cfg = new(shared.Config)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"
	cfg.Startup.DB.Driver = "mysql"
}

func setupDB(cfg *shared.Config) (err error) {
	cfg.DB, err = db.Connect(cfg.Startup.DB)
	if err != nil {
		return err
	}

	err = db.InitTables(cfg.DB)
	if err != nil {
		return err
	}
	err = db.CreateDefaults(cfg.DB)
	if err != nil {
		return err
	}
	return nil
}

func respRecorder() (shared.Request, *httptest.ResponseRecorder) {
	var r shared.Request

	req := new(http.Request)
	rec := httptest.NewRecorder()

	err := r.New(req, rec)
	if err != nil {
		panic(err)
	}

	return r, rec
}
