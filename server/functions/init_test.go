package functions

// This sets up the various common parts for the tests in this package

import (
	"fmt"
	"net/http/httptest"
	"os"

	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

var (
	cfg     *shared.Config
	session *auth.SessionInfo
	unpriv  *auth.SessionInfo
)

func init() {
	cfg = new(shared.Config)
	session = new(auth.SessionInfo)
	unpriv = new(auth.SessionInfo)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.File = fmt.Sprintf("%s%s%s", os.TempDir(), string(os.PathSeparator), "skds_db_test")
	cfg.Startup.DB.User = "root"
	cfg.Startup.DB.Driver = "sqlite3"

	session.Name = "admin"
	session.UID = 1
	session.GID = shared.SuperGID
	session.Admin = true
	session.Super = true

	unpriv.Name = "unpriv"
	unpriv.UID = 3
	unpriv.GID = shared.DefAdminGID
	unpriv.Admin = true
	unpriv.Super = false
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

	rec := httptest.NewRecorder()

	r.Parse(nil, rec)

	return r, rec
}
