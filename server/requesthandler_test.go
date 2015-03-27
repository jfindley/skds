// +build linux darwin

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

type closingBuffer struct {
	*bytes.Buffer
}

func (cb closingBuffer) Close() error {
	return nil
}

func TestAuthentication(t *testing.T) {
	var msg shared.Message
	var err error

	msg.Auth.Name = "admin"
	msg.Auth.Password = []byte("password")

	testData, err := json.Marshal(&msg)
	if err != nil {
		t.Fatal(err)
	}

	in := &closingBuffer{bytes.NewBuffer(testData)}
	req := new(http.Request)
	req.Body = *in

	rec := httptest.NewRecorder()
	cfg := new(shared.Config)
	pool := new(auth.SessionPool)

	cfg.Startup.DB.Database = "skds_test"
	cfg.Startup.DB.Host = "localhost"
	cfg.Startup.DB.User = "root"
	cfg.Startup.DB.Driver = "mysql"

	cfg.DB, err = db.Connect(cfg.Startup.DB)
	if err != nil {
		t.Fatal(err)
	}

	err = db.InitTables(cfg.DB)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := crypto.PasswordHash([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}

	ok, _ := crypto.PasswordVerify([]byte("password"), hash)
	if !ok {
		t.Fatal(".")
	}

	enc, err := hash.Encode()
	if err != nil {
		t.Fatal(err)
	}

	cfg.DB.Create(&db.Users{Id: 5, Name: "admin", Password: enc, Admin: true})

	authentication(cfg, pool, rec, req)

	if rec.Code != 200 {
		t.Error("Recieved bad response:", rec.Code)
	}

	if rec.Header().Get("Session-ID") == "" {
		t.Error("No session ID in response headers")
	}

	if rec.Header().Get("X-AUTH-KEY") == "" {
		t.Error("No session key in response headers")
	}
}

func TestApi(t *testing.T) {
	var job dictionary.APIFunc

	job.Serverfn = func(cfg *shared.Config, r shared.Request) {
		r.Reply(200)
		return
	}

	// Test unauthenticated functions

	rec := httptest.NewRecorder()
	cfg := new(shared.Config)
	pool := new(auth.SessionPool)
	req := new(http.Request)

	api(cfg, pool, job, rec, req)

	if rec.Code != 200 {
		t.Error("Bad response code:", rec.Code)
	}

	// Create session and request

	sess := new(auth.SessionInfo)

	id, err := pool.Add(sess)
	if err != nil {
		t.Error(err)
	}

	testData := []byte(`{"Request":"Test"}`)

	req.Body = closingBuffer{bytes.NewBuffer(testData)}

	req.RequestURI = "/test/request"

	mac := crypto.NewMAC(pool.Pool[id].SessionKey, "/test/request", testData)

	req.Header = http.Header(make(map[string][]string))
	req.Header.Add(shared.HdrMAC, mac)
	req.Header.Add(shared.HdrSession, strconv.FormatInt(id, 10))

	// Test authenticated functions

	job.AuthRequired = true

	rec = httptest.NewRecorder()
	api(cfg, pool, job, rec, req)
	if rec.Code != 200 {
		t.Error("Bad response code:", rec.Code)
	}

	// Test admin restrictions

	job.AdminOnly = true

	req.Body = closingBuffer{bytes.NewBuffer(testData)}
	rec = httptest.NewRecorder()
	api(cfg, pool, job, rec, req)
	if rec.Code != 403 {
		t.Error("Bad response code:", rec.Code)
	}

	pool.Pool[id].Admin = true

	req.Body = closingBuffer{bytes.NewBuffer(testData)}
	rec = httptest.NewRecorder()
	api(cfg, pool, job, rec, req)
	if rec.Code != 200 {
		t.Error("Bad response code:", rec.Code)
	}

	// Test super user restrictions

	job.SuperOnly = true

	req.Body = closingBuffer{bytes.NewBuffer(testData)}
	rec = httptest.NewRecorder()
	api(cfg, pool, job, rec, req)
	if rec.Code != 403 {
		t.Error("Bad response code:", rec.Code)
	}

	pool.Pool[id].Super = true

	req.Body = closingBuffer{bytes.NewBuffer(testData)}
	rec = httptest.NewRecorder()
	api(cfg, pool, job, rec, req)
	if rec.Code != 200 {
		t.Error("Bad response code:", rec.Code)
	}
}
