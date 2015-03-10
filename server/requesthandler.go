// The server component
package main

import (
	"io/ioutil"
	"net/http"

	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

// login handles session creation.  Errors in message handling are for safety assumed to be bad requests.
func login(cfg *shared.Config, pool *auth.SessionPool, w http.ResponseWriter, r *http.Request) {
	var req shared.Request

	// As this is a new session, we don't need to do any validation, just parse the request directly.
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request", 400)
	}

	err = r.Body.Close()
	if err != nil {
		http.Error(w, "Unable to read request", 400)
	}

	if !req.Parse(body, w) {
		return
	}

	if req.Req.Auth.Name == "" || req.Req.Auth.Password == nil {
		req.Reply(400)
		return
	}

	user := new(db.Users)
	err = user.Get(cfg.DB, req.Req.Auth.Name)
	if db.NotFound(err) {
		req.Reply(401)
	} else if err != nil {
		cfg.Log(log.ERROR, err)
		req.Reply(500)
		return
	}

	ok, session := auth.Auth(user, req.Req.Auth.Password)
	if !ok {
		req.Reply(400)
		return
	}

	id, err := pool.Add(session)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	req.Session = session

	req.SetSessionID(id)

	cfg.Log(log.DEBUG, pool.Pool[id].Name, "logged in")

	req.Reply(200)
}

func logout(cfg *shared.Config, pool *auth.SessionPool, w http.ResponseWriter, r *http.Request) {
	ok, id, _ := pool.Validate(r)
	if !ok {
		http.Error(w, "Unauthorized", 401)
		return
	}

	cfg.Log(log.DEBUG, pool.Pool[id].Name, "logged out")

	pool.Delete(id)

	w.WriteHeader(204)
	w.Write(nil)
}

func api(cfg *shared.Config, pool *auth.SessionPool, job dictionary.APIFunc, w http.ResponseWriter, r *http.Request) {
	var req shared.Request
	var body []byte
	var err error

	if !job.AuthRequired {

		if r.Body != nil {
			body, err = ioutil.ReadAll(r.Body)
			if err != nil {
				return
			}

			err = r.Body.Close()
			if err != nil {
				return
			}
		}

		if !req.Parse(body, w) {
			return
		}

		job.Serverfn(cfg, req)

	} else {

		ok, id, body := pool.Validate(r)
		if !ok {
			http.Error(w, "Unauthorized", 401)
			return
		}

		cfg.Log(log.DEBUG, pool.Pool[id].Name, "requested", r.RequestURI)

		if !req.Parse(body, w) {
			http.Error(w, "Unable to parse request", 400)
			return
		}

		if job.AdminOnly && !pool.Pool[id].IsAdmin() {
			req.Reply(403)
			return
		}

		if job.SuperOnly && !pool.Pool[id].IsSuper() {
			req.Reply(403)
			return
		}

		req.Session = pool.Pool[id]

		job.Serverfn(cfg, req)

	}

	return
}
