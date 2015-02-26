package main

import (
	"net/http"

	// "github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

// authentication handles session creation.  Errors in message handling are for safety assumed to be bad requests.
func authentication(cfg *shared.Config, pool *auth.SessionPool, w http.ResponseWriter, r *http.Request) {
	var req shared.Request

	err := req.New(r, w)
	if err != nil {
		req.Reply(400)
		return
	}

	// As this is a new session, we don't need to do any validation, just parse the response directly.
	err = req.Parse()
	if err != nil {
		req.Reply(400)
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
		cfg.Log(1, err)
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
		cfg.Log(1, err)
		return
	}

	req.Session = session

	req.SetSessionID(id)
	req.Reply(200)
}

// func authRequest(cfg *shared.Config, pool *auth.SessionPool, res http.ResponseWriter, req *http.Request,
// 	authfunc auth.Authfunc) {
// 	var msg shared.Message

// 	body, err := ioutil.ReadAll(req.Body)
// 	if err != nil {
// 		http.Error(res, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// We only log the source of authentication requests, to avoid putting sensitive data into the logs.
// 	cfg.Log(3, "Authentiation request recieved from", req.RemoteAddr)

// 	err = json.Unmarshal(body, &msg)
// 	if err != nil {
// 		// Generally just malformed input, log in debug mode only.
// 		cfg.Log(3, err)
// 		http.Error(res, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	ok, id := pool.New(cfg, msg.Auth.Name, msg.Auth.Password, authfunc)
// 	if !ok {
// 		http.Error(res, "Authentication failed", http.StatusUnauthorized)
// 		return
// 	}

// 	res.Header().Set("sessionid", strconv.FormatInt(id, 10))
// 	res.Header().Set("key", string(pool.Pool[id].SessionKey))
// 	_, err = res.Write(nil)
// 	if err != nil {
// 		// Mostly this just means the client disconnected, log it in debug mode however.
// 		cfg.Log(3, err)
// 	}
// 	return
// }

// func apiRequest(cfg *shared.Config, pool *auth.SessionPool, job dictionary.ApiFunction, res http.ResponseWriter, req *http.Request) {
// 	var msg shared.Message

// 	body, err := ioutil.ReadAll(req.Body)
// 	if err != nil {
// 		http.Error(res, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	// In debug mode we have something similar to an access log.
// 	cfg.Log(3, req.RemoteAddr, req.RequestURI, string(body))

// 	err = json.Unmarshal(body, &msg)
// 	if err != nil {
// 		// Generally just malformed input, log in debug mode only.
// 		cfg.Log(3, err)
// 		http.Error(res, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	session, err := strconv.ParseInt(req.Header.Get("sessionid"), 10, 64)
// 	if err != nil {
// 		// Generally just malformed input, log in debug mode only.
// 		cfg.Log(3, err)
// 		http.Error(res, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	mac := []byte(req.Header.Get("mac"))

// 	if job.AuthRequired {
// 		if ok := pool.Validate(session, mac, body); !ok {
// 			http.Error(res, "Please authenticate first", http.StatusUnauthorized)
// 			return
// 		}
// 		if job.AdminOnly && !pool.Pool[session].Admin {
// 			http.Error(res, "You are not an admin user", http.StatusForbidden)
// 			return
// 		}
// 		if job.SuperOnly && !pool.Pool[session].Super {
// 			http.Error(res, "You are not a super-user", http.StatusForbidden)
// 			return
// 		}
// 		if job.AclCheck && !pool.Pool[session].Super {
// 			// Do ACL check here
// 		}
// 	}

// 	status, resp := job.Serverfn(cfg, pool.Pool[session], msg)
// 	// So that we don't have to set the return code to 200 in every func
// 	if status == 0 {
// 		status = 200
// 	}
// 	out, err := json.Marshal(resp)
// 	if err != nil {
// 		cfg.Log(3, err)
// 		http.Error(res, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	if job.AuthRequired {
// 		pool.NextKey(session)
// 		res.Header().Set("key", string(pool.Pool[session].SessionKey))
// 	}

// 	res.Header().Set("Content-Type", "text/json")
// 	res.WriteHeader(status)
// 	_, err = res.Write(out)
// 	if err != nil {
// 		// Mostly this just means the client disconnected, log it in debug mode however.
// 		cfg.Log(3, err)
// 	}
// 	return
// }
