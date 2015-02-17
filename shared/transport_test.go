package shared

// // We use one huge testing function for this package to avoid creating and
// // terminating http servers for each individual test function.

// import (
// 	"encoding/json"
// 	"io/ioutil"
// 	"net/http"
// 	"os"
// 	"testing"

// 	"github.com/jfindley/skds/crypto"
// )

// var testReq = "Hello SKDS"

// func return200(w http.ResponseWriter, r *http.Request) {
// 	w.WriteHeader(200)
// 	return
// }

// func returnError(w http.ResponseWriter, r *http.Request) {
// 	w.WriteHeader(500)
// 	return
// }

// func returnNamedError(w http.ResponseWriter, r *http.Request) {
// 	w.WriteHeader(500)
// 	var m Message
// 	m.Response = "Failed"
// 	d, err := json.Marshal(m)
// 	if err != nil {
// 		panic(err)
// 	}
// 	w.Write(d)
// }

// func uncondSuccess(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set(hdrSession, "1234")
// 	w.Header().Set(hdrKey, "26774619fb65718d94b4378badd15175b8bd231dd08425714160a32828a29ce0")
// 	w.WriteHeader(200)
// 	return
// }

// func badSessionKey(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set(hdrSession, "5678")
// 	w.Header().Set(hdrKey, "")
// 	w.WriteHeader(200)
// 	return
// }

// func verifySig(w http.ResponseWriter, r *http.Request) {
// 	sig := r.Header.Get(hdrKey)
// 	if len(sig) == 0 {
// 		w.Header().Set(hdrSession, "1234")
// 		w.Header().Set(hdrKey, "26774619fb65718d94b4378badd15175b8bd231dd08425714160a32828a29ce0")
// 		w.WriteHeader(200)
// 	} else {
// 		w.WriteHeader(500)
// 	}
// }

// func testRequest(w http.ResponseWriter, r *http.Request) {
// 	req := new(Message)
// 	resp := new(Message)

// 	body, err := ioutil.ReadAll(r.Body)
// 	if err != nil {
// 		panic(err)
// 	}
// 	err = r.Body.Close()
// 	if err != nil {
// 		panic(err)
// 	}

// 	err = json.Unmarshal(body, req)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Basic GET request
// 	if body == nil {
// 		resp.Response = "OK"
// 		data, err := json.Marshal(resp)
// 		if err != nil {
// 			panic(err)
// 		}
// 	}

// 	switch req.Admin.Name {

// 	case "basic":
// 		resp.Response = "OK"
// 		data, err := json.Marshal(resp)
// 		if err != nil {
// 			panic(err)
// 		}

// 		w.Header().Set(hdrKey, "df3fee813df4036d3744f45e8a474427d1c6b0a868538091dde3d8e89bc0680d")
// 		w.WriteHeader(200)
// 		w.Write(data)

// 	case "nokey":
// 		resp.Response = "OK"
// 		data, err := json.Marshal(resp)
// 		if err != nil {
// 			panic(err)
// 		}

// 		w.WriteHeader(200)
// 		w.Write(data)

// 	case "norot":
// 		resp.Response = "OK"
// 		data, err := json.Marshal(resp)
// 		if err != nil {
// 			panic(err)
// 		}

// 		w.Header().Set(hdrKey, "df3fee813df4036d3744f45e8a474427d1c6b0a868538091dde3d8e89bc0680d")
// 		w.WriteHeader(200)
// 		w.Write(data)

// 	default:
// 		w.WriteHeader(500)

// 	}

// 	return
// }

// func testServer(cfg *Config) {
// 	srv := new(Server)

// 	err := srv.New(cfg)

// 	srv.Mux.HandleFunc("/test", return200)
// 	srv.Mux.HandleFunc("/login", uncondSuccess)
// 	srv.Mux.HandleFunc("/auth", badSessionKey)
// 	srv.Mux.HandleFunc("/test/request", testRequest)
// 	srv.Mux.HandleFunc("/auth/testsig", verifySig)
// 	srv.Mux.HandleFunc("/fail", returnError)
// 	srv.Mux.HandleFunc("/failerror", returnNamedError)

// 	srv.Start()

// 	return
// }

// func TestTransport(t *testing.T) {
// 	cfg := new(Config)

// 	cfg.Runtime.Key = new(crypto.TLSKey)
// 	cfg.Runtime.CACert = new(crypto.TLSCert)
// 	cfg.Runtime.Cert = new(crypto.TLSCert)
// 	cfg.Runtime.CA = new(crypto.CertPool)

// 	err := cfg.Runtime.Key.Generate()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	err = cfg.Runtime.CACert.Generate("ca", true, 1, cfg.Runtime.Key.Public(), cfg.Runtime.Key, nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	err = cfg.Runtime.Cert.Generate("localhost", false, 1, cfg.Runtime.Key.Public(), cfg.Runtime.Key, cfg.Runtime.CACert)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	cfg.Runtime.CA.New(cfg.Runtime.Cert)

// 	cfg.Startup.Address = "localhost:8443"
// 	cfg.Startup.Dir = "/tmp"

// 	testServer(cfg)

// 	// First test that our custom dial+client works correctly

// 	sess := new(Session)

// 	err = sess.New(cfg)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	_, err = sess.Get("http://localhost:8443/test")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	realSig := cfg.Startup.ServerSignature
// 	cfg.Startup.ServerSignature = "00000000"

// 	err = sess.NewClient(cfg)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	_, err = sess.Client.Get("http://localhost:8443/test")
// 	if err == nil {
// 		t.Fatal("No error when server certificate changed")
// 	}

// 	cfg.Startup.ServerSignature = realSig
// 	err = sess.NewClient(cfg)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// The client will write a config file with the server signature.
// 	// Make sure this is cleaned up, and we don't leave junk on peoples
// 	// systems.

// 	defer os.Remove("/tmp/skds.conf")

// 	// Basic new session test

// 	err = sess.AuthClient(cfg)
// 	if err == nil || err.Error() != "Invalid session key in response" {
// 		t.Error("Expected to get: Invalid session key in response, got", err)
// 	}

// 	err = sess.AuthAdmin(cfg)
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	var msg Message

// 	msg.Admin.Name = "basic"
// 	resp, err := sess.Request(cfg, "/test/request", msg)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	if resp.Response != "OK" {
// 		t.Error("Bad response")
// 	}

// 	msg.Admin.Name = "nokey"
// 	_, err = sess.Request(cfg, "/test/request", msg)
// 	if err == nil || err.Error() != "Invalid session key in response" {
// 		t.Error("Expected to get: Invalid session key in response, got", err)
// 	}

// 	msg.Admin.Name = "norot"
// 	_, err = sess.Request(cfg, "/test/request", msg)
// 	if err == nil || err.Error() != "Session key not rotated" {
// 		t.Error("Expected to get: Session key not rotated, got", err)
// 	}

// 	err = sess.auth(cfg, "/auth/testsig")
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	_, err = sess.Request(cfg, "/fail", msg)
// 	if err.Error() != "500 Internal Server Error ()" {
// 		t.Error("Did not get correct error, got:", err)
// 	}

// 	_, err = sess.Request(cfg, "/failerror", msg)
// 	if err.Error() != "500 Internal Server Error (Failed)" {
// 		t.Error("Did not get correct error, got:", err)
// 	}
// }
