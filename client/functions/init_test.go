package functions

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"

	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

var cfg *shared.Config

func init() {
	cfg = new(shared.Config)

	cfg.Startup.LogLevel = log.WARN
	cfg.Startup.LogFile = ""
	cfg.StartLogging()
}

func testPost(expected shared.Message, code int, responses ...shared.Message) (ts *httptest.Server) {
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		req, err := shared.ReadResp(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
		}

		if reflect.DeepEqual(req[0], expected) {
			var body []byte

			for _, msg := range responses {
				data, err := json.Marshal(msg)
				if err != nil {
					http.Error(w, "Error sending response", http.StatusInternalServerError)
					return
				}
				body = append(body, data...)
			}

			w.WriteHeader(code)
			w.Write(body)
		}
	}))
	return
}

func testGet(code int, responses ...shared.Message) (ts *httptest.Server) {
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var body []byte

		for _, msg := range responses {
			data, err := json.Marshal(msg)
			if err != nil {
				http.Error(w, "Error sending response", http.StatusInternalServerError)
				return
			}
			body = append(body, data...)
		}

		w.WriteHeader(code)
		w.Write(body)

	}))
	return
}
