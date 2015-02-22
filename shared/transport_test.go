package shared

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCustomDialer(t *testing.T) {
	cfg.Init()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	cfg.Startup.Address = strings.TrimPrefix(ts.URL, "https://")
	cfg.Runtime.ServerCert = ts.TLS.Certificates[0].Certificate[0]

	s := new(Session)
	err = s.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := s.client.Get(strings.Replace(ts.URL, "https", "http", 1))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Wrong status code:", resp.StatusCode)
	}
}
