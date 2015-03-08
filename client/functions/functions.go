package functions

import (
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func GetCA(cfg *shared.Config, url string) (ok bool) {
	resp, err := cfg.Session.Get(url)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}
	if len(resp) != 1 {
		cfg.Log(log.ERROR, "Bad response from server")
		return
	}

	cfg.NewClient()

	err = cfg.Runtime.CA.Decode(resp[0].X509.Cert)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	err = shared.Write(cfg.Runtime.CA, cfg.Startup.Crypto.CACert)
	if err != nil {
		cfg.Log(log.ERROR, err)
		return
	}

	return true
}

func Register(cfg *shared.Config, url string) (ok bool) {
	return
}

func GetSecrets(cfg *shared.Config, url string) (ok bool) {
	return
}
