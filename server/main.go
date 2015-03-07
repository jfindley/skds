package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

var cfgFile string

func init() {
	flag.StringVar(&cfgFile, "/etc/skds/skds.conf", "-f", "Config file location")
}

func readFiles(cfg *shared.Config) (install bool, err error) {

	err = shared.Read(cfg.Runtime.CACert, cfg.Startup.Crypto.CACert)
	if os.IsNotExist(err) {
		install = true
	} else if err != nil {
		return
	}

	err = shared.Read(cfg.Runtime.CAKey, cfg.Startup.Crypto.CAKey)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.CAKey)
		}
	} else if err != nil {
		return
	} else if install {
		return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.CACert)
	}

	err = shared.Read(cfg.Runtime.Cert, cfg.Startup.Crypto.Cert)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.Cert)
		}
	} else if err != nil {
		return
	}

	err = shared.Read(cfg.Runtime.Key, cfg.Startup.Crypto.Key)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.Key)
		}
	} else if err != nil {
		return
	}

	return
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()

	cfg := new(shared.Config)

	err := shared.Read(cfg, cfgFile)
	if err != nil {
		fmt.Println("Cannot read config file:", err)
		os.Exit(2)
	}

	err = cfg.StartLogging()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg.DB, err = db.Connect(cfg.Startup.DB)
	if err != nil {
		cfg.Fatal(err)
	}

	install, err := readFiles(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	if install {
		err = setup(cfg)
		if err != nil {
			cfg.Fatal(err)
		}
	}

	pool := new(auth.SessionPool)
	server := new(shared.Server)

	go pool.Pruner()

	server.New(cfg)

	server.Mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		authentication(cfg, pool, w, r)
	})

	for url, fn := range dictionary.Dictionary {
		// Copy references so they are not overwritten
		f := fn
		server.Mux.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
			api(cfg, pool, f, w, r)
		})
	}

	cfg.Log(log.INFO, "SKDS Server version", shared.SkdsVersion, "started")

	server.Start()

}
