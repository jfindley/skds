package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/server/auth"
	"github.com/jfindley/skds/server/db"
	"github.com/jfindley/skds/shared"
)

var cfgFile string

func init() {
	flag.StringVar(&cfgFile, "f", "/etc/skds/skds.conf", "Config file location.")
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

	return install, nil
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Parse()

	cfg := new(shared.Config)
	cfg.New()

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

	cfg.Log(log.DEBUG, "Connecting to DB")
	cfg.DB, err = db.Connect(cfg.Startup.DB)
	if err != nil {
		cfg.Fatal(err)
	}

	cfg.Log(log.DEBUG, "Reading keys and certificates from disk")
	install, err := readFiles(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	if install {
		cfg.Log(log.INFO, "Performing first-run install")
		err = setup(cfg)
		if err != nil {
			cfg.Fatal(err)
		}
	}

	pool := new(auth.SessionPool)
	server := new(shared.Server)

	go pool.Pruner()

	err = server.New(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	sigs := make(chan os.Signal, 1)

	go func() {
		<-sigs
		cfg.Log(log.INFO, "Server shutting down")
		server.Stop()
	}()

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

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

	cfg.Log(log.INFO, "SKDS Server version", shared.Version, "started")

	server.Start()

	server.Wait()
}
