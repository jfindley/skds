package main

import (
    "errors"
    "flag"
    "net/http"
    "runtime"

    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/dictionary"
    "github.com/jfindley/skds/server/auth"
    "github.com/jfindley/skds/transport"
)

func ReadArgs() (cfg config.Config, install bool) {
    flag.StringVar(&cfg.Startup.Dir, "c", "/etc/skds/", "Certificate directory.")
    flag.IntVar(&cfg.Startup.LogLevel, "d", 1, "Log level in the range 0 to 3.")
    flag.StringVar(&cfg.Startup.LogFile, "l", "STDOUT", "Logfile.  Use STDOUT for console logging.")
    flag.BoolVar(&install, "setup", false, "Run setup.  Caution: this will cause data loss if run after first install.")
    flag.Parse()
    return
}

func loadConfig(cfg *config.Config) (err error) {

    // Ignore extra arguments
    initCfg, install := ReadArgs()
    *cfg = initCfg

    if install {
        err = Setup(cfg)
    } else {
        err = cfg.Startup.Read("server.conf")
        if err != nil {
            return errors.New("Cannot parse config file")
        }
        flag.Visit(config.SetOverrides(cfg))
        // We connect to the DB early, so we can init the tables if needed
        err = cfg.DBConnect()
    }
    return
}

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    cfg := new(config.Config)
    err := loadConfig(cfg)
    if err != nil {
        cfg.Fatal(err)
    }

    err = cfg.ReadFiles(config.CACert(), config.CAKey(), config.Cert(), config.Key())
    cfg.Option(config.CAPool())
    if err != nil {
        cfg.Fatal(err)
    }

    urls := dictionary.Dictionary.URLDict()
    pool := new(auth.SessionPool)

    go pool.Pruner()

    tlsSocket, server, mux, err := transport.ServerInit(cfg)
    if err != nil {
        cfg.Fatal(err)
    }

    // Authentication
    mux.HandleFunc("/auth/admin", func(w http.ResponseWriter, r *http.Request) {
        authRequest(cfg, pool, w, r, auth.Admin)
    })
    mux.HandleFunc("/auth/client", func(w http.ResponseWriter, r *http.Request) {
        authRequest(cfg, pool, w, r, auth.Client)
    })

    for url, fn := range urls {
        // Copy references so they are not overwritten
        f := fn
        mux.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
            apiRequest(cfg, pool, f, w, r)
        })
    }

    cfg.Log(2, "SKDS Server version", config.SkdsVersion, "started")

    server.Serve(*tlsSocket)

}
