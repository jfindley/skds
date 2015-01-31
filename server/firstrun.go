package main

import (
    "os"

    "github.com/jfindley/skds/config"
    "github.com/jfindley/skds/crypto"
    "github.com/jfindley/skds/server/db"
)

func Setup(cfg *config.Config) (err error) {
    // TODO: we should ship a default config file instead
    loadDefaults(cfg)

    _, err = os.Stat(cfg.Startup.Dir)
    if os.IsNotExist(err) {
        err = os.Mkdir(cfg.Startup.Dir, 0700)
        if err != nil {
            return
        }
    }

    cfg.Option(config.LogFile())

    // Make sure we can connect with the details given, otherwise abort
    err = cfg.DBConnect()
    if err != nil {
        cfg.Log(0, "Could not connect to DB:", err)
        return
    }
    // Write the config file to disk
    cfg.Startup.Write("server.conf")
    // Generate the CA and write it to disk
    // We use doubt the usual key length for the CA key
    cfg.Log(3, "Generating a new CA and server cert")
    cfg.Runtime.CAKey, err = crypto.GenKey(cfg.Startup.Crypto.KeyLen * 2)
    if err != nil {
        cfg.Log(0, "Error generating CA key:", err)
        return
    }
    cfg.Runtime.CACert, err = crypto.GenCert(
        cfg.Startup.Name+" CA",
        true,
        true,
        10,
        &cfg.Runtime.CAKey.PublicKey,
        cfg.Runtime.CAKey,
        nil,
    )
    if err != nil {
        cfg.Log(0, "Error generating CA cert:", err)
        return
    }
    // Now generate the server certificate from the CA
    cfg.Runtime.Key, err = crypto.GenKey(cfg.Startup.Crypto.KeyLen)
    if err != nil {
        cfg.Log(0, "Error generating server key:", err)
        return
    }
    // TODO: Implement shorter length, rotating certs
    cfg.Runtime.Cert, err = crypto.GenCert(
        cfg.Startup.Name,
        false,
        false,
        10,
        &cfg.Runtime.Key.PublicKey,
        cfg.Runtime.CAKey,
        cfg.Runtime.CACert,
    )
    if err != nil {
        cfg.Log(0, "Error generating server cert:", err)
        return
    }
    err = cfg.WriteFiles(config.CACert(), config.CAKey(), config.Cert(), config.Key())
    if err != nil {
        return
    }
    cfg.Log(3, "Creating DB")
    err = db.InitDB(cfg)
    if err != nil {
        return
    }
    err = db.CreateDefaults(cfg)
    if err != nil {
        return
    }
    return
}

func loadDefaults(cfg *config.Config) {
    // cfg.Dir = "/etc/skds"
    cfg.Startup.Name = "server.skds.com"
    cfg.Startup.Address = "0.0.0.0:8443"
    // cfg.Startup.LogFile = "STDOUT"
    // cfg.Startup.LogLevel = 1
    cfg.Startup.Crypto.CACert = "ca.crt"
    cfg.Startup.Crypto.CAKey = "ca.key"
    cfg.Startup.Crypto.Cert = "server.crt"
    cfg.Startup.Crypto.Key = "server.key"
    cfg.Startup.Crypto.KeyLen = 2048
    cfg.Startup.DB.Host = "localhost"
    cfg.Startup.DB.User = "root"
    cfg.Startup.DB.Pass = ""
    cfg.Startup.DB.Database = "skds"
}
