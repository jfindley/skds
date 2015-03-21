package main

import (
	"code.google.com/p/gopass"
	"fmt"
	"github.com/codegangsta/cli"
	"os"
	"os/user"

	"github.com/jfindley/skds/log"
	"github.com/jfindley/skds/shared"
)

func cfgFile(cfg *shared.Config, file string) string {
	return fmt.Sprintf("%s%c%s", cfg.Startup.Dir, os.PathSeparator, file)
}

func readFiles(cfg *shared.Config) (install bool, err error) {
	err = shared.Read(cfg, cfgFile(cfg, "admin.conf"))
	if os.IsNotExist(err) {
		cfg.Startup.Crypto.CACert = cfgFile(cfg, "bundle.pem")
		cfg.Startup.Crypto.KeyPair = cfgFile(cfg, "keypair.pem")
		cfg.Startup.Crypto.ServerCert = cfgFile(cfg, "server-signature.pem")
		install = true
	} else if err != nil {
		return
	}

	err = shared.Read(cfg.Runtime.CA, cfg.Startup.Crypto.CACert)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.KeyPair)
		}
	} else if err != nil {
		return
	}

	err = shared.Read(cfg.Runtime.Keypair, cfg.Startup.Crypto.KeyPair)
	if os.IsNotExist(err) {
		if !install {
			return false, fmt.Errorf("Missing file: %s", cfg.Startup.Crypto.KeyPair)
		}
	} else if err != nil {
		return
	}

	return install, nil
}

func startup(cfg *shared.Config, ctx *cli.Context) {
	if ctx.GlobalBool("verbose") {
		cfg.Startup.LogLevel = log.DEBUG
	} else {
		cfg.Startup.LogLevel = log.INFO
	}

	cfg.Startup.Dir = ctx.GlobalString("dir")

	err := cfg.StartLogging()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cfg.Log(log.DEBUG, "Reading keys and configuration from disk")
	install, err := readFiles(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	if install {
		cfg.Log(log.INFO, "Performing first-run install")
		err = setup(cfg, ctx)
		if err != nil {
			cfg.Fatal(err)
		}
	} else {
		if cfg.Startup.Crypto.ServerCert == "" {
			cfg.Log(log.WARN, "Server certificate pinning disabled.  This is strongly discouraged.\n",
				"Please consider configuring a ServerCert location.")
		}

		pass, err := gopass.GetPass("Please enter your password:\n")
		if err != nil {
			cfg.Fatal(err)
		}
		cfg.Runtime.Password = []byte(pass)

		cfg.Session.New(cfg)

		err = cfg.Session.Login(cfg)
		if err != nil {
			cfg.Fatal(err)
		}

		cfg.Log(log.INFO, "Logged in")
	}
	return
}

func main() {
	cfg := new(shared.Config)
	cfg.NewClient()

	cfg.Startup.LogFile = ""

	usr, err := user.Current()
	if err != nil {
		fmt.Println("Error looking up user:", err)
		os.Exit(2)
	}

	main := cli.NewApp()
	main.Name = "SKDS"
	main.Usage = "admin client"
	main.Version = shared.Version

	main.Authors = []cli.Author{
		cli.Author{
			Name:  "James Findley",
			Email: "skds@fastmail.fm",
		},
	}

	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, V",
		Usage: "print the version",
	}

	main.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, v",
			Usage: "Verbose mode",
		},
		cli.StringFlag{
			Name:  "dir, d",
			Usage: "Path to store configuration and secret keys",
			Value: usr.HomeDir + "/.skds",
		},
	}

	main.Before = func(ctx *cli.Context) error {
		startup(cfg, ctx)
		return nil
	}

	main.Action = func(ctx *cli.Context) {
		startCli(cfg, ctx)
	}

	err = main.Run(os.Args)
	if err != nil {
		fmt.Println("Error starting application:", err)
		os.Exit(2)
	}
}
