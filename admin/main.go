package main

import (
	"bufio"
	"bytes"
	"code.google.com/p/gopass"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/dictionary"
	"github.com/jfindley/skds/messages"
	"github.com/jfindley/skds/transport"
)

func ReadArgs() (cfg config.Config, install bool, args []string) {
	usr, err := user.Current()
	if err != nil {
		// What?
		panic(err)
	}
	dir := fmt.Sprintf("%s/%s", usr.HomeDir, ".skds")
	flag.StringVar(&cfg.Startup.Dir, "c", dir, "Key directory.")
	flag.IntVar(&cfg.Startup.LogLevel, "d", 1, "Log level in the range 0 to 3.")
	flag.StringVar(&cfg.Startup.LogFile, "l", "STDOUT", "Logfile.  Use STDOUT for console logging.")
	flag.BoolVar(&install, "setup", false, "Run setup.  Caution: this will regenerate master encryption keys, making you unable to read ALL previously encrypted data.")
	flag.Parse()
	args = flag.Args()
	return
}

func loadConfig(cfg *config.Config) (input []string, err error) {

	initCfg, install, input := ReadArgs()
	*cfg = initCfg

	if install {
		err = Setup(cfg)
		if err != nil {
			return
		}
		cfg.Log(2, "Setup complete")
		os.Exit(0)
	} else {
		err = cfg.Startup.Read("admin.conf")
		if err != nil {
			err = errors.New("Cannot parse config file")
			return
		}
		flag.Visit(config.SetOverrides(cfg))
		// Don't load the private key until we actually need it
		err = cfg.ReadFiles(config.CACert(), config.PublicKey())
		if err != nil {
			return
		}
		cfg.Runtime.Client, err = transport.ClientInit(cfg)

	}
	return
}

func main() {
	cfg := new(config.Config)
	input, err := loadConfig(cfg)
	if err != nil {
		cfg.Fatal(err)
	}

	pass, err := gopass.GetPass("Enter password: ")
	if err != nil {
		return
	}
	cfg.Runtime.Password = []byte(pass)
	var msg messages.Message
	msg.Admin.Password = cfg.Runtime.Password
	msg.Admin.Name = cfg.Startup.User

	cfg.Runtime.Session = new(transport.Session)

	err = cfg.Runtime.Session.NewClient(cfg)
	if err != nil {
		cfg.Log(0, err)
		os.Exit(1)
	}
	cfg.Log(-1, "Connected")

	err = cfg.Runtime.Session.AuthAdmin(cfg)

	if bytes.Compare(config.DefaultAdminPass, cfg.Runtime.Password) == 0 {
		cfg.Log(1, "Default password set - please change this right away!")
	}

	if len(input) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			in := scanner.Text()
			if in == "quit" || in == "exit" {
				os.Exit(0)
			}
			args := strings.Fields(in)
			err = dictionary.Dictionary.FindFunc(cfg, args)
			if err != nil {
				cfg.Log(1, err)
			}
		}
		if err != nil {
			cfg.Log(0, err)
		}
	} else {
		err = dictionary.Dictionary.FindFunc(cfg, input)
		if err != nil {
			cfg.Fatal(err)
		}
	}
}
