package shared

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jinzhu/gorm"
	"io"
	"io/ioutil"
	"strconv"

	"github.com/jfindley/skds/crypto"
)

const (
	SkdsVersion  = "0.1-HEAD"
	DefClientGid = 1
	DefAdminGid  = 2
	SuperGid     = 3
)

var DefaultAdminPass = []byte("password")

// Root config object
type Config struct {
	Runtime Runtime
	Startup Startup
	DB      gorm.DB
	Session Session
	Server  Server
}

// Runtime attributes.
// These should never be written to disk
type Runtime struct {
	Log       io.Writer
	Key       *crypto.TLSKey
	Cert      *crypto.TLSCert
	CAKey     *crypto.TLSKey
	CACert    *crypto.TLSCert
	CA        *crypto.CertPool
	Keypair   *crypto.Key
	ServerSig *Binary
}

// Startup attributes.
// These can be written to the config file safely
type Startup struct {
	Dir      string // Directory where certs etc are stored
	Name     string // Node name
	Address  string
	User     string
	LogFile  string
	LogLevel int
	Version  string
	Crypto   StartupCrypto
	DB       DBSettings
}

type DBSettings struct {
	Host     string
	Port     string
	User     string
	Pass     string
	Database string
	Driver   string
}

type StartupCrypto struct {
	Cert       string
	Key        string
	CACert     string
	CAKey      string
	PublicKey  string
	PrivateKey string
	ServerSig  string
}

func ReadArgs() (cfg Config, install bool, args []string) {
	flag.StringVar(&cfg.Startup.Dir, "c", "/etc/skds/", "Certificate directory.")
	flag.IntVar(&cfg.Startup.LogLevel, "d", 1, "Log level in the range 0 to 4.")
	flag.StringVar(&cfg.Startup.LogFile, "l", "STDOUT", "Logfile.  Use STDOUT for console logging.")
	flag.BoolVar(&install, "setup", false, "Run setup.  Caution: this will cause data loss if run after first install.")
	flag.Parse()
	args = flag.Args()
	return
}

func (s *Startup) Read(file string) (err error) {
	path := fmt.Sprintf("%s/%s", s.Dir, file)
	toml.DecodeFile(path, s)
	return
}

func (s *Startup) Write(file string) (err error) {
	path := fmt.Sprintf("%s/%s", s.Dir, file)
	b := new(bytes.Buffer)
	if err = toml.NewEncoder(b).Encode(s); err != nil {
		return
	}
	if err = ioutil.WriteFile(path, b.Bytes(), 0644); err != nil {
		return
	}
	return
}

// Set options at runtime with an Option method
type Option func(*Config)

func (c *Config) Option(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}

// Allow commandline options to override config
type dynamicOpt func(*flag.Flag)

func SetOverrides(c *Config) dynamicOpt {
	return func(f *flag.Flag) {
		// c.Log(3, f.Name, f.Value.String())
		switch f.Name {
		case "l":
			c.Startup.LogFile = f.Value.String()
			c.Option(LogFile())
		case "d":
			level, err := strconv.Atoi(f.Value.String())
			if err != nil {
				c.Log(1, "Invalid log level specified, ignoring")
			} else {
				c.Option(Verbosity(level))
			}
		}
	}
}

// File handling
// type File func(*Config, string) error

// func (c *Config) ReadFiles(files ...File) (err error) {
// 	for _, f := range files {
// 		err = f(c, "read")
// 		if err != nil {
// 			return
// 		}
// 	}
// 	return
// }

// func (c *Config) WriteFiles(files ...File) (err error) {
// 	for _, f := range files {
// 		err = f(c, "write")
// 		if err != nil {
// 			return
// 		}
// 	}
// 	return
// }

// func (c *Config) path(p string) string {
// 	// If the filename contains '/' treat it as a full path
// 	if strings.Contains(p, "/") {
// 		return p
// 	}
// 	if c.Startup.Dir[len(c.Startup.Dir)-1:] == "/" {
// 		return c.Startup.Dir + p
// 	} else {
// 		return c.Startup.Dir + "/" + p
// 	}
// }

// func CACert() File {
// 	var data []byte
// 	return func(c *Config, a string) (err error) {
// 		switch a {
// 		case "read":
// 			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.CACert))
// 			if err != nil {
// 				return
// 			}
// 			c.Runtime.CACert, err = shared.CertDecode(data)
// 			return
// 		case "write":
// 			data, err = shared.CertEncode(c.Runtime.CACert)
// 			if err != nil {
// 				return
// 			}
// 			err = ioutil.WriteFile(c.path(c.Startup.Crypto.CACert), data, 0644)
// 			return
// 		default:
// 			err = errors.New("Invalid method")
// 			return
// 		}
// 	}
// }

// func Cert() File {
// 	return func(c *Config, a string) (err error) {
// 		var data []byte
// 		switch a {
// 		case "read":
// 			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.Cert))
// 			if err != nil {
// 				return
// 			}
// 			c.Runtime.Cert, err = shared.CertDecode(data)
// 			return
// 		case "write":
// 			data, err = shared.CertEncode(c.Runtime.Cert)
// 			if err != nil {
// 				return
// 			}
// 			err = ioutil.WriteFile(c.path(c.Startup.Crypto.Cert), data, 0644)
// 			return
// 		default:
// 			err = errors.New("Invalid method")
// 			return
// 		}
// 	}
// }

// func CAKey() File {
// 	return func(c *Config, a string) (err error) {
// 		var data []byte
// 		switch a {
// 		case "read":
// 			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.CAKey))
// 			if err != nil {
// 				return
// 			}
// 			c.Runtime.CAKey, err = shared.KeyDecode(data)
// 			return
// 		case "write":
// 			data, err = shared.KeyEncode(c.Runtime.CAKey)
// 			if err != nil {
// 				return
// 			}
// 			err = ioutil.WriteFile(c.path(c.Startup.Crypto.CAKey), data, 0600)
// 			return
// 		default:
// 			err = errors.New("Invalid method")
// 			return
// 		}
// 	}
// }

// func Key() File {
// 	return func(c *Config, a string) (err error) {
// 		var data []byte
// 		switch a {
// 		case "read":
// 			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.Key))
// 			if err != nil {
// 				return
// 			}
// 			c.Runtime.Key, err = shared.KeyDecode(data)
// 			return
// 		case "write":
// 			data, err = shared.KeyEncode(c.Runtime.Key)
// 			if err != nil {
// 				return
// 			}
// 			err = ioutil.WriteFile(c.path(c.Startup.Crypto.Key), data, 0600)
// 			return
// 		default:
// 			err = errors.New("Invalid method")
// 			return
// 		}
// 	}
// }

// func PrivateKey() File {
// 	return func(c *Config, a string) (err error) {
// 		var data []byte
// 		switch a {
// 		case "read":
// 			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.PrivateKey))
// 			if err != nil {
// 				return
// 			}
// 			key := shared.HexDecode(data)
// 			crypto.Zero(data)
// 			c.Runtime.Keypair.SetPriv(key)
// 			return
// 		case "write":
// 			data = shared.HexEncode(c.Runtime.Keypair.Priv[:])
// 			err = ioutil.WriteFile(c.path(c.Startup.Crypto.PrivateKey), data, 0600)
// 			return
// 		default:
// 			err = errors.New("Invalid method")
// 			return
// 		}
// 	}
// }

// func PublicKey() File {
// 	return func(c *Config, a string) (err error) {
// 		var data []byte
// 		switch a {
// 		case "read":
// 			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.PublicKey))
// 			if err != nil {
// 				return
// 			}
// 			key := shared.HexDecode(data)
// 			c.Runtime.Keypair.New(key, nil)
// 			return
// 		case "write":
// 			data = shared.HexEncode(c.Runtime.Keypair.Pub[:])
// 			err = ioutil.WriteFile(c.path(c.Startup.Crypto.PublicKey), data, 0644)
// 			return
// 		default:
// 			err = errors.New("Invalid method")
// 			return
// 		}
// 	}
// }
