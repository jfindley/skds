package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/shared"
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
}

// Runtime attributes.
// These should never be written to disk
type Runtime struct {
	DB         gorm.DB
	Log        io.Writer
	Key        *ecdsa.PrivateKey
	Cert       *x509.Certificate
	CA         *x509.CertPool
	CAKey      *ecdsa.PrivateKey
	CACert     *x509.Certificate
	Client     *http.Client
	Keypair    crypto.Key
	Password   []byte
	SessionID  int64
	SessionKey []byte
}

// Startup attributes.
// These can be written to the config file safely
type Startup struct {
	Dir             string // Directory where certs etc are stored
	Name            string // Node name
	Address         string
	User            string
	LogFile         string
	LogLevel        int
	Version         string
	ServerSignature string
	Crypto          StartupCrypto
	DB              DB
}

type DB struct {
	Host     string
	Port     string
	User     string
	Pass     string
	Database string
}

type StartupCrypto struct {
	Cert       string
	Key        string
	CACert     string
	CAKey      string
	PublicKey  string
	PrivateKey string
}

var prefixes = map[int]string{
	-1: "",
	0:  "ERROR: ",
	1:  "WARN: ",
	2:  "INFO: ",
	3:  "DEBUG: ",
	4:  "DEBUG: ",
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

func (c *Config) DBConnect() (err error) {
	var uri string
	if c.Startup.DB.Host == "localhost" {
		uri = fmt.Sprintf("%s:%s@/%s", c.Startup.DB.User,
			c.Startup.DB.Pass, c.Startup.DB.Database)
	} else {
		uri = fmt.Sprintf("%s:%s@(%s:%s)/%s", c.Startup.DB.User,
			c.Startup.DB.Pass, c.Startup.DB.Host, c.Startup.DB.Port,
			c.Startup.DB.Database)
	}
	c.Runtime.DB, err = gorm.Open("mysql", uri)
	if err != nil {
		return
	}
	if c.Startup.LogLevel == 4 {
		c.Runtime.DB.SetLogger(log.New(c.Runtime.Log, "(DB QUERY) ", -1))
		c.Runtime.DB.LogMode(true)
	}
	// Test we sucessfully connected and set limits
	err = c.Runtime.DB.DB().Ping()
	c.Runtime.DB.DB().SetMaxIdleConns(10)
	c.Runtime.DB.DB().SetMaxOpenConns(100)
	return
}

func (c *Config) Log(level int, values ...interface{}) {
	if c.Runtime.Log == nil {
		c.Option(LogFile())
	}
	pref, ok := prefixes[level]
	if !ok {
		pref = ""
	}
	if level <= c.Startup.LogLevel {
		_, err := fmt.Fprintln(c.Runtime.Log, pref, values)
		if err != nil {
			fmt.Println("Logging error:", err)
		}
	}
}

// No log level for fatal errors - these are always shown
func (c *Config) Fatal(values ...interface{}) {
	if c.Runtime.Log == nil {
		c.Option(LogFile())
	}
	_, err := fmt.Fprintln(c.Runtime.Log, "FATAL: ", values)
	if err != nil {
		fmt.Println("Logging error:", err)
	}
	os.Exit(1)
}

// Set options at runtime with an Option method
type Option func(*Config)

func (c *Config) Option(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}

func Verbosity(o int) Option {
	return func(c *Config) {
		c.Startup.LogLevel = o
	}
}

func LogFile() Option {
	return func(c *Config) {
		if c.Startup.LogFile != "STDOUT" {
			f, err := os.Open(c.Startup.LogFile)
			if err != nil {
				// Cannot write to log, discard logs instead
				c.Runtime.Log = ioutil.Discard
			} else {
				c.Runtime.Log = f
			}
		} else {
			c.Runtime.Log = os.Stdout
		}
	}
}

func CAPool() Option {
	return func(c *Config) {
		c.Runtime.CA = crypto.CaPool(c.Runtime.CACert)
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
type File func(*Config, string) error

func (c *Config) ReadFiles(files ...File) (err error) {
	for _, f := range files {
		err = f(c, "read")
		if err != nil {
			return
		}
	}
	return
}

func (c *Config) WriteFiles(files ...File) (err error) {
	for _, f := range files {
		err = f(c, "write")
		if err != nil {
			return
		}
	}
	return
}

func (c *Config) path(p string) string {
	// If the filename contains '/' treat it as a full path
	if strings.Contains(p, "/") {
		return p
	}
	if c.Startup.Dir[len(c.Startup.Dir)-1:] == "/" {
		return c.Startup.Dir + p
	} else {
		return c.Startup.Dir + "/" + p
	}
}

func CACert() File {
	var data []byte
	return func(c *Config, a string) (err error) {
		switch a {
		case "read":
			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.CACert))
			if err != nil {
				return
			}
			c.Runtime.CACert, err = shared.CertDecode(data)
			return
		case "write":
			data, err = shared.CertEncode(c.Runtime.CACert)
			if err != nil {
				return
			}
			err = ioutil.WriteFile(c.path(c.Startup.Crypto.CACert), data, 0644)
			return
		default:
			err = errors.New("Invalid method")
			return
		}
	}
}

func Cert() File {
	return func(c *Config, a string) (err error) {
		var data []byte
		switch a {
		case "read":
			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.Cert))
			if err != nil {
				return
			}
			c.Runtime.Cert, err = shared.CertDecode(data)
			return
		case "write":
			data, err = shared.CertEncode(c.Runtime.Cert)
			if err != nil {
				return
			}
			err = ioutil.WriteFile(c.path(c.Startup.Crypto.Cert), data, 0644)
			return
		default:
			err = errors.New("Invalid method")
			return
		}
	}
}

func CAKey() File {
	return func(c *Config, a string) (err error) {
		var data []byte
		switch a {
		case "read":
			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.CAKey))
			if err != nil {
				return
			}
			c.Runtime.CAKey, err = shared.KeyDecode(data)
			return
		case "write":
			data, err = shared.KeyEncode(c.Runtime.CAKey)
			if err != nil {
				return
			}
			err = ioutil.WriteFile(c.path(c.Startup.Crypto.CAKey), data, 0600)
			return
		default:
			err = errors.New("Invalid method")
			return
		}
	}
}

func Key() File {
	return func(c *Config, a string) (err error) {
		var data []byte
		switch a {
		case "read":
			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.Key))
			if err != nil {
				return
			}
			c.Runtime.Key, err = shared.KeyDecode(data)
			return
		case "write":
			data, err = shared.KeyEncode(c.Runtime.Key)
			if err != nil {
				return
			}
			err = ioutil.WriteFile(c.path(c.Startup.Crypto.Key), data, 0600)
			return
		default:
			err = errors.New("Invalid method")
			return
		}
	}
}

func PrivateKey() File {
	return func(c *Config, a string) (err error) {
		var data []byte
		switch a {
		case "read":
			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.PrivateKey))
			if err != nil {
				return
			}
			key := shared.HexDecode(data)
			crypto.Zero(data)
			c.Runtime.Keypair.SetPriv(key)
			return
		case "write":
			data = shared.HexEncode(c.Runtime.Keypair.Priv[:])
			err = ioutil.WriteFile(c.path(c.Startup.Crypto.PrivateKey), data, 0600)
			return
		default:
			err = errors.New("Invalid method")
			return
		}
	}
}

func PublicKey() File {
	return func(c *Config, a string) (err error) {
		var data []byte
		switch a {
		case "read":
			data, err = ioutil.ReadFile(c.path(c.Startup.Crypto.PublicKey))
			if err != nil {
				return
			}
			key := shared.HexDecode(data)
			c.Runtime.Keypair.New(key, nil)
			return
		case "write":
			data = shared.HexEncode(c.Runtime.Keypair.Pub[:])
			err = ioutil.WriteFile(c.path(c.Startup.Crypto.PublicKey), data, 0644)
			return
		default:
			err = errors.New("Invalid method")
			return
		}
	}
}
