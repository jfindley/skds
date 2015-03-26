package shared

import (
	"bytes"
	"github.com/BurntSushi/toml"
	"github.com/jinzhu/gorm"
	"io"

	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/log"
)

const (
	// Software versin
	Version = "0.1-HEAD"
	// DefClientGID is the default client group ID
	DefClientGID = 1
	// DefAdminGID is the default admin group ID
	DefAdminGID = 2
	// SuperGID is the super group ID
	SuperGID = 3
)

var DefaultAdminPass = []byte("password")

// Root config object
type Config struct {
	Runtime Runtime // These are only used at runtime, and never saved to disk
	Startup Startup // These are stored in the config file
	DB      gorm.DB // DB interface (only used in server mode)
	Session Session // Admin/Client transport data
	logger  log.Logger
}

// Runtime attributes.
// These should never be written to disk
type Runtime struct {
	Log        io.Writer
	Key        *crypto.TLSKey
	Cert       *crypto.TLSCert
	CAKey      *crypto.TLSKey
	CACert     *crypto.TLSCert
	CA         *crypto.CertPool
	Keypair    *crypto.Key
	ServerCert crypto.Binary
	Password   crypto.Binary
}

// Startup attributes.
// These can be written to the config file safely
type Startup struct {
	Dir      string // Directory where certs etc are stored
	NodeName string // Should be set to hostname for servers.
	Address  string
	LogFile  string
	LogLevel log.LogLevel
	Crypto   StartupCrypto `toml:"files"`
	DB       DBSettings    `toml:"database"`
}

type DBSettings struct {
	Host     string
	Port     string
	User     string
	Pass     string `toml:"Password"`
	Database string
	Driver   string
	File     string
}

type StartupCrypto struct {
	Cert       string
	Key        string
	CACert     string
	CAKey      string
	KeyPair    string
	ServerCert string
	Password   string // Client only.
}

// Encode encodes the Startup part of a config tree in TOML format.
func (c *Config) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := toml.NewEncoder(buf).Encode(&c.Startup)
	return buf.Bytes(), err
}

// Decode reads TOML data into the startup part of a config tree.
func (c *Config) Decode(data []byte) error {
	_, err := toml.Decode(string(data), &c.Startup)

	// Hande relative paths
	c.Startup.Crypto.Cert = c.setPath(c.Startup.Crypto.Cert)
	c.Startup.Crypto.Key = c.setPath(c.Startup.Crypto.Key)
	c.Startup.Crypto.CACert = c.setPath(c.Startup.Crypto.CACert)
	c.Startup.Crypto.CAKey = c.setPath(c.Startup.Crypto.CAKey)
	c.Startup.Crypto.KeyPair = c.setPath(c.Startup.Crypto.KeyPair)
	c.Startup.Crypto.ServerCert = c.setPath(c.Startup.Crypto.ServerCert)
	c.Startup.Crypto.Password = c.setPath(c.Startup.Crypto.Password)
	c.Startup.DB.File = c.setPath(c.Startup.DB.File)

	return err
}

// setPath currently just prepends Config.Startup.Dir to path if path
// is not absolute.
func (c *Config) setPath(path string) string {
	if len(path) > 0 && path[0] != '/' {
		return c.Startup.Dir + "/" + path
	}
	return path
}

// NewServer allocates all objects used by the server
func (c *Config) NewServer() {
	c.Runtime.Key = new(crypto.TLSKey)
	c.Runtime.CAKey = new(crypto.TLSKey)

	c.Runtime.Cert = new(crypto.TLSCert)
	c.Runtime.CACert = new(crypto.TLSCert)
	c.Runtime.CA = new(crypto.CertPool)
}

// NewClient allocations all objects used by the client.
func (c *Config) NewClient() {
	c.Runtime.CA = new(crypto.CertPool)
	c.Runtime.Keypair = new(crypto.Key)
}

// We wrap the log functions here to provide a short calling method.

// StartLogging is a wrapper around log.Start()
func (c *Config) StartLogging() error {
	return c.logger.Start(c.Startup.LogLevel, c.Startup.LogFile)
}

// StopLogging is a wrapper around log.Stop()
func (c *Config) StopLogging() error {
	return c.logger.Stop()
}

// Log is a wrapper around log.Log()
func (c *Config) Log(level log.LogLevel, values ...interface{}) {
	c.logger.Log(level, values...)
}

// Fatal is a wrapper around log.Fatal()
func (c *Config) Fatal(values ...interface{}) {
	c.logger.Fatal(values...)
}
