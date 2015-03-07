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
	Hostname string // Hostname
	Address  string
	User     string
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
}

type StartupCrypto struct {
	Cert       string
	Key        string
	CACert     string
	CAKey      string
	PublicKey  string
	PrivateKey string
	ServerCert string
}

func (c *Config) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := toml.NewEncoder(buf).Encode(&c.Startup)
	return buf.Bytes(), err
}

func (c *Config) Decode(data []byte) error {
	_, err := toml.Decode(string(data), &c.Startup)
	return err
}

func (c *Config) New() {
	c.Runtime.Key = new(crypto.TLSKey)
	c.Runtime.CAKey = new(crypto.TLSKey)

	c.Runtime.Cert = new(crypto.TLSCert)
	c.Runtime.CACert = new(crypto.TLSCert)
	c.Runtime.CA = new(crypto.CertPool)

	c.Runtime.Keypair = new(crypto.Key)
}

func (c *Config) StartLogging() error {
	return c.logger.Start(c.Startup.LogLevel, c.Startup.LogFile)
}

func (c *Config) StopLogging() error {
	return c.logger.Stop()
}

func (c *Config) Log(level log.LogLevel, values ...interface{}) {
	c.logger.Log(level, values...)
}

func (c *Config) Fatal(values ...interface{}) {
	c.logger.Fatal(values...)
}
