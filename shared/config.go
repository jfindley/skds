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
	SkdsVersion = "0.1-HEAD"
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
	Name     string // Node name
	Address  string
	User     string
	LogFile  string
	LogLevel log.LogLevel
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

func (c *Config) StartLogging() error {
	return c.logger.Start(cfg.Startup.LogLevel, cfg.Startup.LogFile)
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

// TODO: we're no longer setting most options this way.
// when logging gets re-written, get rid of this.

// Set options at runtime with an Option method
// type Option func(*Config)

// func (c *Config) Option(opts ...Option) {
// 	for _, opt := range opts {
// 		opt(c)
// 	}
// }

// // Allow commandline options to override config
// type dynamicOpt func(*flag.Flag)

// func SetOverrides(c *Config) dynamicOpt {
// 	return func(f *flag.Flag) {
// 		// c.Log(3, f.Name, f.Value.String())
// 		switch f.Name {
// 		case "l":
// 			c.Startup.LogFile = f.Value.String()
// 			c.Option(LogFile())
// 		case "d":
// 			level, err := strconv.Atoi(f.Value.String())
// 			if err != nil {
// 				c.Log(1, "Invalid log level specified, ignoring")
// 			} else {
// 				c.Option(Verbosity(level))
// 			}
// 		}
// 	}
// }
