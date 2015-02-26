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
	Mode    string  // Server|Admin|Client
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
	ServerCert string
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

// TODO: we're no longer setting most options this way.
// when logging gets re-written, get rid of this.

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
