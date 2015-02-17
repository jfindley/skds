package shared

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jfindley/skds/crypto"
)

// As we only need to interoperate with ourself, there's no reason to
// support anything other than a single cipher.

var ciphers = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

// Timeout values in seconds.  We generally favour commands completing
// over commands timing out, so these are generally pretty long.  This
// particularly applies to the response timeout - if we've triggered a
// very large operation, it may be some time before we get a response.

var (
	tcpTimeout  time.Duration = 5 * time.Second
	tlsTimeout  time.Duration = 20 * time.Second
	respTimeout time.Duration = 300 * time.Second
)

type Session struct {
	Password  []byte
	ServerSig []byte

	sessionID  int64
	sessionKey []byte
	client     *http.Client
	tls        *tls.Config
}

type Server struct {
	Pool *SessionPool
	Mux  *http.ServeMux

	tls    *tls.Config
	server *http.Server
	socket net.Listener
}

func (s *Server) New(cfg *Config) (err error) {
	s = new(Server)
	s.Mux = http.NewServeMux()
	s.Pool = new(SessionPool)
	s.server = new(http.Server)

	s.tls = generateTLS(cfg)
	s.socket, err = tls.Listen("tcp", cfg.Startup.Address, s.tls)
	if err != nil {
		return
	}

	s.server = new(http.Server)
	s.server.Addr = cfg.Startup.Address
	s.server.Handler = s.Mux
	return
}

func (s *Server) Start() {
	go func() {
		err := s.server.Serve(s.socket)
		if err != nil {
			panic(err)
		}
	}()
	return
}

func (s *Session) New(cfg *Config) error {
	tr := new(http.Transport)
	tr.TLSHandshakeTimeout = tlsTimeout
	tr.ResponseHeaderTimeout = respTimeout

	tr.Dial = func(network, addr string) (net.Conn, error) {
		return customDialer(network, addr, cfg)
	}

	s.client = &http.Client{Transport: tr}

	return nil
}

func generateTLS(cfg *Config) *tls.Config {

	config := tls.Config{
		Rand:                   nil, // Use crypto/rand
		CipherSuites:           ciphers,
		SessionTicketsDisabled: false,
		ClientAuth:             tls.NoClientCert,
	}

	if cfg.Runtime.Cert != nil && cfg.Runtime.Key != nil {
		config.Certificates = crypto.TLSCertKeyPair(cfg.Runtime.Cert, cfg.Runtime.Key)
	}

	if cfg.Runtime.CA == nil {
		config.InsecureSkipVerify = true
	} else {
		config.InsecureSkipVerify = false
		config.RootCAs = cfg.Runtime.CA.CA
	}
	return &config
}

func customDialer(network, addr string, cfg *Config) (conn net.Conn, err error) {
	tlsCfg := generateTLS(cfg)

	serverName, _, err := net.SplitHostPort(cfg.Startup.Address)
	if err != nil {
		return
	}

	if !tlsCfg.InsecureSkipVerify {
		tlsCfg.ServerName = serverName
	}

	conn, err = net.DialTimeout(network, addr, tcpTimeout)
	if err != nil {
		return
	}
	conn = tls.Client(conn, tlsCfg)

	err = conn.(*tls.Conn).Handshake()
	if err != nil {
		return
	}

	if !tlsCfg.InsecureSkipVerify {
		err = conn.(*tls.Conn).VerifyHostname(serverName)
		if err != nil {
			return
		}
	}

	connState := conn.(*tls.Conn).ConnectionState()
	if len(connState.PeerCertificates) == 0 {
		err = errors.New("No server certificates available")
		return
	}

	err = checkSig(cfg, connState.PeerCertificates[0].Raw)

	return
}

func checkSig(cfg *Config, sig []byte) (err error) {
	if cfg.Runtime.ServerSig == nil {
		cfg.Runtime.ServerSig = new(Binary)

		if _, err = os.Stat(cfg.Startup.Crypto.ServerSig); os.IsNotExist(err) {

			cfg.Runtime.ServerSig.New(sig)

			err = Write(cfg.Runtime.ServerSig, cfg.Startup.Crypto.ServerSig)
			return
		} else {

			err = Read(cfg.Runtime.ServerSig, cfg.Startup.Crypto.ServerSig)
			if err != nil {
				return
			}

		}
	}

	if !cfg.Runtime.ServerSig.Compare(sig) {
		return errors.New("Server signature does not match")
	}
	return nil
}
