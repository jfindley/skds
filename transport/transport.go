package transport

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/shared"
)

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

func ServerInit(cfg *config.Config) (*net.Listener, *http.Server, *http.ServeMux, error) {
	tlsCfg := generate(cfg)
	tlsSocket, err := tls.Listen("tcp", cfg.Startup.Address, tlsCfg)
	if err != nil {
		return nil, nil, nil, err
	}
	mux := http.NewServeMux()
	srv := http.Server{
		Addr:    cfg.Startup.Address,
		Handler: mux,
	}
	return &tlsSocket, &srv, mux, nil
}

func ClientInit(cfg *config.Config) (*http.Client, error) {
	tr := &http.Transport{
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: respTimeout,
	}

	tr.Dial = func(network, addr string) (net.Conn, error) {
		return customDialer(network, addr, cfg)
	}

	return &http.Client{Transport: tr}, nil
}

func generate(cfg *config.Config) *tls.Config {
	tlsCert := make([]tls.Certificate, 1)
	if cfg.Runtime.Cert != nil {
		tlsCert[0].Certificate = append(tlsCert[0].Certificate, cfg.Runtime.Cert.Raw)
		tlsCert[0].PrivateKey = cfg.Runtime.Key
	}

	config := tls.Config{
		Certificates:           tlsCert,
		Rand:                   nil, // Use crypto/rand
		CipherSuites:           ciphers,
		SessionTicketsDisabled: false,
		ClientAuth:             tls.NoClientCert,
	}

	if cfg.Runtime.CA == nil {
		config.InsecureSkipVerify = true
	} else {
		config.InsecureSkipVerify = false
		config.RootCAs = cfg.Runtime.CA
	}
	return &config
}

func customDialer(network, addr string, cfg *config.Config) (conn net.Conn, err error) {
	tlsCfg := generate(cfg)

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
	serverSig := string(shared.HexEncode(connState.PeerCertificates[0].Signature))
	if cfg.Startup.ServerSignature == "" {
		cfg.Startup.ServerSignature = serverSig
		err = cfg.Startup.Write("skds.conf")
		if err != nil {
			return
		}
	} else {
		if serverSig != cfg.Startup.ServerSignature {
			err = errors.New("Server certificate changed unexpectedly")
			return
		}
	}

	return
}
