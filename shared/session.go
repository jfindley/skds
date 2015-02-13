package shared

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
)

type Session interface {
	New(*Config) (bool, LogItem)
	Auth() (bool, LogItem)
	Get(url string) (bool, LogItem)
	Put(url string, msg interface{}) (bool, LogItem)
}

type Server interface {
	New(*Config) (bool, LogItem)
	RegisterURL(handler string, function func(http.ResponseWriter, *http.Request))
	Serve() error
}

type ClientSession struct {
	Password []byte
	AuthURL  string

	sessionID  int64
	sessionKey []byte
	client     *http.Client
	tls        *tls.Config
	serverSig  []byte
}

type ServerSession struct {
	Pool SessionPool
	Mux  *http.ServeMux

	tls    *tls.Config
	socket *net.Listener
	server *http.Server
}
