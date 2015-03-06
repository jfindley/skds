package shared

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/jfindley/skds/crypto"
)

var maxLen = 200

// Header names
const (
	hdrEnc     = "Content-Encoding"
	hdrUA      = "User-Agent"
	HdrSession = "Session-ID"
	HdrMAC     = "X-AUTH-MAC"
	HdrKey     = "X-AUTH-KEY"
)

type Session struct {
	Password   []byte
	ServerCert []byte

	sessionID  int64
	sessionKey crypto.Binary
	client     *http.Client
	tls        *tls.Config
	serverPath string
}

func (s *Session) New(cfg *Config) error {
	tr := new(http.Transport)
	tr.TLSHandshakeTimeout = tlsTimeout
	tr.ResponseHeaderTimeout = respTimeout

	tr.Dial = func(network, addr string) (net.Conn, error) {
		return customDialer(network, addr, cfg)
	}

	s.client = &http.Client{Transport: tr}
	// We use the http scheme as we handle the TLS seperately.
	s.serverPath = "http://" + cfg.Startup.Address

	return nil
}

func (s *Session) Get(url string) (resp []Message, err error) {
	request, err := http.NewRequest("GET", s.fmtURL(url), nil)
	if err != nil {
		return
	}

	s.setHeaders(request, nil)

	r, err := s.client.Do(request)
	if err != nil {
		return
	}

	if r.StatusCode != 200 {
		return resp, fmt.Errorf("%s %d %s\n", "Recieved", r.StatusCode, "response from server")
	}

	err = s.nextKey(r)
	if err != nil {
		return
	}

	return ReadResp(r.Body)
}

func (s *Session) Post(url string, msg Message) (resp []Message, err error) {

	data, err := json.Marshal(&msg)
	if err != nil {
		return
	}

	request, err := http.NewRequest("POST", s.fmtURL(url), bytes.NewReader(data))
	if err != nil {
		return
	}

	s.setHeaders(request, data)

	r, err := s.client.Do(request)
	if err != nil {
		return
	}

	if r.StatusCode != 200 {
		return resp, fmt.Errorf("%s %d %s\n", "Recieved", r.StatusCode, "response from server")
	}

	err = s.nextKey(r)
	if err != nil {
		return
	}

	return ReadResp(r.Body)
}

func (s *Session) Login(cfg *Config) (err error) {
	msg := new(Message)
	msg.Auth.Name = "test login"
	msg.Auth.Password = []byte("test password")

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	request, err := http.NewRequest("POST", s.fmtURL("/login"), bytes.NewReader(data))
	if err != nil {
		return
	}

	s.setHeaders(request, data)

	r, err := s.client.Do(request)
	if err != nil {
		return
	}

	if r.StatusCode != 200 {
		return fmt.Errorf("%s %d %s\n", "Recieved", r.StatusCode, "response from server")
	}
	s.sessionID, err = strconv.ParseInt(r.Header.Get(HdrSession), 10, 64)
	if err != nil {
		return
	}
	if s.sessionID == 0 {
		return errors.New("No session ID in response")
	}
	s.sessionKey.Decode([]byte(r.Header.Get(HdrKey)))
	if s.sessionKey == nil {
		return errors.New("No session key in response")
	}
	return
}

func (s *Session) setHeaders(request *http.Request, data []byte) {
	request.Header.Add(hdrUA, "SKDS version "+SkdsVersion)
	if data != nil {
		request.Header.Add(hdrEnc, "application/json")
		request.ContentLength = int64(len(data))
	}

	if s.sessionKey != nil {
		request.Header.Add(HdrSession, strconv.FormatInt(s.sessionID, 10))
		request.Header.Add(HdrMAC, crypto.NewMAC(s.sessionKey, request.URL.Path, data))
	}
	return
}

func (s *Session) nextKey(r *http.Response) (err error) {
	if s.sessionID == 0 {
		return
	}

	var newKey crypto.Binary
	err = newKey.DecodeString(r.Header.Get(HdrKey))
	if err != nil {
		return
	}

	if len(newKey) == 0 {
		return errors.New("Invalid session key in response")
	}
	if bytes.Compare(newKey, s.sessionKey) == 0 {
		return errors.New("Session key not rotated")
	}
	s.sessionKey = newKey
	return
}

func (s *Session) fmtURL(u string) string {
	return s.serverPath + u
}

// ReadResp parses a message array from an io.Reader.
func ReadResp(r io.Reader) (resp []Message, err error) {
	if r == nil {
		return
	}
	dec := json.NewDecoder(r)
	for {
		var m Message
		if err = dec.Decode(&m); err == io.EOF {
			return resp, nil
		} else if err != nil {
			return
		}
		resp = append(resp, m)
	}
}
