package transport

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/jfindley/skds/config"
	"github.com/jfindley/skds/crypto"
	"github.com/jfindley/skds/messages"
	"github.com/jfindley/skds/shared"
)

var maxLen = 200

// Header names
const (
	hdrEnc     = "Content-Encoding"
	hdrUA      = "User-Agent"
	hdrSession = "Session-ID"
	hdrMAC     = "X-AUTH-MAC"
	hdrKey     = "X-AUTH-KEY"
)

func NewClientSession(cfg *config.Config) (err error) {
	err = auth(cfg, "/auth/client")
	return
}

func NewAdminSession(cfg *config.Config) (err error) {
	err = auth(cfg, "/auth/admin")
	return
}

func Request(cfg *config.Config, path string, msg messages.Message) (m messages.Message, err error) {

	data, err := json.Marshal(msg)
	if err != nil {
		cfg.Log(0, "Error building message")
		return
	}
	cfg.Log(3, "Sending:", fmtData(data))

	mac := crypto.NewMAC(cfg.Runtime.SessionKey, data)

	req, err := http.NewRequest("POST", url(cfg.Startup.Address, path), bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Add(hdrEnc, "application/json")
	req.Header.Add(hdrUA, "SKDS "+cfg.Startup.Version)
	req.Header.Add(hdrSession, strconv.FormatInt(cfg.Runtime.SessionID, 10))
	req.Header.Add(hdrMAC, string(mac))

	resp, err := cfg.Runtime.Client.Do(req)
	if err != nil {
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	err = resp.Body.Close()
	if err != nil {
		return
	}

	if len(body) > 0 {
		err = json.Unmarshal(body, &m)
		if err != nil {
			return
		}
	}

	cfg.Log(3, "Recieved:", resp.StatusCode, fmtData(body))

	if resp.StatusCode != 200 {
		return m, errors.New(fmt.Sprintf("%s (%s)", resp.Status, m.Response))
	}

	key := []byte(resp.Header.Get(hdrKey))
	newKey := shared.HexDecode(key)
	if len(newKey) == 0 {
		err = errors.New("Invalid session key in response")
		return
	}
	if bytes.Compare(newKey, cfg.Runtime.SessionKey) == 0 {
		err = errors.New("Session key not rotated")
		return
	}
	cfg.Runtime.SessionKey = newKey

	return
}

// Even though all requests are sent over HTTPS, we use the http scheme
// here because we use a custom dialer that handles the TLS setup seperately.

func url(addr, path string) string {
	return fmt.Sprintf("http://%s%s", addr, path)
}

func auth(cfg *config.Config, path string) (err error) {
	msg := new(messages.Message)

	msg.Auth.Name = cfg.Startup.Name
	msg.Auth.Password = cfg.Runtime.Password

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", url(cfg.Startup.Address, path), bytes.NewReader(data))
	if err != nil {
		return
	}

	req.Header.Add(hdrEnc, "application/json")
	req.Header.Add(hdrUA, "SKDS "+cfg.Startup.Version)

	// Only send our public key on first authentication for efficiency.
	if len(cfg.Startup.ServerSignature) == 0 {
		enc, err := x509.MarshalPKIXPublicKey(&cfg.Runtime.Key.PublicKey)
		if err != nil {
			return err
		}
		req.Header.Add(hdrKey, string(shared.HexEncode(enc)))
	}

	// As our dialler pins the server certificate, we have a high
	// degree of confidence that our connection is not compromised, and
	// therefore do not require an ECDSA-signed response.
	// As a signed response would likely use the same key as the certificate
	// we pinned, signing would add very little.

	resp, err := cfg.Runtime.Client.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		return errors.New("Authentication failed")
	}

	err = resp.Body.Close()
	if err != nil {
		return
	}

	key := []byte(resp.Header.Get(hdrKey))
	cfg.Runtime.SessionKey = shared.HexDecode(key)
	if len(cfg.Runtime.SessionKey) == 0 {
		return errors.New("Invalid session key in response")
	}

	cfg.Runtime.SessionID, err = strconv.ParseInt(resp.Header.Get(hdrSession), 10, 64)
	return
}

func fmtData(data []byte) (out string) {
	var line string
	dataStr := string(data)
	if len(dataStr) > 0 {
		i := strings.Index(dataStr, "\n")
		if i == -1 {
			line = dataStr
		} else {
			line = dataStr[0:i]
		}
		if len(line) > maxLen {
			out = line[0:maxLen] + " [...]"
		} else {
			out = strings.TrimSuffix(line, "\n")
		}
	}
	return
}
