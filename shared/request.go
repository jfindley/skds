package shared

import (
	"bytes"
	// "crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	// "strconv"
	"strings"

	"github.com/jfindley/skds/crypto"
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

func (s *Session) Get(url string) (resp []Message, err error) {
	r, err := s.client.Get(fmtUrl(url))
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

	return readResp(r.Body)
}

func (s *Session) Post(url string, data []byte) (resp []Message, err error) {
	r, err := s.client.Post(fmtUrl(url), "application/skds", bytes.NewReader(data))
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

	return readResp(r.Body)
}

// Even though all requests are sent over HTTPS, we force the HTTP scheme
// here because we use a custom dialer that handles the TLS setup seperately.

func fmtUrl(url string) string {
	return strings.Replace(url, "https", "http", 1)
}

func readResp(r io.Reader) (resp []Message, err error) {
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

func (s *Session) nextKey(r *http.Response) (err error) {
	if s.sessionID == 0 {
		return
	}
	key := []byte(r.Header.Get(hdrKey))
	newKey := crypto.HexDecode(key)
	if len(newKey) == 0 {
		return errors.New("Invalid session key in response")
	}
	if bytes.Compare(newKey, s.sessionKey) == 0 {
		return errors.New("Session key not rotated")
	}
	s.sessionKey = newKey
	return
}

// // We use an empty interface here to allow sending other things than an SKDS message.
// func (s *Session) Request(cfg *Config, path string, msg interface{}) (m Message, err error) {

// 	data, err := json.Marshal(msg)
// 	if err != nil {
// 		cfg.Log(0, "Error building message")
// 		return
// 	}
// 	cfg.Log(3, "Sending:", fmtData(data))

// 	mac := crypto.NewMAC(s.SessionKey, data)

// 	req, err := http.NewRequest("POST", url(cfg.Startup.Address, path), bytes.NewReader(data))
// 	if err != nil {
// 		return
// 	}
// 	req.Header.Add(hdrEnc, "application/json")
// 	req.Header.Add(hdrUA, "SKDS "+cfg.Startup.Version)
// 	req.Header.Add(hdrSession, strconv.FormatInt(s.SessionID, 10))
// 	req.Header.Add(hdrMAC, string(mac))

// 	resp, err := s.Client.Do(req)
// 	if err != nil {
// 		return
// 	}
// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return
// 	}
// 	err = resp.Body.Close()
// 	if err != nil {
// 		return
// 	}

// 	if len(body) > 0 {
// 		err = json.Unmarshal(body, &m)
// 		if err != nil {
// 			return
// 		}
// 	}

// 	cfg.Log(3, "Recieved:", resp.StatusCode, fmtData(body))

// 	if resp.StatusCode != 200 {
// 		return m, errors.New(fmt.Sprintf("%s (%s)", resp.Status, m.Response))
// 	}

// 	key := []byte(resp.Header.Get(hdrKey))
// 	newKey := shared.HexDecode(key)

// 	return
// }

// func (s *Session) Auth(cfg *Config) (err error) {
// 	msg := new(Message)

// 	msg.Auth.Name = cfg.Startup.Name
// 	msg.Auth.Password = s.Password

// 	data, err := json.Marshal(msg)
// 	if err != nil {
// 		return
// 	}

// 	req, err := http.NewRequest("POST", url(cfg.Startup.Address, path), bytes.NewReader(data))
// 	if err != nil {
// 		return
// 	}

// 	req.Header.Add(hdrEnc, "application/json")
// 	req.Header.Add(hdrUA, "SKDS "+cfg.Startup.Version)

// 	// Only send our public key on first authentication for efficiency.
// 	if len(cfg.Startup.ServerSignature) == 0 {
// 		enc, err := x509.MarshalPKIXPublicKey(&cfg.Runtime.Key.PublicKey)
// 		if err != nil {
// 			return err
// 		}
// 		req.Header.Add(hdrKey, string(shared.HexEncode(enc)))
// 	}

// 	// As our dialler pins the server certificate, we have a high
// 	// degree of confidence that our connection is not compromised, and
// 	// therefore do not require an ECDSA-signed response.
// 	// As a signed response would likely use the same key as the certificate
// 	// we pinned, signing would add very little.

// 	resp, err := s.Client.Do(req)
// 	if err != nil {
// 		return
// 	}

// 	if resp.StatusCode != 200 {
// 		return errors.New("Authentication failed")
// 	}

// 	err = resp.Body.Close()
// 	if err != nil {
// 		return
// 	}

// 	key := []byte(resp.Header.Get(hdrKey))
// 	s.SessionKey = shared.HexDecode(key)
// 	if len(s.SessionKey) == 0 {
// 		return errors.New("Invalid session key in response")
// 	}

// 	s.SessionID, err = strconv.ParseInt(resp.Header.Get(hdrSession), 10, 64)
// 	return
// }

// func fmtData(data []byte) (out string) {
// 	var line string
// 	dataStr := string(data)
// 	if len(dataStr) > 0 {
// 		i := strings.Index(dataStr, "\n")
// 		if i == -1 {
// 			line = dataStr
// 		} else {
// 			line = dataStr[0:i]
// 		}
// 		if len(line) > maxLen {
// 			out = line[0:maxLen] + " [...]"
// 		} else {
// 			out = strings.TrimSuffix(line, "\n")
// 		}
// 	}
// 	return
// }
