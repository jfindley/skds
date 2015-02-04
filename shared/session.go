// This file just defines the session type, to avoid the loop that
// would result from putting it in transport

package shared

import (
	"crypto/tls"
	"net/http"
)

type Session struct {
	SessionID  int64
	SessionKey []byte
	Client     *http.Client
	TLSConfig  *tls.Config
}
