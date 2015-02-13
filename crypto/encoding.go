// Convience functions to handle encoding/decoding.

package crypto

import (
	"encoding/hex"
)

func HexEncode(in []byte) (out []byte) {
	out = make([]byte, hex.EncodedLen(len(in)))
	hex.Encode(out, in)
	return
}

func HexDecode(in []byte) (out []byte) {
	out = make([]byte, hex.DecodedLen(len(in)))
	hex.Decode(out, in)
	return
}
