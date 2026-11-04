package rfc4757

import (
	"encoding/binary"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:gosec,staticcheck // TODO: Ensure this is not registered by default.
)

// StringToKey returns a key derived from the string provided according to the definition in RFC 4757.
func StringToKey(secret string) ([]byte, error) {
	// MD4 of the password in UTF-16LE; a character outside the BMP is a
	// surrogate pair.
	u := utf16.Encode([]rune(secret))
	b := make([]byte, 2*len(u))

	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}

	h := md4.New()
	h.Write(b)

	return h.Sum(nil), nil
}

func deriveKeys(key, checksum []byte, usage uint32, export bool) (k1, k2, k3 []byte) {
	k1 = key
	k2 = HMAC(k1, UsageToMSMsgType(usage))
	k3 = HMAC(k2, checksum)

	return
}
