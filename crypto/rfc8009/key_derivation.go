package rfc8009

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/pbkdf2"

	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/etypeID"
)

const (
	s2kParamsZero = 32768
)

// DeriveRandom for key derivation as defined in RFC 8009.
func DeriveRandom(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	h := e.GetHashFunc()()
	return KDF_HMAC_SHA2(protocolKey, []byte("prf"), usage, h.Size(), e), nil
}

// DeriveKey derives a key from the protocol key based on the usage and the etype's specific methods.
//
// https://tools.ietf.org/html/rfc8009#section-5
func DeriveKey(protocolKey, label []byte, e etype.EType) []byte {
	kl := e.GetKeySeedBitLength()

	// aes256-cts-hmac-sha384-192's Kc and Ki (usage labels ending 0x99 and
	// 0x55) are 192 bits; its keys and Ke are 256.
	if e.GetETypeID() == etypeID.AES256_CTS_HMAC_SHA384_192 && len(label) == 5 && (label[4] == 0x99 || label[4] == 0x55) {
		kl = 192
	}

	return e.RandomToKey(KDF_HMAC_SHA2(protocolKey, label, nil, kl, e))
}

// RandomToKey returns a key from the bytes provided according to the definition in RFC 8009.
func RandomToKey(b []byte) []byte {
	return b
}

// StringToKey returns a key derived from the string provided according to the definition in RFC 8009.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToItertions(s2kparams)
	if err != nil {
		return nil, err
	}

	return StringToKeyIter(secret, salt, i, e)
}

// StringToKeyIter returns a key derived from the string provided according to the definition in RFC 8009.
func StringToKeyIter(secret, salt string, iterations int, e etype.EType) ([]byte, error) {
	tkey := e.RandomToKey(StringToPBKDF2(secret, salt, iterations, e))
	return e.DeriveKey(tkey, []byte("kerberos"))
}

// StringToPBKDF2 generates an encryption key from a pass phrase and salt string using the PBKDF2 function from PKCS #5 v2.0.
func StringToPBKDF2(secret, salt string, iterations int, e etype.EType) []byte {
	return pbkdf2.Key([]byte(secret), []byte(salt), iterations, e.GetKeyByteSize(), e.GetHashFunc())
}

// KDF_HMAC_SHA2 key derivation: https://tools.ietf.org/html/rfc8009#section-3
func KDF_HMAC_SHA2(protocolKey, label, context []byte, kl int, e etype.EType) []byte {
	//k: Length in bits of the key to be outputted, expressed in big-endian binary representation in 4 bytes.
	k := make([]byte, 4)
	binary.BigEndian.PutUint32(k, uint32(kl))

	c := make([]byte, 4)
	binary.BigEndian.PutUint32(c, uint32(1))
	c = append(c, label...)

	c = append(c, byte(0))
	if len(context) > 0 {
		c = append(c, context...)
	}

	c = append(c, k...)

	mac := hmac.New(e.GetHashFunc(), protocolKey)
	mac.Write(c)

	return mac.Sum(nil)[:(kl / 8)]
}

// GetSaltP returns the salt value based on the etype name: https://tools.ietf.org/html/rfc8009#section-4
func GetSaltP(salt, ename string) string {
	b := []byte(ename)
	b = append(b, byte(0))
	b = append(b, []byte(salt)...)

	return string(b)
}

// S2KparamsToItertions converts the string representation of iterations to an integer for RFC 8009.
func S2KparamsToItertions(s2kparams string) (int, error) {
	var i uint32

	if len(s2kparams) != 8 {
		return s2kParamsZero, errors.New("Invalid s2kparams length")
	}

	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		return s2kParamsZero, errors.New("Invalid s2kparams, cannot decode string to bytes")
	}

	i = binary.BigEndian.Uint32(b)

	return int(i), nil
}
