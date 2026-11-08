package rfc6803

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/go-crypt/x/pbkdf2"

	"github.com/SorinS/krb5/crypto/etype"
)

const (
	s2kParamsZero = 32768
)

// DeriveRandom implements the KDF-FEEDBACK-CMAC function from RFC 6803 Section 3.
// This uses the SP800-108 KDF in Feedback Mode with CMAC as the PRF.
func DeriveRandom(protocolKey, constant []byte, e etype.EType) ([]byte, error) {
	k := e.GetKeySeedBitLength()

	return kdfFeedbackCMAC(protocolKey, constant, k, e)
}

// DeriveKey derives a key from the protocol key based on the usage and the etype's specific methods.
func DeriveKey(protocolKey, usage []byte, e etype.EType) ([]byte, error) {
	r, err := DeriveRandom(protocolKey, usage, e)
	if err != nil {
		return nil, err
	}

	return e.RandomToKey(r), nil
}

// RandomToKey returns a key from the bytes provided.
func RandomToKey(b []byte) []byte {
	return b
}

// kdfFeedbackCMAC implements SP800-108 KDF in Feedback Mode using CMAC.
//
// PRF = CMAC with Camellia as the block cipher.
// n = ceiling(k / 128)
// K(0) = zeros
// K(i) = CMAC(key, K(i-1) | i | constant | 0x00 | k)
// DR(key, constant) = k-truncate(K(1) | K(2) | ... | K(n))
func kdfFeedbackCMAC(key, constant []byte, kBits int, _ etype.EType) ([]byte, error) {
	block, err := NewCamelliaCipher(key)
	if err != nil {
		return nil, err
	}

	n := (kBits + 127) / 128
	kBytes := kBits / 8

	// k as 4-byte big-endian.
	kBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(kBuf, uint32(kBits))

	prev := make([]byte, camelliaBlockSize) // K(0) = zeros

	var result []byte

	for i := 1; i <= n; i++ {
		// Build input: K(i-1) | i | constant | 0x00 | k
		iBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(iBuf, uint32(i))

		var input []byte
		input = append(input, prev...)
		input = append(input, iBuf...)
		input = append(input, constant...)
		input = append(input, 0x00)
		input = append(input, kBuf...)

		prev = CMAC(block, input)
		result = append(result, prev...)
	}

	// k-truncate.
	return result[:kBytes], nil
}

// StringToKey returns a key derived from the string provided according to RFC 6803 Section 4.
func StringToKey(secret, salt, s2kparams string, e etype.EType) ([]byte, error) {
	i, err := S2KparamsToIterations(s2kparams)
	if err != nil {
		return nil, err
	}

	return StringToKeyIter(secret, salt, i, e)
}

// StringToKeyIter returns a key derived from the string provided with the given iteration count.
func StringToKeyIter(secret, salt string, iterations int64, e etype.EType) ([]byte, error) {
	saltp := GetSaltP(salt, e)
	tkey := e.RandomToKey(StringToPBKDF2(secret, saltp, iterations, e))

	return DeriveKey(tkey, []byte("kerberos"), e)
}

// StringToPBKDF2 generates an encryption key from a passphrase and salt using PBKDF2.
func StringToPBKDF2(secret, salt string, iterations int64, e etype.EType) []byte {
	return pbkdf2.KeyExtended([]byte(secret), []byte(salt), iterations, int64(e.GetKeyByteSize()), e.GetHashFunc())
}

// GetSaltP returns the modified salt per RFC 6803 Section 4.
// The enctype name is prepended to the salt, separated by a null byte.
func GetSaltP(salt string, e etype.EType) string {
	var ename string

	switch e.GetKeyByteSize() {
	case 32:
		ename = "camellia256-cts-cmac"
	default:
		ename = "camellia128-cts-cmac"
	}

	b := []byte(ename)
	b = append(b, 0x00)
	b = append(b, []byte(salt)...)

	return string(b)
}

// S2KparamsToIterations converts the string representation of iterations to an integer.
func S2KparamsToIterations(s2kparams string) (int64, error) {
	if len(s2kparams) != 8 {
		return int64(s2kParamsZero), errors.New("invalid s2kparams length")
	}

	b, err := hex.DecodeString(s2kparams)
	if err != nil {
		return int64(s2kParamsZero), errors.New("invalid s2kparams, cannot decode string to bytes")
	}

	i := binary.BigEndian.Uint32(b)

	return int64(i), nil
}

// PRF is the pseudo-random function of RFC 6803 section 6: CMAC under
// KDF-FEEDBACK-CMAC(key, "prf") of the input.
func PRF(protocolKey, input []byte, e etype.EType) ([]byte, error) {
	kp, err := kdfFeedbackCMAC(protocolKey, []byte("prf"), e.GetKeySeedBitLength(), e)
	if err != nil {
		return nil, err
	}

	block, err := NewCamelliaCipher(kp)
	if err != nil {
		return nil, err
	}

	return CMAC(block, input), nil
}
