package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/crypto/rfc3961"
	"github.com/go-krb5/krb5/crypto/rfc6803"
	"github.com/go-krb5/krb5/crypto/rfc8009"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/types"
)

// PRF is the encryption type's pseudo-random function (RFC 3961 section
// 5.3): for RFC 3962 and DES3, SHA-1 of the input cut to a multiple of the
// cipher's block and encrypted under DK(key, "prf"); for RFC 8009,
// KDF-HMAC-SHA2(key, "prf", input); for RFC 6803, CMAC under
// KDF-FEEDBACK-CMAC(key, "prf"); for RC4, which RFC 4757 leaves out,
// HMAC-SHA1(key, input), as MIT has it.
func PRF(key types.EncryptionKey, input []byte) ([]byte, error) {
	e, err := GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	if len(key.KeyValue) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("key of %d bytes for encryption type %d", len(key.KeyValue), key.KeyType)
	}

	switch key.KeyType {
	case etypeID.AES128_CTS_HMAC_SHA256_128:
		return rfc8009.KDF_HMAC_SHA2(key.KeyValue, []byte("prf"), input, 256, e), nil
	case etypeID.AES256_CTS_HMAC_SHA384_192:
		return rfc8009.KDF_HMAC_SHA2(key.KeyValue, []byte("prf"), input, 384, e), nil
	case etypeID.CAMELLIA128_CTS_CMAC, etypeID.CAMELLIA256_CTS_CMAC:
		return rfc6803.PRF(key.KeyValue, input, e)
	case etypeID.RC4_HMAC:
		m := hmac.New(sha1.New, key.KeyValue)
		m.Write(input)

		return m.Sum(nil), nil
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.DES3_CBC_SHA1_KD:
		dk, err := rfc3961.DeriveKey(key.KeyValue, []byte("prf"), e)
		if err != nil {
			return nil, err
		}

		var block cipher.Block
		if key.KeyType == etypeID.DES3_CBC_SHA1_KD {
			block, err = des.NewTripleDESCipher(dk)
		} else {
			block, err = aes.NewCipher(dk)
		}

		if err != nil {
			return nil, err
		}

		h := sha1.Sum(input)
		tmp := h[:len(h)/block.BlockSize()*block.BlockSize()]
		out := make([]byte, len(tmp))
		cipher.NewCBCEncrypter(block, make([]byte, block.BlockSize())).CryptBlocks(out, tmp)

		return out, nil
	}

	return nil, fmt.Errorf("no PRF for encryption type %d", key.KeyType)
}

// PRFPlus is PRF+ (RFC 6113 section 5.1): PRF(key, 1 || input) ||
// PRF(key, 2 || input) || ..., cut to n bytes.
func PRFPlus(key types.EncryptionKey, input []byte, n int) ([]byte, error) {
	x := append([]byte{0}, input...)

	var out []byte

	for i := 1; len(out) < n; i++ {
		if i > 255 {
			return nil, errors.New("PRF+ output too long")
		}

		x[0] = byte(i)

		p, err := PRF(key, x)
		if err != nil {
			return nil, err
		}

		out = append(out, p...)
	}

	return out[:n], nil
}

// CF2 is KRB-FX-CF2 (RFC 6113 section 5.1): random-to-key of
// PRF+(k1, pepper1) XOR PRF+(k2, pepper2), each as long as k1's type's
// random string. The key is of k1's type, whatever k2's is. FAST's armor,
// challenge and reply keys are made this way.
func CF2(k1 types.EncryptionKey, pepper1 string, k2 types.EncryptionKey, pepper2 string) (types.EncryptionKey, error) {
	e, err := GetEtype(k1.KeyType)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	n := e.GetKeySeedBitLength() / 8

	a, err := PRFPlus(k1, []byte(pepper1), n)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	b, err := PRFPlus(k2, []byte(pepper2), n)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	for i := range a {
		a[i] ^= b[i]
	}

	// RC4's random-to-key is the identity (its RandomToKey here is its
	// string-to-key).
	if k1.KeyType != etypeID.RC4_HMAC {
		a = e.RandomToKey(a)
	}

	return types.EncryptionKey{KeyType: k1.KeyType, KeyValue: a}, nil
}

// RandomToKey is the encryption type's random-to-key of seed (its key
// seed length): the identity for RC4.
func RandomToKey(etypeID int32, seed []byte) (types.EncryptionKey, error) {
	e, err := GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	if len(seed) != e.GetKeySeedBitLength()/8 {
		return types.EncryptionKey{}, fmt.Errorf("random-to-key of %d bytes for encryption type %d", len(seed), etypeID)
	}

	k := append([]byte(nil), seed...)
	if etypeID != etypeIDRC4 {
		k = e.RandomToKey(k)
	}

	return types.EncryptionKey{KeyType: etypeID, KeyValue: k}, nil
}

const etypeIDRC4 = etypeID.RC4_HMAC

// RandomKey is a new random key of the encryption type: random-to-key of
// random bytes, so a DES3 key has its parity.
func RandomKey(etypeID int32) (types.EncryptionKey, error) {
	e, err := GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, err
	}

	k, err := types.GenerateEncryptionKey(e)
	if err != nil {
		return k, err
	}

	if e.GetKeySeedBitLength() != e.GetKeyByteSize()*8 {
		seed := make([]byte, e.GetKeySeedBitLength()/8)
		copy(seed, k.KeyValue)
		k.KeyValue = e.RandomToKey(seed)
	}

	return k, nil
}
