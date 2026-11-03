package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/types"
)

// Every encryption type refuses ciphertext too short for its confounder,
// checksum and a block, with an error, not a panic (upstream PR 580: an
// AP-REQ whose ticket has 4 bytes of ciphertext crashed an acceptor before
// any key was tried).
func TestDecryptMessage_Short(t *testing.T) {
	t.Parallel()

	for _, id := range []int32{
		etypeID.DES3_CBC_SHA1_KD, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128, etypeID.AES256_CTS_HMAC_SHA384_192, etypeID.RC4_HMAC,
		etypeID.CAMELLIA128_CTS_CMAC, etypeID.CAMELLIA256_CTS_CMAC,
	} {
		e, err := GetEtype(id)
		if !assert.NoError(t, err, "etype %d", id) {
			continue
		}

		key := types.EncryptionKey{KeyType: id, KeyValue: make([]byte, e.GetKeyByteSize())}

		for n := 0; n <= e.GetConfounderByteSize()+e.GetHMACBitLength()/8+2*e.GetMessageBlockByteSize(); n++ {
			assert.NotPanics(t, func() {
				_, err := DecryptMessage(make([]byte, n), key, 1)
				assert.Error(t, err, "etype %d, %d bytes", id, n)
			}, "etype %d, %d bytes", id, n)
		}
	}
}

// The PBKDF2 iteration count a KDC sends in ETYPE-INFO2, as MIT takes it:
// none (the default), the default or more up to 2^24 - 1; not zero, fewer
// than the default, or 2^24 and more (upstream issues 444, 445).
func TestCheckS2KParams(t *testing.T) {
	t.Parallel()

	aes, _ := GetEtype(etypeID.AES256_CTS_HMAC_SHA1_96)
	sha2, _ := GetEtype(etypeID.AES256_CTS_HMAC_SHA384_192)
	rc4, _ := GetEtype(etypeID.RC4_HMAC)

	for _, v := range []struct {
		et    etype.EType
		param string
		ok    bool
	}{
		{aes, "", true}, {aes, "00001000", true}, {aes, "00ffffff", true}, {aes, "0000ffff", true},
		{aes, "00000000", false}, {aes, "00000001", false}, {aes, "00000fff", false}, {aes, "01000000", false},
		{aes, "ffffffff", false}, {aes, "0000", false}, {aes, "zzzzzzzz", false},
		{sha2, "00008000", true}, {sha2, "00001000", false},
		{rc4, "", true},
	} {
		err := checkS2KParams(v.et, v.param)
		assert.Equal(t, v.ok, err == nil, "etype %d, %q: %v", v.et.GetETypeID(), v.param, err)
	}
}
