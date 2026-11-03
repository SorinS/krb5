package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
