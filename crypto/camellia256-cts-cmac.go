package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"

	"github.com/SorinS/krb5/crypto/rfc6803"
	"github.com/SorinS/krb5/iana/chksumtype"
	"github.com/SorinS/krb5/iana/etypeID"
)

// RFC 6803.

// Camellia256CtsCmac implements Kerberos encryption type camellia256-cts-cmac.
type Camellia256CtsCmac struct {
}

// GetETypeID returns the EType ID number.
func (e Camellia256CtsCmac) GetETypeID() int32 {
	return etypeID.CAMELLIA256_CTS_CMAC
}

// GetHashID returns the checksum type ID number.
func (e Camellia256CtsCmac) GetHashID() int32 {
	return chksumtype.CMAC_CAMELLIA256
}

// GetKeyByteSize returns the number of bytes for key of this etype.
func (e Camellia256CtsCmac) GetKeyByteSize() int {
	return 256 / 8
}

// GetKeySeedBitLength returns the number of bits for the seed for key generation.
func (e Camellia256CtsCmac) GetKeySeedBitLength() int {
	return e.GetKeyByteSize() * 8
}

// GetHashFunc returns the hash function for this etype.
func (e Camellia256CtsCmac) GetHashFunc() func() hash.Hash {
	return sha1.New
}

// GetMessageBlockByteSize returns the block size for the etype's messages.
func (e Camellia256CtsCmac) GetMessageBlockByteSize() int {
	return 1
}

// GetDefaultStringToKeyParams returns the default key derivation parameters in string form.
func (e Camellia256CtsCmac) GetDefaultStringToKeyParams() string {
	return "00008000"
}

// GetConfounderByteSize returns the byte count for confounder to be used during cryptographic operations.
func (e Camellia256CtsCmac) GetConfounderByteSize() int {
	return 16
}

// GetHMACBitLength returns the bit count size of the integrity hash.
func (e Camellia256CtsCmac) GetHMACBitLength() int {
	return 128
}

// GetCypherBlockBitLength returns the bit count size of the cypher block.
func (e Camellia256CtsCmac) GetCypherBlockBitLength() int {
	return 128
}

// StringToKey returns a key derived from the string provided.
func (e Camellia256CtsCmac) StringToKey(secret string, salt string, s2kparams string) ([]byte, error) {
	return rfc6803.StringToKey(secret, salt, s2kparams, e)
}

// RandomToKey returns a key from the bytes provided.
func (e Camellia256CtsCmac) RandomToKey(b []byte) []byte {
	return rfc6803.RandomToKey(b)
}

// EncryptData encrypts the data provided.
func (e Camellia256CtsCmac) EncryptData(key, data []byte) ([]byte, []byte, error) {
	return rfc6803.EncryptData(key, data, e)
}

// EncryptMessage encrypts the message provided and concatenates it with the integrity hash to create an encrypted message.
func (e Camellia256CtsCmac) EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error) {
	return rfc6803.EncryptMessage(key, message, usage, e)
}

// DecryptData decrypts the data provided.
func (e Camellia256CtsCmac) DecryptData(key, data []byte) ([]byte, error) {
	return rfc6803.DecryptData(key, data, e)
}

// DecryptMessage decrypts the message provided and verifies the integrity of the message.
func (e Camellia256CtsCmac) DecryptMessage(key, ciphertext []byte, usage uint32) ([]byte, error) {
	return rfc6803.DecryptMessage(key, ciphertext, usage, e)
}

// DeriveKey derives a key from the protocol key based on the usage value.
func (e Camellia256CtsCmac) DeriveKey(protocolKey, usage []byte) ([]byte, error) {
	return rfc6803.DeriveKey(protocolKey, usage, e)
}

// DeriveRandom generates data needed for key generation.
func (e Camellia256CtsCmac) DeriveRandom(protocolKey, usage []byte) ([]byte, error) {
	return rfc6803.DeriveRandom(protocolKey, usage, e)
}

// VerifyIntegrity checks the integrity of the plaintext message.
func (e Camellia256CtsCmac) VerifyIntegrity(protocolKey, ct, pt []byte, usage uint32) bool {
	return rfc6803.VerifyIntegrity(protocolKey, ct, pt, usage, e)
}

// GetChecksumHash returns a keyed checksum hash of the bytes provided.
func (e Camellia256CtsCmac) GetChecksumHash(protocolKey, data []byte, usage uint32) ([]byte, error) {
	return rfc6803.GetChecksumHash(protocolKey, data, usage, e)
}

// VerifyChecksum compares the checksum of the message bytes is the same as the checksum provided.
func (e Camellia256CtsCmac) VerifyChecksum(protocolKey, data, chksum []byte, usage uint32) bool {
	c, err := e.GetChecksumHash(protocolKey, data, usage)
	if err != nil {
		return false
	}

	return hmac.Equal(chksum, c)
}
