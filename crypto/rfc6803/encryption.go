package rfc6803

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/crypto/common"
	"github.com/go-krb5/krb5/crypto/etype"
)

// EncryptData encrypts the data provided using Camellia-CBC-CTS.
func EncryptData(key, data []byte, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	return EncryptCTS(key, data)
}

// EncryptMessage encrypts the message provided and concatenates it with the CMAC integrity tag.
func EncryptMessage(key, message []byte, usage uint32, e etype.EType) ([]byte, []byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, nil, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	// Generate random confounder.
	c := make([]byte, e.GetConfounderByteSize())

	_, err := rand.Read(c)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate random confounder: %w", err)
	}

	plainBytes := append(c, message...)

	// Derive encryption key Ke.
	ke, err := e.DeriveKey(key, common.GetUsageKe(usage))
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving key for encryption: %w", err)
	}

	// Encrypt the data.
	iv, b, err := EncryptData(ke, plainBytes, e)
	if err != nil {
		return iv, b, fmt.Errorf("error encrypting data: %w", err)
	}

	// Generate CMAC integrity tag using Ki.
	ih, err := GetIntegrityHash(plainBytes, key, usage, e)
	if err != nil {
		return iv, b, fmt.Errorf("error generating integrity hash: %w", err)
	}

	b = append(b, ih...)

	return iv, b, nil
}

// DecryptData decrypts the data provided using Camellia-CBC-CTS.
func DecryptData(key, data []byte, e etype.EType) ([]byte, error) {
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("incorrect keysize: expected: %v actual: %v", e.GetKeyByteSize(), len(key))
	}

	return DecryptCTS(key, data)
}

// DecryptMessage decrypts the message provided and verifies the integrity.
func DecryptMessage(key, ciphertext []byte, usage uint32, e etype.EType) ([]byte, error) {
	// Derive the encryption key Ke.
	ke, err := e.DeriveKey(key, common.GetUsageKe(usage))
	if err != nil {
		return nil, fmt.Errorf("error deriving key: %w", err)
	}

	// Strip off the CMAC tag from the end.
	hashLen := e.GetHMACBitLength() / 8
	b, err := DecryptData(ke, ciphertext[:len(ciphertext)-hashLen], e)
	if err != nil {
		return nil, err
	}

	// Verify integrity.
	if !VerifyIntegrity(key, ciphertext, b, usage, e) {
		return nil, errors.New("integrity verification failed")
	}

	// Remove the confounder bytes.
	return b[e.GetConfounderByteSize():], nil
}

// GetIntegrityHash returns a CMAC integrity tag of the bytes provided.
func GetIntegrityHash(pt, key []byte, usage uint32, e etype.EType) ([]byte, error) {
	ki, err := e.DeriveKey(key, common.GetUsageKi(usage))
	if err != nil {
		return nil, fmt.Errorf("unable to derive key for integrity: %w", err)
	}

	block, err := NewCamelliaCipher(ki)
	if err != nil {
		return nil, err
	}

	return CMAC(block, pt), nil
}

// VerifyIntegrity checks the integrity of the ciphertext message.
func VerifyIntegrity(key, ct, pt []byte, usage uint32, e etype.EType) bool {
	hashLen := e.GetHMACBitLength() / 8
	h := make([]byte, hashLen)
	copy(h, ct[len(ct)-hashLen:])

	expectedMAC, err := GetIntegrityHash(pt, key, usage, e)
	if err != nil {
		return false
	}

	return hmac.Equal(h, expectedMAC)
}

// GetChecksumHash returns a CMAC checksum hash of the bytes provided.
func GetChecksumHash(protocolKey, data []byte, usage uint32, e etype.EType) ([]byte, error) {
	kc, err := e.DeriveKey(protocolKey, common.GetUsageKc(usage))
	if err != nil {
		return nil, fmt.Errorf("unable to derive key for checksum: %w", err)
	}

	block, err := NewCamelliaCipher(kc)
	if err != nil {
		return nil, err
	}

	return CMAC(block, data), nil
}
