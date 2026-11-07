// Package crypto implements cryptographic functions for Kerberos 5 implementation.
package crypto

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/types"
)

// GetEtype returns an instances of the required etype struct for the etype ID.
func GetEtype(id int32) (etype.EType, error) {
	switch id {
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		var et Aes128CtsHmacSha96
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		var et Aes256CtsHmacSha96
		return et, nil
	case etypeID.AES128_CTS_HMAC_SHA256_128:
		var et Aes128CtsHmacSha256128
		return et, nil
	case etypeID.AES256_CTS_HMAC_SHA384_192:
		var et Aes256CtsHmacSha384192
		return et, nil
	case etypeID.DES3_CBC_SHA1_KD:
		var et Des3CbcSha1Kd
		return et, nil
	case etypeID.RC4_HMAC:
		var et RC4HMAC
		return et, nil
	case etypeID.CAMELLIA128_CTS_CMAC:
		var et Camellia128CtsCmac
		return et, nil
	case etypeID.CAMELLIA256_CTS_CMAC:
		var et Camellia256CtsCmac
		return et, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported EType: %d", id)
	}
}

// GetChksumEtype returns an instances of the required etype struct for the checksum ID.
func GetChksumEtype(id int32) (etype.EType, error) {
	switch id {
	case chksumtype.HMAC_SHA1_96_AES128:
		var et Aes128CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA1_96_AES256:
		var et Aes256CtsHmacSha96
		return et, nil
	case chksumtype.HMAC_SHA256_128_AES128:
		var et Aes128CtsHmacSha256128
		return et, nil
	case chksumtype.HMAC_SHA384_192_AES256:
		var et Aes256CtsHmacSha384192
		return et, nil
	case chksumtype.HMAC_SHA1_DES3_KD:
		var et Des3CbcSha1Kd
		return et, nil
	case chksumtype.KERB_CHECKSUM_HMAC_MD5:
		var et RC4HMAC
		return et, nil
	// case chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED:
	//	var et RC4HMAC
	//	return et, nil
	case chksumtype.CMAC_CAMELLIA128:
		var et Camellia128CtsCmac
		return et, nil
	case chksumtype.CMAC_CAMELLIA256:
		var et Camellia256CtsCmac
		return et, nil
	default:
		return nil, fmt.Errorf("unknown or unsupported checksum type: %d", id)
	}
}

// GetKeyFromPassword generates an encryption key from the principal's password.
func GetKeyFromPassword(passwd string, cname types.PrincipalName, realm string, etypeID int32, pas types.PADataSequence) (types.EncryptionKey, etype.EType, error) {
	var key types.EncryptionKey

	et, err := GetEtype(etypeID)
	if err != nil {
		return key, et, fmt.Errorf("error getting encryption type: %w", err)
	}

	sk2p := et.GetDefaultStringToKeyParams()

	var (
		salt string
		paID int32
	)

	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_PW_SALT:
			if paID > pa.PADataType {
				continue
			}

			salt = string(pa.PADataValue)
		case patype.PA_ETYPE_INFO:
			if paID > pa.PADataType {
				continue
			}

			var eti types.ETypeInfo

			err := eti.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("error unmashaling PA Data to PA-ETYPE-INFO2: %w", err)
			}

			if len(eti) == 0 {
				return key, et, fmt.Errorf("PA-ETYPE-INFO from the KDC has no entries")
			}

			if etypeID != eti[0].EType {
				et, err = GetEtype(eti[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %w", err)
				}
			}

			salt = string(eti[0].Salt)
		case patype.PA_ETYPE_INFO2:
			if paID > pa.PADataType {
				continue
			}

			var et2 types.ETypeInfo2

			err := et2.Unmarshal(pa.PADataValue)
			if err != nil {
				return key, et, fmt.Errorf("error unmashalling PA Data to PA-ETYPE-INFO2: %w", err)
			}

			if len(et2) == 0 {
				return key, et, fmt.Errorf("PA-ETYPE-INFO2 from the KDC has no entries")
			}

			if etypeID != et2[0].EType {
				et, err = GetEtype(et2[0].EType)
				if err != nil {
					return key, et, fmt.Errorf("error getting encryption type: %w", err)
				}
			}

			if len(et2[0].S2KParams) == 4 {
				sk2p = hex.EncodeToString(et2[0].S2KParams)
			}

			salt = et2[0].Salt
		}
	}

	if salt == "" {
		salt = cname.GetSalt(realm)
	}

	if err := checkS2KParams(et, sk2p); err != nil {
		return key, et, err
	}

	k, err := et.StringToKey(passwd, salt, sk2p)
	if err != nil {
		return key, et, fmt.Errorf("error deriving key from string: %+v", err)
	}

	key = types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: k,
	}

	return key, et, nil
}

// GetEncryptedData encrypts the data provided and returns and EncryptedData type.
// Pass a usage value of zero to use the key provided directly rather than deriving one.
func GetEncryptedData(plainBytes []byte, key types.EncryptionKey, usage uint32, kvno int) (types.EncryptedData, error) {
	var ed types.EncryptedData

	et, err := GetEtype(key.KeyType)
	if err != nil {
		return ed, fmt.Errorf("error getting etype: %w", err)
	}

	_, b, err := et.EncryptMessage(key.KeyValue, plainBytes, usage)
	if err != nil {
		return ed, err
	}

	ed = types.EncryptedData{
		EType:  key.KeyType,
		Cipher: b,
		KVNO:   kvno,
	}

	return ed, nil
}

// DecryptEncPart decrypts the EncryptedData.
func DecryptEncPart(ed types.EncryptedData, key types.EncryptionKey, usage uint32) ([]byte, error) {
	return DecryptMessage(ed.Cipher, key, usage)
}

// DecryptMessage decrypts the ciphertext and verifies the integrity.
func DecryptMessage(ciphertext []byte, key types.EncryptionKey, usage uint32) ([]byte, error) {
	et, err := GetEtype(key.KeyType)
	if err != nil {
		return []byte{}, fmt.Errorf("error decrypting: %w", err)
	}

	b, err := et.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, fmt.Errorf("error decrypting: %w", err)
	}

	return b, nil
}

// maxIterationCount is MIT's MAX_ITERATION_COUNT (s2k_pbkdf2.c): more PBKDF2
// iterations than a KDC may ask for.
const maxIterationCount = 0x1000000

// checkS2KParams checks the string-to-key parameters a KDC sent (in
// ETYPE-INFO2, unauthenticated) for an encryption type whose keys come
// from PBKDF2, as MIT does: an iteration count of zero, fewer than the
// type's default (4096, or 32768 for RFC 8009's types and Camellia), or
// 2^24 or more is refused. Fewer would weaken the key against guessing; a
// forged count of 2^32 - 1 would keep the client busy for hours.
func checkS2KParams(et etype.EType, s2kparams string) error {
	def := et.GetDefaultStringToKeyParams()
	if s2kparams == "" || len(def) != 8 {
		return nil
	}

	b, err := hex.DecodeString(s2kparams)
	if err != nil || len(b) != 4 {
		return fmt.Errorf("invalid string-to-key parameters %q", s2kparams)
	}

	d, _ := hex.DecodeString(def)
	n, min := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(d)

	if n == 0 || n < min || n >= maxIterationCount {
		return fmt.Errorf("the KDC's PBKDF2 iteration count %d is outside %d to %d", n, min, maxIterationCount-1)
	}

	return nil
}
