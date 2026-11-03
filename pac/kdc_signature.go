package pac

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

// signatureDataTypeLength is the size of a PAC_SIGNATURE_DATA's SignatureType field.
const signatureDataTypeLength = 4

// zeroSignature zeroes, in a copy of the PAC, what follows the type of the
// signature buffer.
func zeroSignature(data []byte, buf InfoBuffer) {
	if buf.CBBufferSize < signatureDataTypeLength {
		return
	}

	start := int(buf.Offset) + signatureDataTypeLength
	end := int(buf.Offset) + int(buf.CBBufferSize)

	clear(data[start:end])
}

// verifySignature checks a PAC signature over data with the key, as MS-PAC
// 2.8 has it: a keyed checksum of the signature's type, with key usage
// KERB_NON_KERB_CKSUM_SALT.
func verifySignature(sig *SignatureData, key types.EncryptionKey, data []byte, what string) error {
	if sig == nil {
		return fmt.Errorf("PAC has no %s", what)
	}

	etype, err := crypto.GetChksumEtype(int32(sig.SignatureType))
	if err != nil {
		return fmt.Errorf("PAC %s: %w", what, err)
	}

	if etype.GetETypeID() != key.KeyType {
		return fmt.Errorf("PAC %s is of checksum type %d, which the key's encryption type %d does not make",
			what, int32(sig.SignatureType), key.KeyType)
	}

	if len(sig.Signature) == 0 || !etype.VerifyChecksum(key.KeyValue, data, sig.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		return fmt.Errorf("PAC %s verification failed", what)
	}

	return nil
}

// VerifyKDCSignature checks the KDC's signature (MS-PAC 2.8.2), which is
// over the server's signature, with the key of the KDC's krbtgt principal.
// Only a KDC, or a service holding the krbtgt key, can do this; a service
// checks the server's signature (done in ProcessPACInfoBuffers).
func (pac *PACType) VerifyKDCSignature(krbtgtKey types.EncryptionKey) error {
	if pac.ServerChecksum == nil {
		return errors.New("PAC has no server signature")
	}

	return verifySignature(pac.KDCChecksum, krbtgtKey, pac.ServerChecksum.Signature, "KDC signature")
}

// VerifyFullChecksum checks the KDC's signature over the whole PAC (MS-PAC
// 2.8.5, the extended KDC signature), with the krbtgt key: it is over the
// PAC with the server's, the KDC's and its own signatures zeroed.
func (pac *PACType) VerifyFullChecksum(krbtgtKey types.EncryptionKey) error {
	buf, ok := pac.sigBuffers[infoTypePACFullChecksum]
	if !ok || pac.FullChecksum == nil {
		return errors.New("PAC has no full checksum")
	}

	data := make([]byte, len(pac.ZeroSigData))
	copy(data, pac.ZeroSigData)
	zeroSignature(data, buf)

	return verifySignature(pac.FullChecksum, krbtgtKey, data, "full checksum")
}

// VerifyTicketChecksum checks the KDC's signature over the ticket (MS-PAC
// 2.8.3) with the krbtgt key. encTicketPart is the ticket's EncTicketPart,
// re-encoded with the PAC's ad-data replaced by a single zero byte
// (messages.Ticket.VerifyPACKDC makes it).
func (pac *PACType) VerifyTicketChecksum(krbtgtKey types.EncryptionKey, encTicketPart []byte) error {
	return verifySignature(pac.TicketChecksum, krbtgtKey, encTicketPart, "ticket checksum")
}

// ValidateClientInfo checks the PAC's client info against the ticket it
// came in, as MIT's krb5_pac_verify does: the time is the ticket's auth
// time and the name the ticket's client name, its components joined by
// "/", without the realm or (as MIT does when asked) with it.
func (pac *PACType) ValidateClientInfo(cname types.PrincipalName, crealm string, authTime time.Time) error {
	if pac.ClientInfo == nil {
		return errors.New("PAC has no client info")
	}

	if pac.ClientInfo.ClientID.Time().Unix() != authTime.Unix() {
		return fmt.Errorf("PAC client info time %v is not the ticket's auth time %v",
			pac.ClientInfo.ClientID.Time().UTC(), authTime.UTC())
	}

	name := strings.Join(cname.NameString, "/")
	if pac.ClientInfo.Name != name && pac.ClientInfo.Name != name+"@"+crealm {
		return fmt.Errorf("PAC client info name %q is not the ticket's client %q", pac.ClientInfo.Name, name)
	}

	return nil
}
