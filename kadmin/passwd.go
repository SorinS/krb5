// Package kadmin provides Kerberos administration capabilities.
package kadmin

import (
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// ChangePasswdMsg generates a request for a principal to change its own
// password, and the key to decrypt the reply. It uses the change-password
// protocol (version 1): the new password alone, with no target principal,
// which a KDC (Active Directory included) accepts from the principal itself
// without the privilege a reset needs. cname and realm are the requester's,
// from the ticket. SetPasswdMsg is the privileged form that targets another
// principal; the earlier code always sent that form, so a self-service change
// was refused on AD as an unprivileged reset.
func ChangePasswdMsg(cname types.PrincipalName, realm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	return passwdMsg(cname, realm, []byte(password), verChangePassword, tkt, sessionKey)
}

// SetPasswdMsg generates a set-password request (RFC 3244, version 0xff80)
// targeting targName@targRealm, and the key to decrypt the reply. cname and
// realm are the requester's (from the ticket); the KDC requires it to hold the
// right to reset targName's password. A principal changing its own password
// uses ChangePasswdMsg.
func SetPasswdMsg(cname types.PrincipalName, realm string, targName types.PrincipalName, targRealm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  targName,
		TargRealm: targRealm,
	}

	chpwdb, err := chgpasswd.Marshal()
	if err != nil {
		return r, k, krberror.Errorf(err, krberror.KRBMsgError, "error marshaling change passwd data")
	}

	return passwdMsg(cname, realm, chpwdb, verSetPassword, tkt, sessionKey)
}

// passwdMsg builds a kpasswd request carrying userData at the given protocol
// version, and returns the subkey the reply is encrypted with.
func passwdMsg(cname types.PrincipalName, realm string, userData []byte, version uint16, tkt messages.Ticket, sessionKey types.EncryptionKey) (r Request, k types.EncryptionKey, err error) {
	// Generate authenticator.
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
		return
	}

	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey etype")
		return
	}

	err = auth.GenerateSeqNumberAndSubKey(etype.GetETypeID(), etype.GetKeyByteSize())
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey")
		return
	}

	k = auth.SubKey

	// Generate AP_REQ.
	APreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return r, k, err
	}

	// Form the KRBPriv encpart data.
	kp := messages.EncKrbPrivPart{
		UserData:       userData,
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	}
	kpriv := messages.NewKRBPriv(kp)

	err = kpriv.EncryptEncPart(k)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncryptingError, "error encrypting change passwd data")
		return
	}

	r = Request{
		APREQ:   APreq,
		KRBPriv: kpriv,
		Version: version,
	}

	return
}
