package client

import (
	"fmt"

	"github.com/go-krb5/krb5/kadmin"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the client's own password to the value provided, using
// the kpasswd change-password form (RFC 3244 version 1): no target principal,
// so a KDC (Active Directory included) accepts it from the user without the
// right a reset needs. To reset another principal's password, see SetPasswd.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	ticket, key, err := cl.chgPasswdTicket()
	if err != nil {
		return false, err
	}

	msg, subkey, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), newPasswd, ticket, key)
	if err != nil {
		return false, err
	}

	if err := cl.runKPasswd(msg, subkey); err != nil {
		return false, err
	}

	cl.Credentials.WithPassword(newPasswd)

	return true, nil
}

// SetPasswd resets another principal's password (targName@targRealm) to the
// value provided, using the kpasswd set-password form (RFC 3244). The client
// must hold the right to do so (on Active Directory, Reset Password on the
// target). The client's own credentials are left unchanged.
func (cl *Client) SetPasswd(targName types.PrincipalName, targRealm, newPasswd string) (bool, error) {
	ticket, key, err := cl.chgPasswdTicket()
	if err != nil {
		return false, err
	}

	msg, subkey, err := kadmin.SetPasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), targName, targRealm, newPasswd, ticket, key)
	if err != nil {
		return false, err
	}

	if err := cl.runKPasswd(msg, subkey); err != nil {
		return false, err
	}

	return true, nil
}

// chgPasswdTicket gets the ticket to the kadmin/changepw service that a
// kpasswd request is authenticated with, by an AS exchange of its own (the
// password being changed may be expired, so an ordinary TGT may not be held).
func (cl *Client) chgPasswdTicket() (messages.Ticket, types.EncryptionKey, error) {
	ASReq, err := messages.NewASReqForChgPasswdAt(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName(), cl.Now())
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	return ASRep.Ticket, ASRep.DecryptedEncPart.Key, nil
}

// runKPasswd sends a kpasswd request and checks the reply, which subkey
// decrypts.
func (cl *Client) runKPasswd(msg kadmin.Request, subkey types.EncryptionKey) error {
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return err
	}

	if err := r.Decrypt(subkey); err != nil {
		return err
	}

	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %w", r.ResultCode, r.Result, r.KRBError)
	}

	return nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (r kadmin.Reply, err error) {
	_, kps, err := cl.Config.GetKpasswdServers(cl.Credentials.Domain(), true)
	if err != nil {
		return r, err
	}

	b, err := msg.Marshal()
	if err != nil {
		return r, err
	}

	var rb []byte
	if len(b) <= cl.Config.LibDefaults.UDPPreferenceLimit {
		rb, err = dialSendUDP(cl.settings.dialer, kps, b)
		if err != nil {
			return r, err
		}
	} else {
		rb, err = dialSendTCP(cl.settings.dialer, kps, b)
		if err != nil {
			return r, err
		}
	}

	err = r.Unmarshal(rb)

	return r, err
}
