package client

import (
	"errors"

	"github.com/SorinS/krb5/iana/flags"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/krberror"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/types"
)

// GetForwardedTGT asks the KDC for a forwarded copy of the client's TGT
// (RFC 4120 2.6, the FORWARDED option), as MIT's krb5_fwd_tgt_creds does:
// a TGT another host can use, for delegation (KRB-CRED in a GSS-API
// context). The client's TGT must be forwardable (forwardable = true in
// krb5.conf). It returns the ticket and its encrypted part (the key,
// times, flags), and is not kept in the client's cache.
func (cl *Client) GetForwardedTGT() (messages.Ticket, messages.EncKDCRepPart, error) {
	realm := cl.Credentials.Domain()

	if err := cl.ensureValidSession(realm); err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, err
	}

	s, ok := cl.sessions.get(realm)
	if !ok {
		return messages.Ticket{}, messages.EncKDCRepPart{}, errors.New("no TGT for the client's realm")
	}

	s.mux.RLock()
	tgt, key, f := s.tgt, s.sessionKey, s.flags
	s.mux.RUnlock()

	if len(f.Bytes) > 0 && !types.IsFlagSet(&f, flags.Forwardable) {
		return messages.Ticket{}, messages.EncKDCRepPart{}, errors.New("the client's TGT is not forwardable")
	}

	spn := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", realm}}

	req, err := messages.NewTGSReqWithOptionsAt(cl.Credentials.CName(), realm, realm, cl.Config, tgt, key, spn, false,
		cl.Now(), flags.Forwarded, flags.Forwardable)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, krberror.Errorf(err, krberror.KRBMsgError, "error generating the TGS_REQ for a forwarded TGT")
	}

	_, rep, err := cl.TGSExchange(req, realm, tgt, key, 0)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, err
	}

	// TGSExchange keeps what it gets; a forwarded TGT is the caller's.
	cl.cache.RemoveEntry(spn.PrincipalNameString())

	if !types.IsFlagSet(&rep.DecryptedEncPart.Flags, flags.Forwarded) {
		return messages.Ticket{}, messages.EncKDCRepPart{}, errors.New("the KDC did not forward the TGT")
	}

	return rep.Ticket, rep.DecryptedEncPart, nil
}
