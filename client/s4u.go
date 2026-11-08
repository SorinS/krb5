package client

import (
	"crypto/x509"

	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/iana/patype"
	"github.com/SorinS/krb5/krberror"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/types"
)

// GetServiceTicketForUser is S4U2Self (MS-SFU): a ticket to this client (a
// service, with its own TGT) in the name of user, who need not have
// authenticated to it. The ticket's PAC says who the user is. It is
// forwardable, so that S4U2Proxy can use it, only if the client's TGT is
// (forwardable in krb5.conf); AD and MIT deny it to a service with
// delegation targets but without protocol transition
// (TrustedToAuthForDelegation, ok_to_auth_as_delegate). The ticket is not
// cached: GetServiceTicket's are the client's own.
//
// A user of another realm is asked for as Windows and MIT's client do: the
// request goes first to the user's realm, with the client's TGT for it,
// naming the client as an enterprise principal; that KDC answers with a
// referral back towards the client's realm, a TGT carrying the user's PAC,
// which TGSExchange follows with the same request. Active Directory does this
// across a forest trust. MIT's KDC refers only host-based names, so as the
// user's realm it cannot: it answers KDC_ERR_S_PRINCIPAL_UNKNOWN.
func (cl *Client) GetServiceTicketForUser(user types.PrincipalName, userRealm string) (messages.Ticket, types.EncryptionKey, error) {
	realm := cl.Credentials.Domain()
	if userRealm == "" {
		userRealm = realm
	}

	tgt, skey, err := cl.sessionTGT(userRealm)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	cname := cl.Credentials.CName()

	req, err := messages.NewS4U2SelfReqAt(cname, realm, userRealm, cl.Config, tgt, skey,
		messages.S4UUser{Name: user, Realm: userRealm}, cl.Now())
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate the S4U2Self TGS_REQ")
	}

	// The user's realm's KDC has not got this client: it is named as an
	// enterprise principal (client@realm) for that KDC to route by its name
	// suffixes, as MIT does, and the request signed again.
	if userRealm != realm {
		req.ReqBody.SName = types.PrincipalName{
			NameType:   nametype.KRB_NT_ENTERPRISE,
			NameString: []string{cname.PrincipalNameString() + "@" + realm},
		}

		if err = req.SetPAData(realm, tgt, skey, cl.Now()); err != nil {
			return messages.Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate the S4U2Self TGS_REQ")
		}
	}

	_, rep, err := cl.TGSExchange(req, userRealm, tgt, skey, 0)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	return rep.Ticket, rep.DecryptedEncPart.Key, nil
}

// GetServiceTicketForCertificate is S4U2Self by the user's certificate: a
// ticket to this client in the name of whoever the KDC maps cert to, in the
// client's realm; the ticket and the KDC's checksummed reply say who it is.
// Having a user's certificate proves nothing here, it is public: as with
// GetServiceTicketForUser, the service vouches for the user, so it must have
// validated cert and the user's possession of its key first. Do not count on
// the KDC for that: Windows Server 2022's maps by altSecurityIdentities and
// issued the ticket for an expired certificate of a CA it did not know. Nor
// pass on a certificate unchecked. Ed25519 certificates are refused: they have
// not been shown to work with Windows' KDC. MIT's DB2 back end does not do
// this at all. The ticket is not cached.
func (cl *Client) GetServiceTicketForCertificate(cert *x509.Certificate) (messages.Ticket, types.EncryptionKey, error) {
	if cert == nil || len(cert.Raw) == 0 {
		return messages.Ticket{}, types.EncryptionKey{}, krberror.NewErrorf(krberror.KRBMsgError, "S4U2Self by certificate needs a parsed certificate")
	}

	if cert.PublicKeyAlgorithm == x509.Ed25519 {
		return messages.Ticket{}, types.EncryptionKey{}, krberror.NewErrorf(krberror.KRBMsgError, "S4U2Self by certificate does not take Ed25519 certificates")
	}

	realm := cl.Credentials.Domain()

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	req, err := messages.NewS4U2SelfReqAt(cl.Credentials.CName(), realm, realm, cl.Config, tgt, skey,
		messages.S4UUser{Realm: realm, Cert: cert.Raw}, cl.Now())
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate the S4U2Self TGS_REQ")
	}

	_, rep, err := cl.TGSExchange(req, realm, tgt, skey, 0)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	return rep.Ticket, rep.DecryptedEncPart.Key, nil
}

// GetServiceTicketForProxy is S4U2Proxy (MS-SFU): a ticket to spn
// (<SERVICE>/<FQDN>) in the name of evidence's client, evidence being a
// ticket to this client, from GetServiceTicketForUser or the one the user
// presented. The KDC must allow it: AD's msDS-AllowedToDelegateTo on this
// service (which then wants evidence forwardable), or
// msDS-AllowedToActOnBehalfOfOtherIdentity on the target (resource-based);
// MIT's DB2 back end refuses it. The ticket is not cached.
//
// A target in another realm is asked for as MS-SFU 3.1.5.2.2 has it, and
// MIT's client does: the client's KDC answers with a proxy TGT, a referral
// to the target's realm in the user's name; the request goes on to that
// realm with the client's own TGT for it and the proxy TGT as the evidence.
// Across an AD forest trust only resource-based delegation does this.
func (cl *Client) GetServiceTicketForProxy(spn string, evidence messages.Ticket) (messages.Ticket, types.EncryptionKey, error) {
	realm := cl.Credentials.Domain()
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	kdcRealm := realm

	for hops := 0; ; hops++ {
		tgt, skey, err := cl.sessionTGT(kdcRealm)
		if err != nil {
			return messages.Ticket{}, types.EncryptionKey{}, err
		}

		req, err := messages.NewS4U2ProxyReqAt(cl.Credentials.CName(), realm, kdcRealm, cl.Config, tgt, skey, sname, evidence, cl.Now())
		if err != nil {
			return messages.Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "failed to generate the S4U2Proxy TGS_REQ")
		}

		_, rep, err := cl.TGSExchange(req, kdcRealm, tgt, skey, 0)
		if err != nil {
			return messages.Ticket{}, types.EncryptionKey{}, err
		}

		names := rep.Ticket.SName.NameString
		if len(names) != 2 || names[0] != "krbtgt" || sname.Equal(rep.Ticket.SName) {
			return rep.Ticket, rep.DecryptedEncPart.Key, nil
		}

		// A proxy TGT, from a KDC that did resource-based delegation (else
		// it may be an ordinary referral, the client's, of no use here).
		next := names[1]
		if hops == 5 || next == kdcRealm || !rbcdDone(rep) {
			return messages.Ticket{}, types.EncryptionKey{}, krberror.NewErrorf(krberror.KRBMsgError,
				"S4U2Proxy: %s's KDC answered with %s, not a proxy TGT", kdcRealm, rep.Ticket.SName.PrincipalNameString())
		}

		cl.Log("S4U2Proxy: a proxy TGT from %s to %s", kdcRealm, next)
		evidence, kdcRealm = rep.Ticket, next
	}
}

// rbcdDone is whether a TGS reply says the KDC did resource-based
// constrained delegation (its PA-PAC-OPTIONS, in the encrypted part), as
// MIT's client checks of a proxy TGT.
func rbcdDone(rep messages.TGSRep) bool {
	for _, pa := range rep.DecryptedEncPart.EncPAData {
		if pa.PADataType != patype.PA_PAC_OPTIONS {
			continue
		}

		var o types.PAPACOptions
		if o.Unmarshal(pa.PADataValue) == nil && types.IsFlagSet(&o.Options, types.PACOptionResourceBasedConstrained) {
			return true
		}
	}

	return false
}
