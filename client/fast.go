package client

import (
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// FASTArmor makes the client armor its AS exchanges with FAST (RFC 6113),
// the armor made from a, a TGT for the client's realm (krbtgt/REALM@REALM):
// a host's, say, as MIT's kinit -T takes it from a cache (ArmorFromCCache),
// or a machine account's (Client.Armor). Every request is armored, the
// first too, and a reply or error that is not is refused, so nothing in the
// clear can turn FAST off. With FAST the KDC can offer encrypted challenge
// (no password guessing from a captured request) and the reply key is
// strengthened.
//
// s := NewSettings(FASTArmor(armor)).
func FASTArmor(a messages.Armor) func(*Settings) {
	return func(s *Settings) {
		s.armor = &a
	}
}

// FASTDeviceArmor makes the client armor its TGS requests explicitly with
// a, a device's TGT for the realm (Active Directory's computer account), as
// well as with the TGT the request is made with (RFC 6113 5.4.1.1). Active
// Directory then puts the device's groups and claims in the service
// ticket's PAC (compound identity, MS-KILE 3.3.5.7.4) when the service
// account allows it. MIT's KDC refuses explicit TGS armor.
func FASTDeviceArmor(a messages.Armor) func(*Settings) {
	return func(s *Settings) {
		s.deviceArmor = &a
	}
}

// Armor is the client's TGT for its realm as an armor for another client
// (a user's login armored by the machine's TGT).
func (cl *Client) Armor() (messages.Armor, error) {
	if err := cl.AffirmLogin(); err != nil {
		return messages.Armor{}, err
	}

	tgt, key, err := cl.sessionTGT(cl.Credentials.Domain())
	if err != nil {
		return messages.Armor{}, err
	}

	return messages.Armor{Ticket: tgt, SessionKey: key, CName: cl.Credentials.CName(), CRealm: cl.Credentials.Domain()}, nil
}

// ArmorFromCCache is the cache's TGT for the realm as an armor (MIT's
// kinit -T cache).
func ArmorFromCCache(c *credentials.CCache, realm string) (messages.Armor, error) {
	tgtName := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", realm}}

	cred, ok := c.GetEntry(tgtName)
	if !ok || cred.Server.Realm != realm {
		return messages.Armor{}, fmt.Errorf("no TGT for %s in the cache", realm)
	}

	var tkt messages.Ticket
	if err := tkt.Unmarshal(cred.Ticket); err != nil {
		return messages.Armor{}, err
	}

	return messages.Armor{Ticket: tkt, SessionKey: cred.Key, CName: cred.Client.PrincipalName, CRealm: cred.Client.Realm}, nil
}

// armorFor is the AS armor for realm, if the client has one: an armor for
// another realm (a referral's) cannot armor its requests.
func (cl *Client) armorFor(realm string) (*messages.Armor, error) {
	a := cl.settings.armor
	if a == nil {
		return nil, nil
	}

	s := a.Ticket.SName
	if len(s.NameString) != 2 || s.NameString[0] != "krbtgt" || s.NameString[1] != realm || a.Ticket.Realm != realm {
		return nil, fmt.Errorf("the FAST armor is not a TGT for %s", realm)
	}

	return a, nil
}

// fastAvailable is whether the realm's KDC said it does FAST (PA-FX-FAST
// in an AS reply's encrypted padata, MIT's fast_avail): its TGS requests
// are then armored.
func (cl *Client) fastAvailable(realm string) bool {
	_, ok := cl.fastRealms.Load(realm)
	return ok
}

func (cl *Client) setFASTAvailable(realm string) {
	cl.fastRealms.Store(realm, true)
}

// errFASTRequired is an exchange that must be armored getting an
// unarmored error or reply.
var errFASTRequired = errors.New("FAST: the KDC's answer is not armored")
