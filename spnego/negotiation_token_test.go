package spnego

import (
	"testing"

	"github.com/go-krb5/x/encoding/asn1"
	"github.com/stretchr/testify/assert"

	"github.com/SorinS/krb5/gssapi"
	"github.com/SorinS/krb5/keytab"
)

var (
	oidKRB5   = gssapi.OIDKRB5.OID()
	oidLegacy = gssapi.OIDMSLegacyKRB5.OID()
	oidNTLM   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	oidNEGOEX = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 30}
)

func TestMechTypePreferred(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mechs         []asn1.ObjectIdentifier
		offered, pref bool
	}{
		{"krb5 only", []asn1.ObjectIdentifier{oidKRB5}, true, true},
		{"krb5 first", []asn1.ObjectIdentifier{oidKRB5, oidNTLM}, true, true},
		{"krb5 after negoex", []asn1.ObjectIdentifier{oidNEGOEX, oidNTLM, oidKRB5}, true, false},
		{"legacy krb5 first", []asn1.ObjectIdentifier{oidLegacy, oidNTLM}, true, true},
		{"no krb5", []asn1.ObjectIdentifier{oidNEGOEX, oidNTLM}, false, false},
		{"empty", nil, false, false},
	} {
		offered, pref := mechTypePreferred(tc.mechs)
		assert.Equal(t, tc.offered, offered, "%s: offered", tc.name)
		assert.Equal(t, tc.pref, pref, "%s: preferred", tc.name)
	}
}

// When KRB5 is offered but not first, the acceptor answers accept-incomplete
// (ContinueNeeded) instead of rejecting, and does not read the optimistic
// token (which belongs to the first mechanism). It still rejects a list with
// no KRB5 at all.
func TestAcceptSecContext_MechSelection(t *testing.T) {
	svc := SPNEGOService(keytab.New())

	for _, tc := range []struct {
		name string
		init NegTokenInit
		want int
	}{
		{
			"krb5 not first, with a foreign optimistic token",
			NegTokenInit{MechTypes: []asn1.ObjectIdentifier{oidNEGOEX, oidNTLM, oidKRB5}, MechTokenBytes: []byte{0x01, 0x02, 0x03}},
			gssapi.StatusContinueNeeded,
		},
		{
			"krb5 first but no token",
			NegTokenInit{MechTypes: []asn1.ObjectIdentifier{oidKRB5}},
			gssapi.StatusContinueNeeded,
		},
		{
			"no krb5 offered",
			NegTokenInit{MechTypes: []asn1.ObjectIdentifier{oidNEGOEX, oidNTLM}},
			gssapi.StatusBadMech,
		},
		{
			"no mechanisms",
			NegTokenInit{},
			gssapi.StatusDefectiveToken,
		},
	} {
		ct := &SPNEGOToken{Init: true, NegTokenInit: tc.init}
		ok, _, st := svc.AcceptSecContext(ct)
		assert.False(t, ok, tc.name)
		assert.Equal(t, tc.want, st.Code, "%s: %s", tc.name, st.Message)
	}
}
