package spnego

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/gssapi"
)

// Accept's negotiation-state logic, before any Kerberos token is processed, so
// no KDC is needed: a list without Kerberos is rejected, and Kerberos offered
// but not first (or first but with no optimistic token) gets accept-incomplete
// so the initiator continues with Kerberos.
func TestAccept_MechSelection(t *testing.T) {
	t.Parallel()

	tokenFor := func(n NegTokenInit) []byte {
		b, err := (&SPNEGOToken{Init: true, NegTokenInit: n}).Marshal()
		require.NoError(t, err)

		return b
	}

	krb5 := gssapi.OIDKRB5.OID()

	t.Run("no Kerberos offered", func(t *testing.T) {
		t.Parallel()

		ctx, out, err := Accept(tokenFor(NegTokenInit{MechTypes: []asn1.ObjectIdentifier{oidNTLM}}), nil, AcceptOptions{})
		require.Error(t, err)
		assert.Nil(t, ctx)

		var st SPNEGOToken
		require.NoError(t, st.Unmarshal(out))
		assert.Equal(t, NegStateReject, NegState(st.NegTokenResp.NegState))
	})

	t.Run("Kerberos not first", func(t *testing.T) {
		t.Parallel()

		ctx, out, err := Accept(tokenFor(NegTokenInit{MechTypes: []asn1.ObjectIdentifier{oidNTLM, krb5}}), nil, AcceptOptions{})
		require.NoError(t, err)
		require.NotNil(t, ctx)
		assert.False(t, ctx.Established())

		var st SPNEGOToken
		require.NoError(t, st.Unmarshal(out))
		assert.Equal(t, NegStateAcceptIncomplete, NegState(st.NegTokenResp.NegState))
		assert.True(t, st.NegTokenResp.SupportedMech.Equal(krb5))
	})

	t.Run("Kerberos first but no optimistic token", func(t *testing.T) {
		t.Parallel()

		ctx, out, err := Accept(tokenFor(NegTokenInit{MechTypes: []asn1.ObjectIdentifier{krb5}}), nil, AcceptOptions{})
		require.NoError(t, err)
		require.NotNil(t, ctx)
		assert.False(t, ctx.Established())

		var st SPNEGOToken
		require.NoError(t, st.Unmarshal(out))
		assert.Equal(t, NegStateAcceptIncomplete, NegState(st.NegTokenResp.NegState))
	})
}
