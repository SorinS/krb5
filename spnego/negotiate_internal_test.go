package spnego

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/x/encoding/asn1"
)

// Continue must establish the context only on accept-completed, and must
// refuse an acceptor that selects a mechanism we did not offer. These states
// never reach the GSS context (a reject errors first, and the other states do
// not complete), so no KDC or key is needed: the Context carries a nil GSS
// context and must not be touched.
func TestContinue_StateGate(t *testing.T) {
	t.Parallel()

	resp := func(n NegTokenResp) []byte {
		b, err := respToken(n)
		require.NoError(t, err)

		return b
	}

	t.Run("reject errors", func(t *testing.T) {
		t.Parallel()

		c := &Context{initiator: true}

		_, err := c.Continue(resp(NegTokenResp{NegState: asn1.Enumerated(NegStateReject)}))
		require.Error(t, err)
		assert.False(t, c.Established())
	})

	t.Run("accept-incomplete does not establish", func(t *testing.T) {
		t.Parallel()

		c := &Context{initiator: true}

		out, err := c.Continue(resp(NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptIncomplete)}))
		require.NoError(t, err)
		assert.Nil(t, out)
		assert.False(t, c.Established(), "an incomplete state must not establish the context")
	})

	t.Run("request-mic does not establish", func(t *testing.T) {
		t.Parallel()

		c := &Context{initiator: true}

		_, err := c.Continue(resp(NegTokenResp{NegState: asn1.Enumerated(NegStateRequestMIC)}))
		require.NoError(t, err)
		assert.False(t, c.Established())
	})

	t.Run("a non-Kerberos selected mechanism is refused", func(t *testing.T) {
		t.Parallel()

		c := &Context{initiator: true}

		_, err := c.Continue(resp(NegTokenResp{
			NegState:      asn1.Enumerated(NegStateAcceptIncomplete),
			SupportedMech: oidNTLM,
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-Kerberos")
	})
}
