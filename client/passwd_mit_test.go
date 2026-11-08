package client_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/test"
	"github.com/SorinS/krb5/types"
)

// A.TEST's kadmind (test/mitkdc) serves kpasswd. ChangePasswd changes a
// principal's own password (RFC 3244 version 1, no target), which a KDC
// accepts without reset rights; SetPasswd resets another's (the set-password
// form), which needs the privilege. Both do a live round trip to kadmind;
// each test restores the password it changed so a rerun against a long-lived
// TEST_MIT_DIR starts from the same state.

// TestClient_ChangePasswd_MIT: chpw changes its own password, logs in with the
// new one (and not the old), then changes it back.
func TestClient_ChangePasswd_MIT(t *testing.T) {
	cfg := mitConfig(t, test.MIT(t))

	const (
		old = "chpw-pw"
		nw  = "chpw-new-pw"
	)

	cl := client.NewWithPassword("chpw", "A.TEST", old, cfg)

	ok, err := cl.ChangePasswd(nw)
	require.NoError(t, err)
	require.True(t, ok)

	t.Cleanup(func() {
		back := client.NewWithPassword("chpw", "A.TEST", nw, cfg)
		if _, err := back.ChangePasswd(old); err != nil {
			t.Errorf("restoring chpw's password: %v", err)
		}
	})

	// The new password logs in; the old one no longer does.
	require.NoError(t, client.NewWithPassword("chpw", "A.TEST", nw, cfg).Login())
	require.Error(t, client.NewWithPassword("chpw", "A.TEST", old, cfg).Login(), "old password still works")
}

// TestClient_SetPasswd_MIT: chpw-admin resets chpw-target's password (the ACL
// grants it), chpw-target logs in with the new one, then it is reset back. A
// principal without the right (chpw) is refused with KRB5_KPASSWD_ACCESSDENIED.
func TestClient_SetPasswd_MIT(t *testing.T) {
	cfg := mitConfig(t, test.MIT(t))

	const (
		old = "chpw-target-pw"
		nw  = "chpw-target-new-pw"
	)

	target := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "chpw-target")

	admin := client.NewWithPassword("chpw-admin", "A.TEST", "chpw-admin-pw", cfg)

	ok, err := admin.SetPasswd(target, "A.TEST", nw)
	require.NoError(t, err)
	require.True(t, ok)

	t.Cleanup(func() {
		back := client.NewWithPassword("chpw-admin", "A.TEST", "chpw-admin-pw", cfg)
		if _, err := back.SetPasswd(target, "A.TEST", old); err != nil {
			t.Errorf("restoring chpw-target's password: %v", err)
		}
	})

	require.NoError(t, client.NewWithPassword("chpw-target", "A.TEST", nw, cfg).Login())

	// chpw holds no reset right over chpw-target: the KDC refuses it.
	denier := client.NewWithPassword("chpw", "A.TEST", "chpw-pw", cfg)

	_, err = denier.SetPasswd(target, "A.TEST", "should-not-apply")
	require.Error(t, err, "a reset without the privilege must fail")
	assert.Contains(t, err.Error(), "code: 5", "expected KRB5_KPASSWD_ACCESSDENIED")

	// The refused reset did not take: the original new password still works.
	require.NoError(t, client.NewWithPassword("chpw-target", "A.TEST", nw, cfg).Login())
	require.Error(t, client.NewWithPassword("chpw-target", "A.TEST", "should-not-apply", cfg).Login())
}
