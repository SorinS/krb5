package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/keytab"
)

func TestAssumePreauthentication(t *testing.T) {
	t.Parallel()

	cl := NewWithKeytab("username", "REALM", &keytab.Keytab{}, &config.Config{}, AssumePreAuthentication(true))

	require.True(t, cl.settings.assumePreAuthentication)
	require.True(t, cl.settings.AssumePreAuthentication())
}
