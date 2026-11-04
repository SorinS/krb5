package client

import (
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/pkinit"
	"github.com/go-krb5/krb5/types"
)

// AnonymousName is the anonymous principal's name, WELLKNOWN/ANONYMOUS
// (RFC 8062), and AnonymousRealm the realm an anonymous ticket's client is
// in.
const (
	AnonymousName  = "WELLKNOWN/ANONYMOUS"
	AnonymousRealm = "WELLKNOWN:ANONYMOUS"
)

// NewWithPKINIT creates a client that logs in with PKINIT (RFC 4556): the
// identity's certificate and key in place of a password. The KDC's
// certificate is checked as krb5.conf says (pkinit_anchors, pkinit_pool,
// pkinit_kdc_hostname, pkinit_eku_checking); the Diffie-Hellman group is
// pkinit_dh_min_bits' (2048 by default).
func NewWithPKINIT(username, realm string, id *pkinit.Identity, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}

	return &Client{
		Credentials: credentials.New(username, realm),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions:    &sessions{Entries: make(map[string]*session)},
		cache:       NewCache(),
		pkinit:      id,
	}
}

// NewAnonymous creates a client that logs in anonymously to the realm
// (anonymous PKINIT, RFC 8062; MIT's kinit -n): its TGT names
// WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS, and serves as a FAST armor
// (Client.Armor) when no host TGT is at hand.
func NewAnonymous(realm string, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}

	return &Client{
		Credentials: credentials.New(AnonymousName, realm),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions:    &sessions{Entries: make(map[string]*session)},
		cache:       NewCache(),
		anonymous:   true,
	}
}

// hasSecret is whether the client can log in by itself: a password, a
// keytab, a PKINIT identity, or anonymously.
func (cl *Client) hasSecret() bool {
	return cl.Credentials.HasPassword() || cl.Credentials.HasKeytab() || cl.pkinit != nil || cl.anonymous
}

// clientName is the name the client logs in with: the anonymous one's
// type is NT-WELLKNOWN.
func (cl *Client) clientName() types.PrincipalName {
	if cl.anonymous {
		return types.NewPrincipalName(nametype.KRB_NT_WELLKNOWN, AnonymousName)
	}

	return cl.Credentials.CName()
}
