// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/crypto/etype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/krberror"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pkinit"
	"github.com/go-krb5/krb5/types"
)

// Client side configuration and state.
type Client struct {
	Credentials *credentials.Credentials
	Config      *config.Config
	settings    *Settings
	sessions    *sessions
	cache       *Cache

	// The KDC's clock less ours, in nanoseconds, learned from the KDC
	// (kdc_timesync).
	timeOffset atomic.Int64

	// The realms whose KDCs said they do FAST: realm -> true.
	fastRealms sync.Map

	// PKINIT: the identity, or anonymous.
	pkinit    *pkinit.Identity
	anonymous bool
}

// Now returns the client's time: the local clock corrected by the offset
// learned from the KDC.
func (cl *Client) Now() time.Time {
	return time.Now().UTC().Add(time.Duration(cl.timeOffset.Load()))
}

// TimeOffset returns the KDC's clock less the local one, as the client has
// learned it from the KDC (zero until it does): a KRB_AP_ERR_SKEW error's
// time, or an AS reply's auth time, when kdc_timesync is on.
func (cl *Client) TimeOffset() time.Duration {
	return time.Duration(cl.timeOffset.Load())
}

// SetTimeOffset sets the KDC's clock less the local one (a credential
// cache's KDC time offset, say).
func (cl *Client) SetTimeOffset(d time.Duration) {
	cl.timeOffset.Store(int64(d))
}

// syncTime takes the KDC's time t (and usec microseconds) as now.
func (cl *Client) syncTime(t time.Time, usec int) {
	kdc := t.Add(time.Duration(usec) * time.Microsecond)
	d := kdc.Sub(time.Now())
	cl.timeOffset.Store(int64(d))
	cl.Log("clock offset from the KDC set to %v", d)
}

// NewWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewWithPassword(username, realm, password string, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		// The default realm, as the doc of NewWithPassword says (upstream issue 436).
		realm = krb5conf.LibDefaults.DefaultRealm
	}

	creds := credentials.New(username, realm)

	return &Client{
		Credentials: creds.WithPassword(password),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
}

// NewWithKeytab creates a new client from a keytab credential.
func NewWithKeytab(username, realm string, kt *keytab.Keytab, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		// The default realm, as the doc of NewWithPassword says (upstream issue 436).
		realm = krb5conf.LibDefaults.DefaultRealm
	}

	creds := credentials.New(username, realm)

	return &Client{
		Credentials: creds.WithKeytab(kt),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}
}

// NewFromCCache create a client from a populated client cache.
// The cache's KDC time offset, if it has one, becomes the client's.
//
// WARNING: A client created from CCache does not automatically renew TGTs and a failure will occur after the TGT expires.
func NewFromCCache(c *credentials.CCache, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	cl := &Client{
		Credentials: c.GetClientCredentials(),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache: NewCache(),
	}

	if d, ok := c.KDCOffset(); ok {
		cl.SetTimeOffset(d)
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", c.DefaultPrincipal.Realm},
	}

	cred, ok := c.GetEntry(spn)
	if !ok {
		return cl, errors.New("TGT not found in CCache")
	}

	var tgt messages.Ticket

	err := tgt.Unmarshal(cred.Ticket)
	if err != nil {
		return cl, fmt.Errorf("TGT bytes in cache are not valid: %w", err)
	}

	cl.sessions.Entries[c.DefaultPrincipal.Realm] = &session{
		realm:      c.DefaultPrincipal.Realm,
		authTime:   cred.AuthTime,
		startTime:  cred.StartTime,
		flags:      cred.TicketFlags,
		endTime:    cred.EndTime,
		renewTill:  cred.RenewTill,
		tgt:        tgt,
		sessionKey: cred.Key,
	}
	for _, cred := range c.GetEntries() {
		var tkt messages.Ticket

		err = tkt.Unmarshal(cred.Ticket)
		if err != nil {
			return cl, fmt.Errorf("cache entry ticket bytes are not valid: %w", err)
		}

		cl.cache.addEntry(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.TicketFlags,
			cred.Key,
		)
	}

	return cl, nil
}

// CCache returns a credential cache (MIT's FILE format, version 4) with the
// client's TGTs, its own realm's first, and its service tickets, the KDC
// time offset the client has learned in its header: what MIT's kinit and
// kvno would leave, for MIT's and Heimdal's tools, or NewFromCCache, to use.
func (cl *Client) CCache() (*credentials.CCache, error) {
	client := credentials.Principal{Realm: cl.Credentials.Domain(), PrincipalName: cl.Credentials.CName()}
	c := credentials.NewV4CCache(client.PrincipalName, client.Realm)

	if d := cl.TimeOffset(); d != 0 {
		c.SetKDCOffset(d)
	}

	cred := func(tkt messages.Ticket, key types.EncryptionKey, flags asn1.BitString, auth, start, end, renew time.Time) error {
		b, err := tkt.Marshal()
		if err != nil {
			return err
		}

		c.AddCredential(&credentials.Credential{
			Client:      client,
			Server:      credentials.Principal{Realm: tkt.Realm, PrincipalName: tkt.SName},
			Key:         key,
			AuthTime:    auth,
			StartTime:   start,
			EndTime:     end,
			RenewTill:   renew,
			TicketFlags: flags,
			Ticket:      b,
		})

		return nil
	}

	cl.sessions.mux.RLock()
	realms := make([]string, 0, len(cl.sessions.Entries))

	for r := range cl.sessions.Entries {
		realms = append(realms, r)
	}

	cl.sessions.mux.RUnlock()
	sort.Slice(realms, func(i, j int) bool {
		if realms[i] == client.Realm || realms[j] == client.Realm {
			return realms[i] == client.Realm && realms[j] != client.Realm
		}

		return realms[i] < realms[j]
	})

	for _, r := range realms {
		s, ok := cl.sessions.get(r)
		if !ok {
			continue
		}

		s.mux.RLock()
		err := cred(s.tgt, s.sessionKey, s.flags, s.authTime, s.startTime, s.endTime, s.renewTill)
		s.mux.RUnlock()

		if err != nil {
			return nil, fmt.Errorf("TGT for %s: %w", r, err)
		}
	}

	cl.cache.mux.RLock()
	defer cl.cache.mux.RUnlock()

	spns := make([]string, 0, len(cl.cache.Entries))
	for spn := range cl.cache.Entries {
		spns = append(spns, spn)
	}

	sort.Strings(spns)

	for _, spn := range spns {
		e := cl.cache.Entries[spn]
		if err := cred(e.Ticket, e.SessionKey, e.Flags, e.AuthTime, e.StartTime, e.EndTime, e.RenewTill); err != nil {
			return nil, fmt.Errorf("ticket for %s: %w", spn, err)
		}
	}

	return c, nil
}

// SaveCCache writes the client's credential cache (CCache) to the file
// path ("FILE:" prefix taken), mode 0600.
func (cl *Client) SaveCCache(path string) error {
	c, err := cl.CCache()
	if err != nil {
		return err
	}

	return c.Save(path)
}

// Key returns the client's encryption key for the specified encryption type and its kvno (kvno of zero will find latest).
// The key can be retrieved either from the keytab or generated from the client's password.
// If the client has both a keytab and a password defined the keytab is favoured as the source for the key
// A KRBError can be passed in the event the KDC returns one of type KDC_ERR_PREAUTH_REQUIRED and is required to derive
// the key for pre-authentication from the client's password. If a KRBError is not available, pass nil to this argument.
func (cl *Client) Key(etype etype.EType, kvno int, krberr *messages.KRBError) (types.EncryptionKey, int, error) {
	if cl.Credentials.HasKeytab() && etype != nil {
		return cl.Credentials.Keytab().GetEncryptionKey(cl.Credentials.CName(), cl.Credentials.Domain(), kvno, etype.GetETypeID())
	} else if cl.Credentials.HasPassword() {
		if krberr != nil && krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED {
			var pas types.PADataSequence

			err := pas.Unmarshal(krberr.EData)
			if err != nil {
				return types.EncryptionKey{}, 0, fmt.Errorf("could not get PAData from KRBError to generate key from password: %w", err)
			}

			key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), krberr.CName, krberr.CRealm, etype.GetETypeID(), pas)

			return key, 0, err
		}

		key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), cl.Credentials.CName(), cl.Credentials.Domain(), etype.GetETypeID(), types.PADataSequence{})

		return key, 0, err
	}

	return types.EncryptionKey{}, 0, errors.New("credential has neither keytab or password to generate key")
}

// IsConfigured indicates if the client has the values required set.
func (cl *Client) IsConfigured() (bool, error) {
	if cl.Config == nil {
		return false, errors.New("client has no krb5 configuration")
	}

	if cl.Credentials.UserName() == "" {
		return false, errors.New("client does not have a username")
	}

	if cl.Credentials.Domain() == "" {
		return false, errors.New("client does not have a define realm")
	}
	// Client needs to have either a password, keytab or a session already (later when loading from CCache).
	if !cl.hasSecret() {
		authTime, _, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil || authTime.IsZero() {
			return false, errors.New("client has neither a keytab nor a password set and no session")
		}
	}

	if !cl.Config.LibDefaults.DNSLookupKDC {
		for _, r := range cl.Config.Realms {
			if r.Realm == cl.Credentials.Domain() {
				if len(r.KDC) > 0 {
					return true, nil
				}

				return false, errors.New("client krb5 config does not have any defined KDCs for the default realm")
			}
		}
	}

	return true, nil
}

// Login the client with the KDC via an AS exchange.
func (cl *Client) Login() error {
	if ok, err := cl.IsConfigured(); !ok {
		return err
	}

	if !cl.hasSecret() {
		_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "no user credentials available and error getting any existing session")
		}

		if cl.Now().After(endTime) {
			return krberror.New(krberror.KRBMsgError, "cannot login, no user credentials available and no valid existing session")
		}
		// no credentials but there is a session with tgt already.
		return nil
	}

	ASReq, err := messages.NewASReqForTGTAt(cl.Credentials.Domain(), cl.Config, cl.clientName(), cl.Now())
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ")
	}

	if cl.anonymous {
		types.SetFlag(&ASReq.ReqBody.KDCOptions, flags.KDCOptionRequestAnonymous)
	}

	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return err
	}

	cl.addSession(ASRep.Ticket, ASRep.DecryptedEncPart)

	return nil
}

// AffirmLogin will only perform an AS exchange with the KDC if the client does not already have a TGT.
func (cl *Client) AffirmLogin() (err error) {
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || cl.Now().After(endTime) {
		if err = cl.Login(); err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %w", err)
		}
	}

	return nil
}

// realmLogin obtains or renews a TGT and establishes a session for the realm specified.
func (cl *Client) realmLogin(realm string) (err error) {
	if realm == cl.Credentials.Domain() {
		return cl.Login()
	}

	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || cl.Now().After(endTime) {
		if err = cl.Login(); err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %w", err)
		}
	}

	tgt, skey, err := cl.sessionTGT(cl.Credentials.Domain())
	if err != nil {
		return err
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, false)
	if err != nil {
		return err
	}

	cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	return nil
}

// Destroy stops the auto-renewal of all sessions and removes the sessions and cache entries from the client.
func (cl *Client) Destroy() {
	creds := credentials.New("", "")

	cl.sessions.destroy()
	cl.cache.clear()
	cl.Credentials = creds
	cl.Log("client destroyed")
}

// Diagnostics runs a set of checks that the client is properly configured and writes details to the io.Writer provided.
func (cl *Client) Diagnostics(w io.Writer) error {
	cl.Print(w)

	var errs []string

	if cl.Credentials.HasKeytab() {
		var loginRealmEncTypes []int32

		for _, e := range cl.Credentials.Keytab().Entries {
			if e.Principal.Realm == cl.Credentials.Realm() {
				loginRealmEncTypes = append(loginRealmEncTypes, e.Key.KeyType)
			}
		}

		for _, et := range cl.Config.LibDefaults.DefaultTktEnctypeIDs {
			var etInKt bool

			for _, val := range loginRealmEncTypes {
				if val == et {
					etInKt = true
					break
				}
			}

			if !etInKt {
				errs = append(errs, fmt.Sprintf("default_tkt_enctypes specifies %d but this enctype is not available in the client's keytab", et))
			}
		}

		for _, et := range cl.Config.LibDefaults.PreferredPreauthTypes {
			var etInKt bool

			for _, val := range loginRealmEncTypes {
				if int(val) == et {
					etInKt = true
					break
				}
			}

			if !etInKt {
				errs = append(errs, fmt.Sprintf("preferred_preauth_types specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
	}

	udpCnt, udpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for UDP communication: %v", err))
	}

	if udpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via UDP.")
	} else {
		b, _ := json.MarshalIndent(&udpKDC, "", "  ")
		fmt.Fprintf(w, "UDP KDCs: %s\n", string(b))
	}

	tcpCnt, tcpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for TCP communication: %v", err))
	}

	if tcpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via TCP.")
	} else {
		b, _ := json.MarshalIndent(&tcpKDC, "", "  ")
		fmt.Fprintf(w, "TCP KDCs: %s\n", string(b))
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}

	return nil
}

// Print writes the details of the client to the io.Writer provided.
func (cl *Client) Print(w io.Writer) {
	c, _ := cl.Credentials.JSON()
	fmt.Fprintf(w, "Credentials:\n%s\n", c)

	s, _ := cl.sessions.JSON()
	fmt.Fprintf(w, "TGT Sessions:\n%s\n", s)

	c, _ = cl.cache.JSON()
	fmt.Fprintf(w, "Service ticket cache:\n%s\n", c)

	s, _ = cl.settings.JSON()
	fmt.Fprintf(w, "Settings:\n%s\n", s)

	j, _ := cl.Config.JSON()
	fmt.Fprintf(w, "Krb5 config:\n%s\n", j)

	k, _ := cl.Credentials.Keytab().JSON()
	fmt.Fprintf(w, "Keytab:\n%s\n", k)
}
