# Changelog

What this fork (`github.com/SorinS/krb5`, SorinS/krb5) adds to
`github.com/jcmturner/gokrb5/v8`. Behaviour changes are spelled out in
[BREAKING.md](BREAKING.md); how to run the tests is in
[test/README.md](test/README.md).

## Unreleased: branch `dev1`, second round (2026-11-04)

FAST, SPAKE and PKINIT pre-authentication, then S4U, KKDCP, and the leftovers
from the upstream (jcmturner/gokrb5) triage. Pure Go; the curve arithmetic SPAKE
needs comes from filippo.io/edwards25519 and filippo.io/nistec (pure Go, no
cgo).

### Added

- **PRF, PRF+ and KRB-FX-CF2** for all eight encryption types
  (`crypto.PRF`, `PRFPlus`, `CF2`, `RandomKey`), checked against MIT
  libk5crypto's outputs (`crypto/testdata/mit_crypto.txt`, also its
  string-to-key, checksums and ciphertexts).
- **FAST** (RFC 6113): `client.FASTArmor` armors AS exchanges with a TGT
  (`Client.Armor`, `ArmorFromCCache` for MIT's `kinit -T` caches); every
  request armored, errors read from inside the armor, encrypted challenge
  when the KDC offers it (with the KDC's challenge checked), the reply key
  strengthened, the reply's finished part checked. TGS requests are armored
  implicitly when the KDC does FAST, and explicitly with
  `client.FASTDeviceArmor` (AD compound identity: the device's info and
  claims in the PAC). Tested against MIT 1.22 (F.TEST: no encrypted
  timestamp; MIT's kinit with our armor cache and ours with its) and the
  live AD (goosepc$ as the device).
- **SPAKE pre-authentication** (draft-ietf-kitten-krb-spake-preauth, MIT
  1.17+): package `spake` (the four groups edwards25519, P-256, P-384,
  P-521; constant-time point arithmetic from filippo.io/edwards25519 and
  filippo.io/nistec), used by the AS exchange whenever the KDC offers it:
  support message, the KDC's challenge (optimistic too), the response with
  SF-NONE, the reply key K'[0]; inside FAST as well. krb5.conf's
  `spake_preauth_groups` picks the groups (edwards25519 by default, as MIT).
  All of the draft's Appendix C vectors pass (but its SHA-1 group -1, which
  MIT leaves out too); tested against MIT 1.22's S.TEST (every group, every
  encryption type, no encrypted timestamp) and O.TEST (optimistic
  challenge, fallback to the timestamp when no group is in common).
- **PKINIT** (RFC 4556): package `pkinit` and `client.NewWithPKINIT`: a TGT
  from a certificate and its key (RSA, ECDSA, Ed25519; `LoadIdentity` reads
  MIT's `FILE:cert[,key]`), the reply key by Diffie-Hellman in MODP 2048 or
  4096 or P-256/384/521 (`pkinit_dh_min_bits`; the KDC's TD-DH-PARAMETERS
  followed when it refuses ours), RFC 8636's KDFs (and RFC 4556's
  octetstring2key), freshness tokens (RFC 8070). The KDC's certificate is
  checked as MIT does: `pkinit_anchors`, `pkinit_pool`, its id-pkinit-san,
  or `pkinit_kdc_hostname` with `pkinit_eku_checking`. A small CMS
  SignedData (sign, verify) of its own, checked against OpenSSL both ways.
  RFC 4556's and RFC 8636's vectors pass; tested against MIT 1.22's P.TEST,
  Q.TEST (4096-bit groups, freshness required), R.TEST (KDC named by host),
  N.TEST.
- **Anonymous PKINIT** (RFC 8062): `client.NewAnonymous` (MIT's `kinit -n`),
  the KDC's PA-PKINIT-KX checked; its TGT armors FAST (a password login
  armored by an anonymous TGT, tested against MIT).
- **S4U** (MS-SFU): `Client.GetServiceTicketForUser` (S4U2Self: PA-FOR-USER
  and PA-S4U-X509-USER, the KDC's echo checked) and
  `Client.GetServiceTicketForProxy` (S4U2Proxy: constrained and
  resource-based delegation), armored when the KDC does FAST. The tickets
  stay out of the client's cache. Tested against the live AD (protocol
  transition, Kerberos-only delegation, resource-based, a target not
  allowed, a sensitive user; the target decrypts the ticket and reads
  alice's PAC and the delegation info) and MIT 1.22 (S4U2Self, PA-FOR-USER
  alone; its DB2 back end refuses S4U2Proxy).
- **Cross-realm S4U:** S4U2Self for a user of another realm (the request goes
  to the user's realm first, naming the service as an enterprise principal,
  and follows the referral back, as Windows and MIT's client do), and
  S4U2Proxy to a target of another realm (MS-SFU 3.1.5.2.2: the proxy TGT the
  service's KDC answers with is the evidence for the target's realm, asked
  with the service's own TGT there). Neither referral is cached as the
  service's own. Tested both ways across two live AD forests with a two-way
  trust (resource-based delegation, the only kind across a trust).
- **S4U2Self by certificate:** `Client.GetServiceTicketForCertificate`: the
  KDC finds the user, the reply's checksummed echo says who it is (required
  here). RSA certificates tested, on the live AD with `altSecurityIdentities`
  (X509:<SKI>), through to S4U2Proxy; MIT's DB2 cannot map one, so MIT is a
  negative test. Windows' KDC took an expired certificate of an unknown CA: the
  caller must validate it. Ed25519 certificates are refused.
- `examples`: a program for each thing a caller does (a TGT, a service ticket,
  a credential cache, cross-realm, S4U2Self, constrained delegation through to
  the back end, SPNEGO server and client, GSS-API on a socket, LDAP, FAST,
  PKINIT, keytabs), run against MIT's and AD's KDCs by `examples_test.go`.
- `test/mitkdc`: B.TEST (a two-way trust with A.TEST), F.TEST (FAST only), S.TEST and O.TEST (SPAKE), P/Q/R/N.TEST
  (PKINIT, certificates from `test/mitkdc/pki.py` with OpenSSL).
- `test/ad` (was `test/windows`): a bare Windows Server to a DC with every
  account the `*_AD` tests use: a README with the walkthrough and which test
  needs what, `provision.sh` to run the scripts over ssh, `verify.ps1` to check
  the result. `docs`: the KDC setup, the first round's notes, the upstream
  triage.
- `config.LibDefaults.Values`: the libdefaults relations without a field.

### Security

- `Ticket.Marshal` wrote a decrypted ticket's `DecryptedEncPart` (its session
  key and PAC) after the ticket, in the clear, whenever the ticket was sent
  on after being decrypted. Found by S4U2Proxy: AD gave an empty reply, MIT
  ignored the extra field.

### Fixed

- SPNEGO HTTP client: the redirect count is kept per `Do` call, not on the
  shared `Client` (concurrent `Do` calls raced on it); the limit is
  configurable (`Client.MaxRedirects`, default 10); and `setRequestSPN` no
  longer overwrites the request's `Host` header with the canonical name,
  which broke a virtual host behind a proxy (the canonical name is used for
  the SPN only).
- SPNEGO acceptor: KRB5 need not be the first mechanism offered. Windows
  lists NEGOEX or NTLM first; the acceptor now answers accept-incomplete
  (so the client continues with KRB5) instead of rejecting the token, as
  long as KRB5 is somewhere in the list. The optimistic token of a
  non-preferred first mechanism is no longer misread as KRB5.
- SPNEGO negotiation as a programmatic initiator and acceptor
  (`spnego.NewInitiator`, `spnego.Accept`, with `(*spnego.Context).Continue`),
  built on the Kerberos GSS context (gsskrb5). Unlike the stateless HTTP
  handler (`SPNEGOKRB5Authenticate`, unchanged), these carry the AP-REP for
  mutual authentication and exchange a mechListMIC (RFC 4178 section 5): the
  acceptor verifies the initiator's and sends its own when more than Kerberos
  was offered, and the initiator verifies the acceptor's and reciprocates.
  Tested against MIT both ways — our initiator to MIT's gss-server and MIT's
  gss-client -spnego to our acceptor, with mutual authentication and the MIC
  round trip, and MIT rejecting a corrupted MIC. A lone optimistic Kerberos
  offer uses no mechListMIC, as MIT does; the Windows NEGOEX-first path (where
  the initiator continues with Kerberos in a later leg) is not yet driven to
  completion and is unverified against Windows.
- **KKDCP** (MS-KKDCP, Kerberos over HTTPS): a KDC written in krb5.conf as an
  `https://` URL (`kdc = https://proxy.example.com/KdcProxy`) is a KDC proxy —
  the AS and TGS requests are wrapped in a KDC-PROXY-MESSAGE and POSTed over
  HTTPS, with the realm's `http_anchors` as the trusted roots (the system
  roots with none). Tested against MIT's A.TEST through a local HTTPS proxy
  that relays to the real KDC: an AS and a TGS exchange end to end, the wire
  format cross-checked by an independent decoder, and an untrusted proxy
  certificate refused. kpasswd over the proxy is not done.
- `Client.ChangePasswd` now uses the kpasswd change-password form (version 1,
  no target principal), which a KDC accepts from the user itself; it sent the
  set-password (reset) form before, which Active Directory refused without
  the reset right. `Client.SetPasswd` is the reset form, for an administrator
  changing another principal's password (`kadmin.SetPasswdMsg`). Both are
  tested live against a kadmind (test/mitkdc now runs one), including a reset
  refused without the privilege.
- aes256-cts-hmac-sha384-192 keys are 32 bytes (were 24).
- RC4: usage 9, usages of 128 and up, passwords outside the BMP (MIT's
  vectors).
- A krb5.conf realm with a nested block panicked the parser.
- A PAC with an empty device claims set was an error, and its logging
  panicked with no logger.
- `flags.RequestAnonymous` (12) is not the request-anonymous KDC option:
  `flags.KDCOptionRequestAnonymous` (16) and the ticket flag
  `flags.Anonymous` (16, as MIT sets it) are added; `nametype.KRB_NT_WELLKNOWN`.
- The SHA-2 types (aes256-cts-hmac-sha384-192, aes128-cts-hmac-sha256-128)
  were missing from the default enctype lists, and `default_tkt_enctypes`
  and `default_tgs_enctypes` did not default to `permitted_enctypes` as in
  MIT: a user with SHA-2 keys only could not log in by default.

## Unreleased: first round (2026-11-03)

Branched from `camellia128-cts-cmac` (7e3cb81). Pure Go throughout: no cgo,
MIT's and Windows' tools are used as test oracles only.

### Added

- **PAC signatures:** the KDC signature, the ticket checksum and the full
  PAC checksum (`pac.VerifyKDCSignature`, `VerifyTicketChecksum`,
  `VerifyFullChecksum`, `Ticket.VerifyPACKDC` given the krbtgt key), and
  the client info checked against the ticket. Verified on MIT 1.22 tickets;
  on AD only the server signature and client info (AD's krbtgt key is not
  available).
- **Compressed PAC claims:** package `pac/xpress` (MS-XCA LZ77+Huffman and
  plain LZ77), used by the client and device claims buffers. Tested with 412
  vectors from Windows' `RtlCompressBuffer` and live AD claims.
- **PA-PAC-OPTIONS** (claims bit) in every AS and TGS request: AD sends no
  claims without it.
- **Clock skew learned from the KDC** (`kdc_timesync`, as MIT): from a
  KRB_AP_ERR_SKEW error's time and the AS reply's authtime, with one retry;
  `Client.Now`, `TimeOffset`, `SetTimeOffset`; the offset is saved in and
  read from credential caches.
- **Writing credential caches** (MIT FILE v4): `CCache.Marshal`, `Save`
  (mode 0600, by rename), `NewV4CCache`, `AddCredential`, config entries,
  the KDC offset tag; `Client.CCache`, `SaveCCache`. Read by MIT's klist and
  kvno and Heimdal's klist.
- **Camellia in constant time:** F's S-boxes as the AES S-box circuit
  (Boyar–Peralta) on bit planes, CMAC subkeys by masks. About 4x slower than
  the table version (47 ns against 12 ns per round function).
- **GSS-API outside SPNEGO:** package `gsskrb5` (RFC 4121): initiator and
  acceptor contexts, mutual authentication, channel bindings, `GetMIC`,
  `VerifyMIC`, `Wrap`, `Unwrap`; credential delegation (KRB-CRED in the
  authenticator, `Delegated()` as a CCache); `Client.GetForwardedTGT`.
  Interoperates with MIT's gss-client and gss-server both ways.
- **SASL GSSAPI** (RFC 4752) with no layer, integrity or confidentiality
  (`gsskrb5.SASL`, which fits go-ldap's `GSSAPIClient`), and package `ldap`:
  a small LDAPv3 client with `BindGSSAPI`, `Search`, `WhoAmI`,
  `DefaultNamingContext`, and AD's `LookupSID` and `TokenGroups`.
- `messages`: `NewAPRep`/`APRep.Marshal`, `NewKRBCred`/`KRBCred.Marshal`,
  the `*At` request constructors.
- `config`: `include` and `includedir`, one-line realms, MIT's enctype
  family names (`aes`, `camellia`, `DEFAULT`, `-name`), case-insensitive
  enctypes, `dns_canonicalize_hostname = fallback`.
- `dns_lookup_kdc` now defaults to true, as MIT: a realm with no KDC
  configured has its KDCs found by DNS SRV records (BREAKING.md).
- `keytab.AddEntryWithSalt`: a keytab entry with an explicit salt (Active
  Directory salts a service account by its UPN or sAMAccountName, not its
  SPN) and a `uint32` key version (AD's can exceed the 8-bit field, written
  then in the format's 32-bit extension). `AddEntry` is unchanged.
- keytab entries can be manipulated: the entry and principal types are
  exported (`keytab.Entry`, `keytab.Principal`), with `Entry.SetKVNO`
  (`uint32`; sets the 8-bit field and the 32-bit extension together) and
  `Entry.SetTimestamp`. `Entry.KVNO` is the full version, `KVNO8` the
  format's original byte.
- Test substrate: `test/mitkdc/mitkdc.py` (two MIT realms on 127.0.0.1, one
  with its clock 900 s ahead), `test/ad/*.ps1` (an AD DC with claims),
  14 integration tests gated by `INTEGRATION=1` and `TEST_MIT_DIR` or
  `TEST_AD_DIR`.

### Fixed

- Logging in to AD with Kerberos armoring support on failed: an AS reply
  with enc-pa-rep now needs PA-REQ-ENC-PA-REP only, as MIT.
- Every PAC from an MIT KDC was refused (no logon info); now accepted, and
  `ADCredentials` set only when the logon info is there.
- Claims were "decompressed" with HPACK's Huffman table.
- A TGS request followed through a referral lost its U2U option.
- The renew lifetime from krb5.conf was ignored (fixed at 48 h).
- LDAP under signing or sealing: a message split across SASL buffers, or
  several in one, was misread.
- krb5.conf parsing: values containing `=`, realms on one line.
- Re-logins use the KDC's salt from ETYPE-INFO2; an empty realm takes the
  default realm; a NetBIOS-only address list counts as none; errors unwrap
  (`krberror.Krberror.Unwrap`).

### Security

- A ciphertext shorter than the confounder and checksum crashed decryption
  in all 8 encryption types (any client could crash an SPNEGO service
  before authenticating).
- The authenticator's realm was not checked against the ticket's client.
- An 18-byte Negotiate header (empty mechTypes) crashed the SPNEGO handler.
- The credential cache reader and the PAC parser crashed on malformed input.
- A forged KDC reply could ask for about 4 billion PBKDF2 iterations; now
  bounded as MIT bounds it.
- A KDC's TCP reply length was allocated as announced (up to 4 GB); now
  capped at 4 MB. Custom dialers no longer crash the transport.

### Upstream (jcmturner/gokrb5) taken

PRs 440, 448, 492, 505, 515, 580, 582, CL 523; issues 436, 444/445, 519,
526. The full triage is in [docs/Go_krb5_upstream_triage.md](docs/Go_krb5_upstream_triage.md).

### Not done yet (being done in the second round, above)

- SPNEGO NEGOEX-first negotiation driven to completion: the acceptor answers
  accept-incomplete when KRB5 is not the first mechanism (done, above), but
  the Kerberos continuation in the following leg, and the behaviour of a
  Windows NEGOEX client, are not yet exercised.
- RC4 and DES3 GSS message tokens (deprecated; not planned).

### Open decisions

- The PAC client info check refuses a mismatch; MIT only marks the PAC
  unverified (see BREAKING.md).
- The Camellia timing test cannot tell the constant-time version from the
  table one on Apple M-series; the claim rests on the construction.

## camellia128-cts-cmac (7e3cb81)

### Added

- The `camellia128-cts-cmac` and `camellia256-cts-cmac` encryption types
  (RFC 6803).
