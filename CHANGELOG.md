# Changelog

What this fork (`github.com/go-krb5/krb5`, SorinS/krb5) adds to
`github.com/jcmturner/gokrb5/v8`. Behaviour changes are spelled out in
[BREAKING.md](BREAKING.md); how to run the tests is in
[test/README.md](test/README.md).

## Unreleased: branch `goose-parity`, second round (2026-11-04)

The rest of what the Goose krb5 has (FAST, SPAKE, PKINIT), then S4U, KDC
proxy and the triage's leftovers. Pure Go; the curve arithmetic SPAKE needs
comes from filippo.io/edwards25519 and filippo.io/nistec (pure Go, no cgo).

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
- `test/mitkdc`: F.TEST (FAST only), S.TEST and O.TEST (SPAKE), P/Q/R/N.TEST
  (PKINIT, certificates from `test/mitkdc/pki.py` with OpenSSL).
- `config.LibDefaults.Values`: the libdefaults relations without a field.

### Fixed

- aes256-cts-hmac-sha384-192 keys are 32 bytes (were 24).
- RC4: usage 9, usages of 128 and up, passwords outside the BMP (MIT's
  vectors).
- A krb5.conf realm with a nested block panicked the parser.
- A PAC with an empty device claims set was an error, and its logging
  panicked with no logger.
- The SHA-2 types (aes256-cts-hmac-sha384-192, aes128-cts-hmac-sha256-128)
  were missing from the default enctype lists, and `default_tkt_enctypes`
  and `default_tgs_enctypes` did not default to `permitted_enctypes` as in
  MIT: a user with SHA-2 keys only could not log in by default.

## Unreleased: branch `goose-parity` (2026-11-03)

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
- Test substrate: `test/mitkdc/mitkdc.py` (two MIT realms on 127.0.0.1, one
  with its clock 900 s ahead), `test/windows/*.ps1` (an AD DC with claims),
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
526. The full triage is in `~/Dev/Goose/docs/Go_krb5_upstream_triage.md`.

### Not done yet (being done in the second round, above)

- SPNEGO HTTP client: the redirect data race and Host rewrite.
- SPNEGO with Kerberos not the first mechanism, and mechListMIC.
- kpasswd's set-password form for AD.
- `DNSLookupKDC`'s default (left as it was).
- keytab `AddEntryWithSalt`.
- RC4 and DES3 GSS message tokens.

### Open decisions

- The PAC client info check refuses a mismatch; MIT only marks the PAC
  unverified (see BREAKING.md).
- The Camellia timing test cannot tell the constant-time version from the
  table one on Apple M-series; the claim rests on the construction.

## camellia128-cts-cmac (7e3cb81)

### Added

- The `camellia128-cts-cmac` and `camellia256-cts-cmac` encryption types
  (RFC 6803).
