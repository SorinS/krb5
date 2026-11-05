# Breaking Changes

## Fork

The following breaking changes exist between `github.com/jcmturner/gokrb5/v8` and `github.com/go-krb5/krb5` v0 (each
change will be elaborated on in time):

- Package `github.com/go-krb5/krb5/iana/asnAppTag` renamed to `github.com/go-krb5/krb5/iana/asn1apptag` (being evaluated
  to be moved to `encoding/asn1`).
- Removal of v7 package and v8 package is now v0.
- Context Value Key for `github.com/go-krb5/krb5/spnego` has changed to const `CTXKey` with an explicit type.
- The struct tag `generalstring` in the `github.com/go-krb5/x/encoding/asn1` package is now `general`. It's unlikely
  anyone was using this however instances of `generalstring` (case-sensitive) in struct asn1 tags should be evaluated
  manually and changed appropriately.

## Behaviour changes on the dev1 branch

Stricter:

- `Ticket.GetPACType` (and so the service's AP-REQ check) refuses a PAC whose client info does not name the ticket's
  client and auth time. This is stricter than MIT: MIT's authdata module (`mspac_verify`) leaves a PAC that fails
  `krb5_pac_verify` unverified and lets the authentication through. go-krb5 already refused a PAC with a bad server
  signature; the client info check follows that.

Stricter, as MIT is:

- `APReq.Verify` refuses an authenticator whose realm is not the ticket's client realm; `service.VerifyAPREQ`'s
  credentials are the ticket's client, not the authenticator's.
- A KDC's PBKDF2 iteration count (ETYPE-INFO2) of zero, below the type's default or 2^24 and more is refused.
- A KDC's TCP reply announced above 4 MB, or with the reserved high bit, is refused.

More lenient, as MIT is:

- A PAC without logon info (an MIT KDC's) or without a KDC signature passes the server signature check;
  `credentials.ADCredentials` are set only when the logon info is there.
- An AS reply with the enc-pa-rep flag needs PA-REQ-ENC-PA-REP only, not PA-FX-FAST as well.
- With `kdc_timesync = 1` (the default) an AS reply is not refused for clock skew: the client takes the KDC's time from
  it, and from KRB_AP_ERR_SKEW errors (`Client.TimeOffset`).
- A ticket address list of one NetBIOS name counts as no addresses.

Other:

- `dns_lookup_kdc` defaults to true (MIT's default), not false. A realm with KDCs listed in the configuration is
  unaffected; a realm with none now has its KDCs resolved by DNS SRV records (`_kerberos._udp`/`_tcp`) rather than
  failing. Set `dns_lookup_kdc = false` to keep the old behaviour.
- A TGS request's authenticator has a subkey (`TGSReq.SubKey`, as MIT and Windows send), so the KDC encrypts the reply
  in it (usage 9); `TGSReq.SetPAData` keeps the request's other padata. `TGSRep.DecryptEncPartUsage` takes the key and
  usage.
- TGS requests are armored with FAST (implicitly, by the TGT) when the realm's KDC said in an AS reply that it does
  FAST, as MIT does; an unarmored reply is still taken.
- `crypto.Aes256CtsHmacSha384192.GetKeyByteSize` is 32 (RFC 8009's 256-bit key), not 24: a random key of the type
  (a subkey) had the wrong length.
- RC4: key usage 9 is 9 in the message type (MIT, Heimdal, Windows; RFC 4757's table says 8), usages are 4 bytes little
  endian (they were a varint), and passwords with characters outside the BMP work.
- The default enctype lists include aes256-cts-hmac-sha384-192 and aes128-cts-hmac-sha256-128 (MIT's defaults), and
  `default_tkt_enctypes` and `default_tgs_enctypes` are `permitted_enctypes` when not set, as in MIT.
- The AS exchange uses SPAKE when the KDC offers it (PA-SPAKE), before the encrypted timestamp, as MIT does.
- `Ticket.Marshal` leaves out `DecryptedEncPart` (it wrote it, in the clear, for a decrypted ticket).
- `TGSRep.VerifyAt` does not compare the client name for an S4U request (`TGSRep.VerifyS4U` does).
- `ASRep.VerifyWithKey` and `VerifyWithKeyRealm` check a reply with the reply key given (FAST, SPAKE, PKINIT);
  `ASRep.VerifyAt` is unchanged.
- New dependencies: filippo.io/edwards25519 and filippo.io/nistec (pure Go; Go's own crypto/internal code, exported),
  for SPAKE's point arithmetic.
- `config.Realm` has `DisableEncryptedTimestamp` and `Values` (the realm's other relations); a nested block in a realm
  (`auth_to_local = { ... }`) no longer panics the parser.
- `pac.PACType.ProcessPACInfoBuffers` takes a nil logger; an empty claims set (a device without claims) is not an
  error.

- `client.CacheEntry` has a `Flags` field; `credentials.Principal` is exported (the unexported `principal` is an alias).
- `config.LibDefaults` has `DNSCanonicalizeHostnameFallback`; enctype names are not case-sensitive, and MIT's family
  names (`aes`, `camellia`, `DEFAULT`, `-name`) are understood; `Load` follows `include` and `includedir`.
- Every AS and TGS request carries PA-PAC-OPTIONS (claims).
- `krberror.Krberror` wraps the error it was made from (`Unwrap`).
