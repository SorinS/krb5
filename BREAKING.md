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

## Behaviour changes on the goose-parity branch

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

- `client.CacheEntry` has a `Flags` field; `credentials.Principal` is exported (the unexported `principal` is an alias).
- `config.LibDefaults` has `DNSCanonicalizeHostnameFallback`; enctype names are not case-sensitive, and MIT's family
  names (`aes`, `camellia`, `DEFAULT`, `-name`) are understood; `Load` follows `include` and `includedir`.
- Every AS and TGS request carries PA-PAC-OPTIONS (claims).
- `krberror.Krberror` wraps the error it was made from (`Unwrap`).
