# go-krb5: features from the Goose krb5 (night of 2026-11-03)

The notes of the first round, on the branch `goose-parity` (off
`camellia128-cts-cmac`, which equals `master`), kept as they were written.
The second round (FAST, SPAKE, PKINIT, S4U, ...) and where things stand now
are in [CHANGELOG.md](../CHANGELOG.md). `test/windows` is now `test/ad`.

Pure Go throughout (no cgo). Test setup: [Test_Kerberos_KDC.md](Test_Kerberos_KDC.md).

## Progress

| Item | Status | Commits |
|---|---|---|
| Test substrate (MIT KDCs on loopback, live AD hooks) | done | 2519a2f |
| AD login with armoring enabled (bug found on the way) | fixed | d4f5ced |
| PAC KDC signature check (+ ticket and full checksums, client info) | done | 84101ad |
| PA-PAC-OPTIONS (claims asked for; needed for any AD claims) | done | 63e712f |
| Compressed PAC claims | done | 7f57c08 |
| Clock skew learned from the KDC | done | 0a30e83 |
| Writing credential caches (+ reader hardening) | done | c1e5e49 |
| Camellia, constant time | done | cb3bb18 |
| Security fixes from upstream (short ciphertext, AP-REQ realm, SPNEGO) | done | 7ea4043 |
| GSS-API outside SPNEGO, delegation, forwarded TGTs (package gsskrb5) | done | e6c8ab7 |
| SASL GSSAPI (RFC 4752) + package ldap with AD SID lookups | done | 11085ec |
| Upstream gokrb5 PRs/issues: adopted (see below) | done | 7ea4043, 0a30e83, c1e5e49, 224e943, 787ffcf |
| Test docs (MIT KDC, Windows DC) + DC scripts in the repo | done | 8e0a690, Test_Kerberos_KDC.md |
| BREAKING.md entries | done | 7606c38, 07a2bfa |
| LDAP: messages split across SASL buffers (found in review) | fixed | b448169 |
| README features | done | 400261a |

## Notes per item

### AD login with armoring enabled
Every AS exchange against our DC failed: "KDC did not respond appropriately
to FAST negotiation". go-krb5 required PA-FX-FAST in the reply's encrypted
padata when the enc-pa-rep flag is set; AD (with "KDC support for claims,
compound authentication and Kerberos armoring") sends only
PA-REQ-ENC-PA-REP (type 149). Now as MIT: the checksum is required,
PA-FX-FAST is not.

### PAC
- New: `PACType.VerifyKDCSignature`, `VerifyFullChecksum`,
  `VerifyTicketChecksum`, `ValidateClientInfo`; `Ticket.VerifyPACKDC`
  (as MIT's `krb5_kdc_verify_ticket`).
- Bugs fixed: every MIT PAC was refused (no logon info); GetPACType looked
  only at the first AD-IF-RELEVANT element (panic on an empty one); buffer
  offsets outside the PAC panicked; the client info was never checked
  against the ticket.
- Tests: MIT 1.22 ticket + keys as unit vectors; live MIT (all four
  signatures verify with the exported krbtgt key); live AD (server
  signature, client info; AD's krbtgt key is not available, so its KDC
  signatures are only checked for presence).

### PA-PAC-OPTIONS
AD sends no claims at all unless the request asks (MIT ignores the
padata). Also fixed: renew_lifetime was overwritten with 48 h; a retried AS
request carried PA-REQ-ENC-PA-REP twice.

### Compressed claims
New package `pac/xpress` (LZ77+Huffman and plain LZ77, MS-XCA). The vendored
mstypes "decompressed" with HPACK's Huffman table, so no compressed claims
set was ever readable. Oracles: 412 vectors from Windows' own ntdll
`RtlCompressBuffer` (made on the DC by `test/ad/xpress.ps1`, checked
there by `RtlDecompressBufferEx`; all decoded first time), MS-XCA examples,
go-krb5's XPRESS_HUFF vector, and live: `test/ad/claims.ps1` gives the
new user carol six string claims, which AD compresses; Go reads them.
DC change: user carol, claim types goose-title/company/streetAddress/
physicalDeliveryOfficeName/displayName/l (alice and bob untouched, so the
Goose ad.py expectations hold).

### Clock skew
As MIT: KRB_AP_ERR_SKEW from the KDC sets the offset and the request is
retried once (AS and TGS); every AS reply sets the offset from its auth
time. Also: `krberror` now wraps (Unwrap, upstream PR 440); ETYPE-INFO2 salt
kept for re-logins (upstream PR 505); U2U was lost on referral. Tests:
K.TEST (KDC +900 s), kdc_timesync = 0 surfaces KRB_AP_ERR_SKEW via
errors.As; live AD with the client 20 min off either way.

### Credential caches
`CCache.Marshal/Save`, `Client.CCache/SaveCCache`, KDC offset and
configuration entries. go-krb5's cache and an MIT 1.22 one round-trip byte
for byte. The reader no longer panics on bad input (every prefix, every
flipped byte, fuzzed), reads the header properly, reads timestamps past 2038.
MIT's klist reads our cache; MIT's kvno uses our TGT; Heimdal's klist reads
it; MIT's kvno honours the KDC offset we write (K.TEST +900 s; fails without it).

### Camellia
s1 = A2(S_aes(A1(x))) on bit planes (Boyar–Peralta circuit), as in the Goose
bignum. CMAC subkeys masked instead of branching. Exhaustive S-box check, 1M
random F against the old table, 898 OpenSSL-checked blocks + 46 CMAC, RFC
3713, RFC 6803; MIT Camellia-only AS/TGS. Assembly checked: no indexed load or
branch on secret data. dudect |t| < 1.1 — but the table version shows no leak
on this M-series machine either, so the timing test cannot prove anything
here; the claim rests on construction + assembly. Cost: F 47 ns vs 12 ns.

### Security (upstream PRs 580, 582 and one found in triage)
Every etype's decrypt panicked on short ciphertext (396 panics in the new
test; pre-auth DoS of any SPNEGO acceptor); AP-REQ realm unchecked and the
caller's identity taken from the authenticator; 18-byte Negotiate header
panicked SPNEGO.

### GSS-API (gsskrb5)
New package: initiator/acceptor contexts, mutual auth, channel bindings,
delegation (KRB-CRED of a forwarded TGT), MIC/Wrap with RRC/EC, sequence and
replay checks. Oracles: MIT gss-server (our initiator, 5 variants incl.
delegation) and MIT gss-client (our acceptor, 7 variants incl. -d; the
delegated TGT then gets a service ticket). RC4/DES3 per-message tokens not
done (refused).

### SASL GSSAPI and LDAP
`gsskrb5.SASL` (also satisfies go-ldap's `GSSAPIClient` by method set, no
import) and package `ldap` (BindGSSAPI with none/integrity/confidentiality
layers, Search with RFC 4515 filters, WhoAmI, DefaultNamingContext,
LookupSID, TokenGroups). Live against the DC: all three layers bind, Who am
I? = GOOSE\alice, alice's PAC SID → her entry, tokenGroups == PAC groups.
Passed first time against Windows (its Wrap tokens, RRC included).

## Upstream (jcmturner/gokrb5) triage

Full table: `Go_krb5_upstream_triage.md` (next to this file) (31 open PRs, ~100 issues, 23
closed-unmerged PRs, each checked against the fork's code; many already in).

Adopted, each with a test:
- PR 580 short-ciphertext panic (all 8 etypes, not just 3) — 7ea4043
- PR 582 / IS 577 AP-REQ realm + identity from the ticket — 7ea4043
- (triage find) SPNEGO empty mechTypes panic — 7ea4043
- IS 519 / PR 525 ccache reader panics — c1e5e49
- PR 440 krberror Unwrap — 0a30e83
- PR 505 ETYPE-INFO2 salt on re-login — 0a30e83
- (triage find) U2U lost on referral — 0a30e83
- IS 444/445 PBKDF2 iteration bounds (MIT's MAX_ITERATION_COUNT 0x1000000 confirmed in MIT source) — 224e943
- PR 547 case / (triage) transport: Dialer panics, 4 GB alloc, partial length read, UDP 4096 cut — 224e943
- PR 492 NetBIOS-only address — 224e943
- IS 436 empty realm → default — 224e943
- PR 448, PR 515/IS 504, IS 526, CL 523/IS 518, '=' in values (krb5.conf) — 787ffcf
- PR 423/532 ideas for ccache writing (round-trip test) — c1e5e49

Candidates not taken (for a next round):
- A9 SPNEGO HTTP client: shared redirect list (data race), Host header
  rewritten to the CNAME (PRs 531, 560).
- IS 451/348: SPNEGO accept only when KRB5 is the first mech; mechListMIC
  never made or checked.
- IS 387: kpasswd always sends the set-password form (0xff80 with target),
  which AD treats as a reset needing rights.
- IS 544: DNSLookupKDC defaults to false (MIT: true) — a behaviour change I
  did not want to make unasked.
- PR 484/IS 416: keytab.AddEntry with an explicit salt, kvno > 255.
- UPN_DNS_INFO bounds and its SID extension; ADCredentials.UserSID.
- spnego/krb5_token.go sets the DELEG flag with no KRB-CRED (MIT acceptors
  reject it): gsskrb5 does delegation properly; spnego not changed.
- `preferred_preauth_types` is read as an etype list in one AS path (a
  latent bug; masked now that the PREAUTH_REQUIRED error is kept).
- PR 498 RFC 1964 v1 wrap tokens (RC4 peers), PR 420 sequence window,
  CL 566 S4U, CL 571 PKINIT, CL 576 FAST — larger features.

## How it was tested
- `go test ./...` (unit, no network): all pass.
- MIT 1.22 on 127.0.0.1 (`test/mitkdc/mitkdc.py`): 13 integration tests,
  all pass — including MIT klist/kvno/kinit/gss-client/gss-server as oracles,
  and Heimdal's klist.
- Live AD (Windows Server 2022 DC through the ssh tunnel): PAC, compressed
  claims, clock skew, LDAP SASL — all pass.
- Windows ntdll compressor as the XPRESS oracle.
- Everything listened on 127.0.0.1 only; DC changes: user carol and six claim
  types (scripts in C:\Goose\scripts: xpress.ps1, claims.ps1).

## Re-running the tests
The MIT KDCs are still running on 127.0.0.1 (a background task of this
session; restart with `python3 test/mitkdc/mitkdc.py --dir DIR`). The AD
test files were copied to `$TEST_AD_DIR` (krb5.conf, web.keytab; mode
0600). With the ssh tunnel up (127.0.0.1:8888 → 88, 3890 → 389):

    set -a; . DIR/env; set +a     # TEST_MIT_DIR, TEST_MIT_BIN, KRB5_CONFIG
    INTEGRATION=1 TEST_AD_DIR=$TEST_AD_DIR \
      TEST_AD_PASSWORD_FILE=$TEST_AD_DIR/users-password.txt \
      TEST_AD_LDAP=127.0.0.1:3890 TEST_AD_DC_HOST=<dc-host>.goose.test \
      go test ./... -run 'TestTicket_VerifyPACKDC_MIT|TestTicket_PAC_AD|TestPAC_Claims_AD|TestClient_ClockSkew_MIT|TestClient_ClockSkew_AD|TestClient_SaveCCache_MIT|TestClient_SaveCCache_KDCOffset_MIT|TestClient_Camellia_MIT|TestInitiator_MITServer|TestMITClient_Acceptor|TestInitiatorAcceptor|TestSASL|TestAD_LDAP|TestSplitWrappedMessages_MIT'

(Not plain `INTEGRATION=1 go test ./...`: go-krb5's older integration tests
also key on INTEGRATION=1 and want their docker KDCs.) `go vet ./...` and
`go test -race ./...` (unit, and the 14 integration tests) are clean.

## Behaviour to decide on
- The PAC client-info check refuses the AP-REQ (as go-krb5 already did for
  a bad server signature). MIT is more lenient here: it marks the PAC
  unverified and still authenticates. BREAKING.md says so.
- With kdc_timesync on (default), the AS reply's skew check is skipped and
  the KDC's time adopted, as MIT does.
