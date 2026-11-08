# gokrb5 upstream triage against the SorinS/krb5 fork

Date: 2026-11-03.
Upstream: https://github.com/jcmturner/gokrb5. The list covers 31 open PRs, about 100 open issues, and the closed-unmerged PRs among the last 100 closed. The data came from the unauthenticated REST API and the PR `.diff` files.
Fork: this repository at committed HEAD `7e3cb81`. The working tree has an uncommitted `pac/pac_type.go` edit, which does not build: `zeroSignature` is undefined. I did not touch it. Every probe ran against a `git archive HEAD` copy in `scratchpad/forkcopy/` with an extra `probe/` package, so nothing in the fork was modified.

## How to read "status"
- **present**: the fork already has the fix or feature. Evidence is given as file:line or a commit.
- **absent**: missing. Evidence is a grep or a probe result. Where it says **PROBED**, a test in `scratchpad/forkcopy/probe/*_test.go` reproduced the failure on the fork.
- **partial**: some of it is in, some is not.
- **n/a**: a question, a dependency bump, an upstream-only issue, or a non-issue.

The fork has already taken these upstream items as its own commits:
- 561 (`20c15ba`, plus the `c.reqs` reset at `spnego/http.go:135`)
- 550/556 (`59dad68`, which returns `UnsupportedDirective` instead of panicking)
- 525 (`7abc25d`, which adds `len(b) < 10` in `LoadCCache`)
- 547/548 (`4f18b5c`, `client.UseDialer`)
- 521/536/130 (`2d996b7`, which adds the `paRealm` argument to `messages.NewTGSReq`)
- 581 (`bb19ece`)
- 579/578 (`client/client.go:345` uses `errors.New`; `go vet ./...` is clean)
- 486 (`gssapi/gssapi.go:194` reads "unsupported QOP value")
- 424 (`client/session.go:46` has the nil-guard and line 210 makes `cancel` a buffered channel)

---

## A. Strongest adopt candidates (in priority order)

### A1. Unauthenticated panic on short ciphertext in every etype (PR 580) [SECURITY / DoS]
- **Status:** absent, PROBED. `crypto.DecryptMessage(make([]byte, l), key, 1)` panics for every etype. For lengths 0..64 the panic counts were: etype 16: 20, 17: 12, 18: 12, 19: 16, 20: 24, 23: 16, 25: 16, 26: 16. The new Camellia code (25/26) has the same flaw.
- **Real attack path, PROBED:** an SPNEGO NegTokenInit whose AP-REQ ticket `enc-part.cipher` is 4 bytes, sent to `SPNEGOService(kt).AcceptSecContext`, gives `slice bounds out of range [:-8]`. The panic happens before any key check, so no credentials are needed. The test is `TestSPNEGOShortCipher`.
- **Code locations:**
  - `crypto/rfc3961/encryption.go:114` (DES3)
  - `crypto/rfc3962/encryption.go:88`
  - `crypto/rfc8009/encryption.go:108`, and `:129-134` in `VerifyIntegrity`
  - `crypto/rfc6803/encryption.go:80`
  - `crypto/rfc4757/encryption.go:70-71`, and `:89` in `VerifyIntegrity`
- **Change:** at the top of each `DecryptMessage`, require `len(ciphertext) >= confounder + hmacLen`. For CTS etypes also require at least one cipher block. Return an error, never a slice. Also guard `b[e.GetConfounderByteSize():]` and the `VerifyIntegrity` helpers. Upstream's PR covers only 3962, 8009 and 4757. The fork also needs 3961 (DES3) and 6803 (Camellia).
- **Test:** a table test over every etype id from `crypto.GetEtype` and every length 0..(confounder+hmac+blocksize). Assert there is no panic and an error is returned. That is the PR's `shortciphertext_test.go`, extended to 16, 25 and 26. Add the SPNEGO-level regression from the probe.

### A2. AP-REQ client realm not checked, and identity taken from the authenticator (PR 582 / IS 577) [SECURITY]
- **Status:** absent. `messages/ap_req.go:210-212` compares only `CName`. `service/ap_exchange.go:32` builds the credentials from `APReq.Authenticator.CName/CRealm`, which the client controls, instead of from `Ticket.DecryptedEncPart`, which the KDC sealed.
- **Change:**
  1. In `APReq.Verify`, add `if a.Authenticator.CRealm != a.Ticket.DecryptedEncPart.CRealm` and return `KRB_AP_ERR_BADMATCH`.
  2. In `VerifyAPREQ`, build `credentials.NewFromPrincipalName(APReq.Ticket.DecryptedEncPart.CName, APReq.Ticket.DecryptedEncPart.CRealm)`.
- **Test:** PR 582's `TestVerifyAPREQ_CRealmMismatch`. It builds a ticket with `messages.NewTicket` and `HTTP_KEYTAB`, sets `a.CRealm = "OTHER.GOKRB5"`, and expects BADMATCH. Also assert that `creds.Domain()` equals the ticket realm in the happy path. This touches the same function as the PAC KDC-signature work.

### A3. SPNEGO accept panics on an empty mechTypes list (related to IS 451) [SECURITY / DoS, found during triage]
- **Status:** absent, PROBED. `spnego/spnego.go:86` reads `oid = t.NegTokenInit.MechTypes[0]` without a length check. The 18-byte header `Authorization: Negotiate YBAGBisGAQUFAqAGMASgAjAA` (`601006062b0601050502a0063004a0023000`) makes `SPNEGOKRB5Authenticate` panic with `index out of range [0] with length 0`. net/http recovers the panic per connection; other embedders (LDAP, gRPC, custom servers) crash.
- **Change:** return `StatusDefectiveToken` when the list is empty.
- **IS 451, same place:** do not require the first OID to be KRB5. Windows often lists NEGOEX or NTLM first. Search the whole list, as `NegTokenInit.Verify` (`spnego/negotiation_token.go:129`) already does. When KRB5 is present but not first, reply `accept-incomplete` with `supportedMech=KRB5`, and later require mechListMIC (IS 348).
- **Test:** a unit test with the header above, plus a token whose mechTypes are `[NTLMSSP, KRB5]`.

### A4. ccache parser panics on bad lengths (IS 519; PR 525 is only a partial fix)
- **Status:** partial, PROBED. `LoadCCache` has the 10-byte minimum (`credentials/ccache.go:73`). But `Unmarshal` (`:83`) indexes `b[0]` with no check, and `readInt32`/`readBytes` (`:352-370`) slice without bounds. A realm length of `0x7fffffff` gives `slice bounds out of range [:2147483675]`. Two truncation lengths of `testdata.CCACHE_TEST` also panic.
- **Change:** make the readers return errors, using the same pattern `keytab/keytab.go:501-595` already uses (keytab probed with 0/838 truncation panics). Thread the errors through `parsePrincipal`, `parseCredential` and `parseHeader`. Cap each length at `len(b)-*p`.
- **Why now:** ccache writing is being added, so the reader should be hardened first. Round-trip tests (write, then read) need a parser that fails cleanly.
- **Test:** truncate `CCACHE_TEST` at every length, flip every byte, and assert there is no panic. Add a Go `FuzzCCacheUnmarshal`.

### A5. krb5.conf parser bugs (PR 448, CL 523/IS 518, IS 526, PR 515/IS 504, IS 544)
Every case below was PROBED with `config.NewFromString` (`probe/probe_test.go:TestConfig`).
- **One-line realm `ATHENA.MIT.EDU = { kdc = kerberos.mit.edu }`:** PANIC `slice bounds out of range [1:0]` in `parseRealms` (`config/krb5conf.go:547-600`). A related bug: `X = { kdc = a` followed by more lines silently loses that KDC, because `parseRealms` passes `lines[start+1:i]` and so drops the text after `{` on the opening line. The fix is to parse the text after `{` and before `}` on the same line. PR 448's fix only turns the panic into an error. The better fix handles the inline form, which MIT accepts.
- **`dns_canonicalize_hostname = fallback`:** fails with a hard error, "invalid boolean value". This is the default `krb5.conf` on Fedora/RHEL, so loading those configs fails. Accept `fallback`: treat it as false, then retry canonicalized on `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Storing it as a tri-state is enough for a first pass.
- **Upper-case and legacy etype names (`AES256-CTS AES128-CTS RC4-HMAC`):** produce an **empty** `DefaultTktEnctypeIDs`. `parseETypes` (`:784`) calls `etypeID.EtypeSupported(et)` with a case-sensitive lookup. MIT is case-insensitive. Lower-case the name first. Also consider MIT family names (`aes`, `rc4`, `camellia`, `des3`), `DEFAULT`, and `+`/`-` prefixes. Those are absent too: `iana/etypeID` `ETypesByName` has only exact names.
- **`include` / `includedir`:** silently ignored, with no error and no effect. RHEL/Fedora's `includedir /etc/krb5.conf.d/` (crypto-policies) is not honoured. PR 515's `recurLoadFile` and its fixture directory `config/testkrb5.conf.d/*` are reusable.
- **`auth_to_local_names` block:** no panic, but `NewFromString` returns `UnsupportedDirective` alongside the config. Present (`:481`). Callers that treat any error as fatal will fail. Document this, or make it a log line.
- **Values containing `=`:** `strings.Split(line, "=")` at `:215`, `:510` and `:624` truncates the value. Use `SplitN(line, "=", 2)`.
- **`DNSLookupKDC` defaults to false (`config/krb5conf.go:92-93`, IS 544).** MIT defaults to true. Adopt, and note it in BREAKING.md.
- **Test:** one fixture `krb5.conf` containing all of the above. Assert there is no panic, the parsed KDC list, the etype IDs, and the canonicalize mode. Also an includedir fixture.

### A6. `Krberror` hides the KRBError, so callers cannot read error codes (PR 440 / IS 437)
- **Status:** absent. `krberror/error.go:47-55`: `Errorf` formats `err` into a string and drops it.
- **Change:** add `inner error` and `Unwrap()`, and set `inner` in `Errorf`. Clock-skew correction depends on this: `errors.As(err, &messages.KRBError{})` must reach the KRBError's `STime/SusecS` and the `KRB_AP_ERR_SKEW` code. So must the `KDC_ERR_KEY_EXPIRED` and `PREAUTH_FAILED` handling.
- **Test:** `client.Login()` against the MIT KDC with a bad password; assert that `errors.As` yields `ErrorCode == KDC_ERR_PREAUTH_FAILED`. Pure unit test: `krberror.Errorf(messages.NewKRBError(...), ...)`, then `errors.As`.

### A7. Re-login uses the default salt instead of the ETYPE-INFO2 salt (PR 505)
- **Status:** absent. `client/client.go:145` passes `types.PADataSequence{}` when there is no KRBError in hand. On a re-login with `assumePreAuthentication` set (`client/as_xchange.go:95-110`), the key is derived from the default `REALMuser` salt, which is wrong for AD (UPN or sAMAccountName salts) and for principals renamed in MIT.
- **Change:** cache the `PADataSequence` from the first `KDC_ERR_PREAUTH_REQUIRED` in `Settings`, keyed by etype, and reuse it.
- **Test:** an MIT KDC principal whose salt type is `special` (`addprinc -e aes256-cts:special`), or AD with a UPN that differs from the sAMAccountName. Log in, destroy the session, then call `AffirmLogin` again; the re-login must succeed.

### A8. KDC transport robustness, mostly found during triage (related to PR 547/543)
- **Status:** partial. The Dialer interface exists (`client/settings.go:20-55`). But:
  - `client/network.go:107` (`conn.(*net.UDPConn)`) and `:178` (`conn.(*net.TCPConn)`) **panic** when a custom Dialer returns any other `net.Conn`, such as a SOCKS or proxy connection. That is exactly the PR 547 use case. Change `sendUDP`/`sendTCP` to take `net.Conn`.
  - `:207` reads the 4-byte length with `conn.Read(sh)`; use `io.ReadFull`.
  - `:214` does `make([]byte, s)` with an unbounded `s`: a hostile KDC or MITM can force a 4 GiB allocation. Reject a set high bit (RFC 4120 7.2.2 reserves it) and cap the size, for example at 64 KiB or 1 MiB.
  - The connection leaks when `SetDeadline` fails (`:101`, `:173`).
  - The UDP buffer at `:130` is 4096 bytes. A larger reply is silently truncated and then fails to parse instead of falling back to TCP.
- **Test:** a fake Dialer returning a `net.Pipe()` end. A fake KDC sending length `0xffffffff`, and one sending the length header one byte at a time.

### A9. SPNEGO HTTP client: redirect counter and Host rewrite (PR 531, PR 560, IS 530/573/575/527)
- **Status:** partial.
  - PR 561's reset is present (`spnego/http.go:103` and `:135`). But the chain is still stored on the shared `Client` (`:35` `reqs`), which is a data race under concurrent `Do` calls (IS 573). PR 531 passes the `via` chain down the recursion instead; take that, and make `MaxRedirects` configurable (IS 575).
  - `setRequestSPN` overwrites `r.Host` with the CNAME target (`:204`, `:216`). That breaks virtual hosts behind proxies (PR 560). Use the CNAME only for the SPN.
  - Go ≥1.20 `LookupCNAME` returns inconsistent results for multi-CNAME chains (IS 527). Consider honouring `dns_canonicalize_hostname=false/fallback` (A5) here.
- **Test:** PR 531's `fakeTransport` `TestClient_Do` (11 sequential requests that each redirect once must all succeed), plus `go test -race` with concurrent `Do`.

### A10. NetBIOS-only address list makes AP-REQ verification fail (PR 492 / IS 490)
- **Status:** absent. `messages/ap_req.go:196-201` rejects with BADADDR whenever `CAddr` is non-empty and does not match. Windows clients put a single NetBIOS address in the ticket.
- **Change:** in `types/host_address.go`, treat a slice whose only member is `addrtype.NetBios` (20) as empty. That matches MIT `addr_srch.c`.
- **Test:** a unit test building a ticket whose `CAddr` is `[{20, "HOST            "}]`, with an IP `ClientAddress` setting.

### A11. RFC 3962 s2kparams: zero not mapped to 2^32, and no iteration cap (IS 444 / IS 445) [DoS]
- **Status:** absent, PROBED. `S2KparamsToItertions("00000000")` returns 0 (`crypto/rfc3962/key_derivation.go:54-56`). `"ffffffff"` returns 4294967295, which is accepted.
- **Why it matters:** ETYPE-INFO2 arrives unauthenticated in the PREAUTH_REQUIRED KRB-ERROR. A spoofed KDC reply can therefore make the client run about 4 billion PBKDF2 rounds.
- **Change:** map 0 to 2^32 as the RFC requires, then reject anything above a cap. MIT also caps the count. I believe MIT's limit is `MAX_ITERATION_COUNT` = 0x1000000, but I did not read the source; confirm it in `src/lib/crypto/krb/s2k_pbkdf2.c` before choosing the fork's cap. Check `crypto/rfc6803` (Camellia, default 32768) for the same handling.
- **Test:** a unit test for the vectors 0, 1000, 0x1000000 and 0xffffffff.

### A12. Smaller adopt items
- **IS 436:** an empty realm in `NewWithPassword`/`NewWithKeytab` (`client/client.go:35-60`) should fall back to `krb5conf.LibDefaults.DefaultRealm`. Today `IsConfigured` fails at `:159`. Absent; it is a one-line fix plus a test.
- **IS 387, kpasswd:** `kadmin.ChangePasswdMsg` always sends protocol version `0xff80` (`kadmin/message.go:35`) with `TargName`/`TargRealm` set (`kadmin/passwd.go:16-17`). AD treats that as a reset, which needs the Reset-Password right. For a self-change, omit TargName/TargRealm, or use version 1. Absent. Test on AD with a normal user (`client.ChangePasswd`). This overlaps the kpasswd feature.
- **TGS referral with U2U (found during triage):** `client/tgs_exchange.go:65-70` builds the U2U request using the old `kdcRealm`/`tgt`, and then `:72` overwrites it unconditionally with a plain TGS-REQ. U2U is therefore lost on every referral. Build the U2U request from the referral TGT, inside an `else`.
- **UPN_DNS_INFO (IS 455 is n/a, because the fork no longer NDR-decodes this buffer):** two problems remain.
  - `pac/upn_dns_info.go:54-55` slices `b[off:off+len]` with no bounds check. PROBED: `slice bounds out of range [65520:0]`. The input is only reachable after the ticket has been decrypted, so the KDC is trusted, but cheap hardening is still worth it.
  - The MS-PAC 2.10 extension (flag `S` = 0x2: SamName and SID) is not parsed. That is the clean answer to IS 409 ("Get User SID"). Also expose `UserSID = LogonDomainID + "-" + UserID` in `credentials.ADCredentials` (`credentials/credentials.go:60-72`).
  - The decoding uses `rune(uint16)`, which is wrong for surrogate pairs; use `utf16.Decode`.
- **PR 484 / IS 416, AD salt for keytab entries:** `keytab.AddEntry` (`keytab/keytab.go:139`) always uses the principal-derived salt and takes `kvno uint8`, which truncates AD kvnos above 255. Adopt an `AddEntryWithSalt`/`WithKey` variant (CL 566/576 also add `AddEntryWithKey`) and a `uint32` kvno.

---

## B. Overlap with the features in progress (mine for ideas and tests; do not merge as-is)

| Feature | Upstream item(s) | Fork today | What to take |
|---|---|---|---|
| ccache writing | PR 423 (`CCache.Marshal`, `NewV4CCache`, `writeV4Header`, `TestMarshal`); PR 532 (`CCacheFromCredentials`, `Client.GetCCache`, `writePrincipal`/`writeCredential`, endianness) | absent: `credentials/ccache.go` has no Marshal | PR 423's round-trip test against `testdata.CCACHE_TEST`: marshal the parsed cache and compare with the input bytes. The vector contains an `X-CACHECONF:` entry, so the writer must preserve conf entries and header tags for the comparison to hold. I did not check this. PR 532 shows how to keep the v1/v2 native-endian quirk. Also check with MIT `klist -c` on the written file. |
| default ccache/keytab paths and expansion | PR 429 (`ExpandParams` for `%{uid}`, `%{TEMP}`…, reading `krb5-config`); IS 499 (`GetDefaultPath`/`LoadDefault`) | absent: no `default_ccache_name` key and no `KRB5CCNAME`/`KRB5_CONFIG`/`KRB5_KTNAME` handling (grep was empty) | The ccache writer needs a target. Take the env-then-conf-then-`/tmp/krb5cc_%{uid}` resolution order and the `FILE:` prefix stripping. Skip the krb5-config shell-out. |
| TGT forwarding / GSS delegation | PR 532 (`Authenticator.GetCredDelegation`, `KRBCred.ToCredentials`, `CredDelegation`); IS 503 (layout of `newAuthenticatorChksum`); IS 411/541/228 (caller-chosen flags) | partial: `spnego/krb5_token.go:228-245` appends 4 zero bytes when `ContextFlagDeleg` is set, so the DELEG flag goes out with Dlgth=0 and no KRB-CRED. MIT acceptors reject that. Flags are hard-coded to Integ\|Conf at `spnego/negotiation_token.go:337`. `messages/krb_cred.go` only unmarshals (no Marshal or encrypt). | IS 503's single-OR flag computation. PR 532's acceptor-side extraction (DlgOpt=1, Dlgth, KRB-CRED → ccache). Add an option for the context flags (IS 541: AD LDAP hangs with Integ\|Conf set on GSS-SPNEGO binds unless SASL layers are negotiated). Test: an MIT KDC with a forwardable TGT, Go initiator to Go acceptor, then the acceptor writes a ccache and `klist -f` shows `F`. |
| AP-REP / mutual auth | PR 433 (`NewAPRep`, `EncAPRepPart.Marshal/Verify`, MIT `ktest_make_sample_*` vectors); PR 532 / CL 576 (`NewAPRep(req)`, `GenerateSeqNumber`) | absent: `messages/ap_rep.go` only unmarshals, `spnego/krb5_token.go:60` errors on marshaling an AP-REP, and the HTTP server always returns the fixed `spnegoNegTokenRespKRBAcceptCompleted` with no responseToken (`spnego/http.go:265`) | PR 433's tests ported from MIT `ktest` sample data give byte-exact DER vectors for AP-REP and EncAPRepPart (with and without optionals). Use them as the marshal oracle. |
| RFC 4121 sequence numbers / replay window | PR 420 (`SequenceState`, a 64-entry window copied from MIT `util_seqstate.c`, with `wide` 32/64-bit) | absent: no sequence tracking in `gssapi/` (grep empty) | Port the logic and the `TestSequenceState` table. Note: the fork already limits generated sequence numbers to 2^30 (`d5a586b`). |
| SASL GSSAPI (RFC 4752) / wrap tokens | PR 568 (`SecurityLayerSession`, `WrapWithSASLFraming`, `SecureConn`; AD-tested with RRC=12 integrity and RRC=28 confidentiality); IS 567/471/460 | partial: `gssapi/wrap_token.go` handles integrity-only v2 tokens. `Unmarshal` (`:153-193`) reads RRC but never un-rotates, and there is no Sealed (0x02) / confidentiality path. AD sends rotated tokens, so the current code cannot read them. | RRC rotation and the EC/filler arithmetic, and the RFC 4752 layer negotiation (4-byte bitmask plus max size). Their example test files hold AD-shaped vectors. Test: AD LDAP on 389 with `ldapsearch -Y GSSAPI -O maxssf=56` style integrity and confidentiality, Go client against Samba/AD. |
| RFC 1964 v1 wrap (RC4/DES peers) | PR 498 (`WrapTokenV1` plus tests against Cloudera Kafka) | absent | Defer: needed only for RC4 session keys (Kafka/ZooKeeper on old clusters). Keep the PR's vectors if RC4 is ever supported. |
| Channel bindings | CL 572 (closed; its diff is no longer available); IS 553/569 (tls-server-end-point, tls-exporter / RFC 9266) | absent: the checksum Bnd field is always zero (`spnego/krb5_token.go:230`) and the acceptor does not check it | Bnd = MD5 of the `gss_channel_bindings_struct` encoding (RFC 4121 4.1.1.2). The tls-server-end-point hash comes from the certificate's signature hash. AD LDAP channel-binding enforcement (`LdapEnforceChannelBinding=2`) is the test scenario. |
| FAST | CL 576 (`AutoPAFXFAST`: try FAST first, retry without it on `isPAFXFASTUnsupportedError`; tests `TestShouldRetryASExchangeWithoutPAFXFAST`) | partial: only `DisablePAFXFAST` plus the `PA_REQ_ENC_PA_REP` check (`messages/kdc_rep.go:319-339`) | The retry heuristic and its unit tests are useful if armored FAST is added. |
| PKINIT | CL 571 (`setPKInitPAData`, DH and enc-key-pack paths, CMS types, `PAData_ms.go` for MS variants) | absent | Reference for the AD-specific PA types and the `paChecksum` over the req-body. The code quality is unknown (it ships a binary `v8/main/main`); use it as reference only. |
| S4U2Self/Proxy | CL 566 (`NewS4U2ProxyTGSReq`, `setPAPACOptions` with resource-based constrained delegation, `GetProxyTicket`, `InitProxySecContext`); IS 449 | absent | `PA-PAC-OPTIONS` bit handling and the `cname-in-addl-tkt` KDC option. Test: AD with RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`). |
| SPNEGO mechListMIC | IS 348 | absent: MechListMIC is parsed but never produced or verified (`spnego/negotiation_token.go:35-118`) | Needed once A3 (non-first mech) is done; RFC 4178 §5 requires the MIC then. |
| Clock skew | (no upstream item) | absent: `messages/krb_error.go:25` carries `STime` but nothing uses it | Depends on A6 (`Unwrap`) so callers can reach the KRBError. |
| DNS SRV | IS 544 (default), IS 441 (rand seed) | present: SRV lookup (`config/hosts.go:40-90`, vendored `go-krb5/x/dns.OrderedSRV`). IS 441 is n/a on Go ≥1.20. | Flip the default (A5). The vendored `weightedOrder` does not treat target `"."` (RFC 2782 "service not available") specially; add that. |
| PAC KDC signature verification | no upstream PR or issue touches this | in progress in the parent's working tree | none |
| Compressed PAC claims (MS-XCA LZ77+Huffman) | no upstream PR or issue touches this | absent | none |
| Camellia | none upstream | present (`7e3cb81`) | Apply the A1 and A11 guards to `rfc6803`. |

---

## C. Full table

### C.1 Open PRs

| # | Title | Cat | Status in fork (evidence) | Rec |
|---|---|---|---|---|
| 582 | reject a mismatched authenticator client realm | security | absent: `messages/ap_req.go:210`, `service/ap_exchange.go:32` | **adopt-with-test** (A2) |
| 580 | crypto: no panic on short ciphertext | security/bug | absent, PROBED in all 8 etypes incl. camellia | **adopt-with-test** (A1, extend to 3961/6803) |
| 579 | fix Diagnostics error formatting | bug | present: `client/client.go:345` uses `errors.New` | already-in |
| 574 | Upgrade GoSDK, x/net, google/uuid | deps | n/a: fork has its own Renovate deps | decline |
| 568 | SASL security layer for GSSAPI | feature (cat 2) | absent: no confidentiality/RRC (`gssapi/wrap_token.go:153-193`) | mine for ideas (B) |
| 561 | spnego client reqs forever incrementing | bug | present: `20c15ba`, `spnego/http.go:135` | already-in |
| 560 | Do not set Host header for CNAME | bug | absent: `spnego/http.go:204,216` | **adopt** (A9) |
| 558 | typo | trivial | n/a | decline |
| 550 | config: no panic on auth_to_local* | bug | present: `59dad68`, `config/krb5conf.go:481` (returns UnsupportedDirective) | already-in (consider downgrading to log) |
| 547 | dialer for TCP | feature | partial: `client.UseDialer` exists, but `conn.(*net.TCPConn)` at `client/network.go:178` panics for non-TCPConn | **adopt-with-test** (A8) |
| 543 | Custom connections | feature | partial: covered by Dialer; same assertion panic (`:107`, `:178`) | fold into A8 |
| 540 | CI on go 1.21/1.22 | ci | n/a | decline |
| 535 | header support for proxy auth | feature | absent | decline for now (proxy auth, IS 397; feature creep) |
| 532 | GSS-API server functionality (AP-REP, ccache write, delegation) | feature (cat 2) | absent | mine for ideas (B) |
| 531 | SPNEGO redirect loop detection per request | bug | partial: reset present, shared `reqs` field still racy (`spnego/http.go:35,101`) | **adopt-with-test** (A9) |
| 525 | Check CCache file length | bug | partial: `credentials/ccache.go:73`; `Unmarshal` still panics (PROBED) | adopt the proper fix (A4) |
| 522 | errBuf.String() | trivial | n/a | decline |
| 521 | cross-domain support | bug | present: `2d996b7`, `messages/kdc_req.go:168` `paRealm` | already-in |
| 515 | include / includedir | bug | absent: silently ignored (PROBED) | **adopt-with-test** (A5) |
| 505 | Store pre-auth data sequence | bug | absent: `client/client.go:145` | **adopt-with-test** (A7) |
| 498 | Wrap Tokens v1 | feature | absent | defer (RC4 only) |
| 492 | NetBIOS-only address list treated as empty | bug | absent: `types/host_address.go:167`, `messages/ap_req.go:196` | **adopt-with-test** (A10) |
| 486 | Fix Bad QOP message | trivial | present: `gssapi/gssapi.go:194` | already-in |
| 484 | AES keytab entries for AD (AD salt) | feature | absent: `keytab/keytab.go:139` | adopt (A12) |
| 448 | panic on one-line realm config | bug | absent, PROBED panic | **adopt-with-test** (A5; parse inline, not just error) |
| 440 | Krberror Unwrap | bug | absent: `krberror/error.go:47-55` | **adopt-with-test** (A6) |
| 433 | AP-REP create/marshal/encrypt | feature (cat 2) | absent: `messages/ap_rep.go` unmarshal only | mine (B), especially the MIT ktest vectors |
| 429 | krb5.conf parameter expansion | feature (cat 2) | absent | mine (B) |
| 423 | CCache.Marshal | feature (cat 2) | absent | mine (B) |
| 420 | sequence tracking | feature (cat 2) | absent | mine (B) |
| 391 | spnego http handler features (Basic auth etc.) | feature | absent | decline (scope; Basic-to-krb5 login belongs in the app) |

### C.2 Recently closed, unmerged PRs (from the last 100 closed)

| # | Title | Cat | Status | Rec |
|---|---|---|---|---|
| 576 | AutoPAFXFAST option (also bundles AP-REP and S4U) | cat 2 | partial (`DisablePAFXFAST` only) | mine (B) |
| 572 | TLS 1.2/1.3 channel binding (tls-server-end-point) | cat 2 | absent; diff no longer available | design from RFC 4121 / RFC 5929 (B) |
| 571 | PKINIT | cat 2 | absent | reference only (B) |
| 566 | Microsoft S4U2Proxy extensions | cat 2 | absent | mine (B) |
| 559 | allow matching any service class in ticket SPN | feature | absent (24k-line rebase) | decline: weakens SPN matching. Revisit only with explicit opt-in. |
| 555 | feature: v9 | n/a | n/a | decline |
| 549 | change token validation for .NET 8 | bug? | unclear (closed by author) | decline / investigate if .NET 8 clients fail |
| 546 | Docker images for integration tests | ci | n/a | decline |
| 538 | Adding new functionality | n/a | n/a | decline |
| 536 / 534 | complex cross-realm scenarios | bug | present: `2d996b7` (fork adds `client_integration_test.go` cross-realm test) | already-in |
| 523 | handle dns_canonicalize_hostname=fallback | bug | absent, PROBED hard error | **adopt** (A5) |
| 510 | bump x/net | deps | n/a | decline |
| 491 | NetBIOS (dup of 492) | bug | absent | see 492 |
| 468 | init etype IDs for new defaults | bug | present: `a037a7c`; probe shows default tkt etypes `[18 17 23 26 25]` | already-in |
| 450, 418 | fork notices | n/a | n/a | decline |
| 443 | keytab principal printed as string | trivial | present: `634514d` | already-in |
| 438 | doc fix | trivial | present: `b737f74` | already-in |
| 431 | empty LookupCNAME response | bug | present: `3f32f67`, `spnego/http.go:198` (`name != ""`) | already-in |
| 425 | Don't use default realm for TGS | bug | present: `1150460` ("change default behaviour for resolving realm from spn") | already-in |
| 401 | ReqFlags as BitString | bug | present: `78f5693` | already-in |
| 338 | SPNEGO ticket reuse for HTTP client | feature | present: client ticket cache (`client/cache.go`) | already-in |
| 329 | keytab interface | feature | absent | decline |
| 325 | check all MechTypes in NegTokenInit Verify | bug | present: `spnego/negotiation_token.go:129` (loop). But `spnego/spnego.go:86` still uses `[0]` | partial; see A3 |
| 320 | credentials valid-until | feature | present: `credentials/credentials.go:138,315` | already-in |

### C.3 Open issues

| # | Title | Cat | Status | Rec |
|---|---|---|---|---|
| 581 | isolate shared replay cache test | test | present: `bb19ece`; `service/ap_exchange_test.go:219` has no `t.Parallel` | already-in |
| 578 | Diagnostics non-constant format | bug | present: `client/client.go:345` | already-in |
| 577 | [SECURITY] CRealm not checked | security | absent | **adopt** (A2) |
| 575 | configurable maxredirect | feature | absent: hard-coded 10 at `spnego/http.go:102` | adopt with A9 |
| 573 | document thread safety | doc/bug | absent: shared `reqs` is racy | adopt with A9 (fix, then document) |
| 570 | transfer repo to org | n/a | n/a | n/a |
| 569 | RFC 9266 TLS 1.3 channel bindings | cat 2 | absent | B (channel bindings) |
| 567 | SASL security layer | cat 2 | absent | B |
| 562–565 | upgrade aescts/dnsutils/goidentity/rpc | deps | n/a: fork vendors `go-krb5/x/{aescts,dns,identity,rpc}` | n/a |
| 556 | auth_to_local_names panic | bug | present: `config/krb5conf.go:481` | already-in |
| 554 | WWW-Authenticate token question | question | no hard-coded token in the fork (grep for `ade0234568a4209af8bc0280289eca` was empty); the server sends bare `Negotiate` | n/a |
| 553 | channel bindings | cat 2 | absent | B |
| 552 | undefined NewClientFromCCache | question | n/a: the fork has `client.NewFromCCache` | n/a |
| 551 | maintainer? | n/a | n/a | n/a |
| 548 | dialer for TCP | feature | partial (A8) | adopt A8 |
| 544 | DNSLookupKDC default true | bug/config | absent: `config/krb5conf.go:92` | **adopt** (A5; BREAKING note) |
| 541 | can't change SPNEGO context flags | feature (cat 2) | absent: `spnego/negotiation_token.go:337` | adopt as part of the GSS context work (B) |
| 539 | KVN always 0 | bug | present: `keytab/keytab.go:315-320` reads the 32-bit kvno extension; kvno 0 means latest (`:83`) | already-in |
| 533 | client login without keytab | question | n/a | n/a |
| 530 | redirects misread as loops | bug | partial (A9) | adopt A9 |
| 529 | decrypt ticket on client side | question | n/a (expected behaviour; times are in the TGS-REP enc part) | n/a |
| 528 | hard-coded token (static analysis) | false positive | likely a false positive on string or test constants in `crypto/aes128-cts-hmac-sha256-128.go` and `crypto/aes256-cts-hmac-sha384-192.go`; I did not open the two files to confirm | n/a |
| 527 | Go 1.20 LookupCNAME inconsistency | bug | absent: `spnego/http.go:197,209` | adopt with A5/A9 (honour `dns_canonicalize_hostname`) |
| 526 | etype parsing case-sensitive | bug | absent, PROBED: empty etype list | **adopt** (A5) |
| 524 | LoadCCache length | bug | partial | A4 |
| 520 | principal name backslash escaping (RFC 1964 2.1.1) | bug | absent: `types/principal_name.go:62` `ParseSPNString` has no escape handling | adopt (low): needed when writing ccache/keytab names containing `@` or `/` |
| 519 | ccache out of range | bug | absent, PROBED | **adopt** (A4) |
| 518 | dns_canonicalize_hostname fallback | bug | absent, PROBED | **adopt** (A5) |
| 508 | error decrypting service ticket | support | n/a (keytab/kvno mismatch on the user side) | n/a |
| 504 | include / includedir | bug | absent | **adopt** (A5) |
| 503 | `newAuthenticatorChksum` improvements | cat 2 | partial: `spnego/krb5_token.go:228-245` (DELEG flag without KRB-CRED) | fold into the delegation work (B) |
| 499 | API for default config/ccache/keytab path | cat 2 | absent | B |
| 494 | AP_REQ verify failed aes256 | support | n/a (key mismatch; RFC 8429 is a deprecation document, not a crypto change) | n/a |
| 490 | NetBIOS addresses | bug | absent | **adopt** (A10) |
| 487 | IAKERB | feature | absent | decline for now |
| 471 | GSSAPI encryption (pgx) | cat 2 | absent (no Sealed wrap) | B (SASL/wrap) |
| 469 | hiveserver2 | support | n/a | n/a |
| 464 | OSX ccache v2 binary in error | bug | partial: v1/v2 native-endian read exists (`credentials/ccache.go:105`); errors do not echo binary | covered by A4 hardening |
| 460 | full wrap token support | cat 2 | partial | B |
| 457 | req.Body vs ContentLength | bug | partial: TeeReader replay at `spnego/http.go:89`; `ContentLength`/`GetBody` are not reset on replay | adopt (low): set `req.GetBody` and `ContentLength` when re-sending |
| 455 | UPN_DNSInfo malformed NDR | bug | n/a as reported (no longer NDR-decoded), but the bounds panic (PROBED) and missing S-flag fields remain (`pac/upn_dns_info.go:54`) | adopt (A12) |
| 452 | `Authorization: Kerberos` (WinRM) | feature | absent: only `Negotiate` accepted, case-sensitive (`spnego/http.go:353`) | adopt (low): accept the `Kerberos` scheme with a raw KRB5 token, and match the scheme case-insensitively |
| 451 | SPNEGO OID of MechToken not KRB5 (first mech) | bug | absent: `spnego/spnego.go:86` | **adopt** (A3) |
| 449 | GSSAPI impersonation | cat 2 (S4U) | absent | B |
| 447 | Java clients fail (ContinueNeeded) | bug? | unclear; `spnego/negotiation_token.go:131` returns ContinueNeeded when no optimistic token is sent. Same root as A3. | adopt with A3 (reply accept-incomplete instead of failing) |
| 446 | KVNO 0 hard-coded for clients | bug | present: `keytab/keytab.go:83` (0 means latest) | already-in |
| 445 | rfc3962 zero handling on 32-bit | bug | partial: uses `pbkdf2.KeyExtended` with int64 | A11 (cap removes the need) |
| 444 | s2kparams zero and error handling | bug/DoS | absent, PROBED | **adopt** (A11) |
| 441 | rand not seeded | bug | n/a (Go ≥1.20 auto-seeds; the fork targets 1.25) | n/a |
| 437 | Krberror hides original error | bug | absent | **adopt** (A6) |
| 436 | empty realm param not using default | bug | absent: `client/client.go:35`, `:159` | adopt (A12) |
| 432 | AP-REP marshal/encrypt | cat 2 | absent | B |
| 428 | parameter expansion | cat 2 | absent | B |
| 427 | non-file ccaches (KCM/KEYRING) | feature | absent | decline for now (KCM later, if ccache writing needs it) |
| 426 | ccache not reloaded when refreshed | feature | absent | decline for now; reconsider with ccache writing |
| 424 | deadlock on referral for ccache realm | bug | present: `36f9075`, `client/session.go:46` | already-in |
| 419 | sequence numbers tracking | cat 2 | absent | B (PR 420) |
| 416 | AD AES keytab salts | feature | absent | adopt (A12) |
| 412 | OSX ticket cache (KCM/API) | feature | absent | decline |
| 411 | GSS_C_DELEG_FLAG | cat 2 | partial (the flag can be passed to `NewKRB5TokenAPREQ`, but no KRB-CRED is attached) | B |
| 409 | Get user SID | feature | absent: `credentials.ADCredentials` has `UserID` int and `LogonDomainID` but no SID | adopt (A12, trivial) |
| 397 | spnego proxy authentication | feature | absent | decline (or a small Proxy-Authorization variant later) |
| 388, 337 | ssh.GSSAPIClient | feature | absent | decline (it falls out of the GSS context init work; an adapter is easy later) |
| 387 | ChangePasswd uses reset semantics | bug (cat 2: kpasswd) | absent: `kadmin/message.go:35`, `kadmin/passwd.go:16-17` | **adopt-with-test** (A12; AD scenario) |
| 372 | enctype field types inconsistent | cosmetic | absent | decline (API churn) |
| 367 | KDC_ERR_S_PRINCIPAL_UNKNOWN | support | n/a (canonicalization; helped by A5 `dns_canonicalize_hostname`) | n/a |
| 354 | Logger should be an interface | feature | absent: `*log.Logger` everywhere | decline for now (could take `slog` later) |
| 348 | SPNEGO request-mic | cat 2 | absent | B |
| 314 | auth fallback / non-handler API | feature | partial: `spnego.SPNEGOService(...).AcceptSecContext` is usable directly | n/a |
| 273 | email of AD user | question | n/a (LDAP) | n/a |
| 272 | Sarama SASL/Kerberos | question | n/a | n/a |
| 228 | WSMAN accept-incomplete with other flags | bug | absent: same root as A3/IS 541 (no accept-incomplete continuation and no caller flags) | adopt with A3/B |
| 170 | needs KRB5RCACHETYPE=none against mod_auth_gssapi | bug (old v5) | present: redirect strips the auth header (`spnego/http.go:99`); each 401 retry builds a new authenticator | already-in (verify on MIT httpd if convenient) |
| 158 | PKINIT | cat 2 | absent | B |
| 130 | cross-realm | bug | present: `2d996b7` | already-in |
| 125 | go-mssqldb | question | n/a | n/a |

---

## D. Probe artifacts
- `scratchpad/forkcopy/probe/probe_test.go`: crypto short-ciphertext sweep, ccache/keytab truncation, krb5.conf cases.
- `scratchpad/forkcopy/probe/spnego_test.go`: empty-mechTypes panic, UPN offsets, s2kparams.
- `scratchpad/forkcopy/probe/spnego_fuzz_test.go`: truncation and bit-flip sweep over a real NegTokenInit (no panics beyond those listed), and the short-ticket-cipher pre-auth panic.
- Run them with `cd scratchpad/forkcopy && go test -v -count=1 ./probe/`.
- Upstream PR diffs are in `scratchpad/gh/diffs/<n>.diff`. The issue and PR dumps are `scratchpad/gh/{prs,issues}.txt`.
