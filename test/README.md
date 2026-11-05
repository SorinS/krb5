# Tests

`go test ./...` runs the unit tests: vectors, MIT's and Windows' outputs
kept in `testdata`, no network. The integration tests need a KDC and are
skipped unless `INTEGRATION=1` and their environment are set:

| Tests | Needs | Environment |
|---|---|---|
| `*_MIT` (PAC KDC signatures, clock skew, credential caches read and written by MIT's tools, Camellia, `gsskrb5` against MIT's gss-client and gss-server, SASL, FAST, SPAKE, PKINIT, S4U2Self) | MIT KDCs from `test/mitkdc/mitkdc.py` | `TEST_MIT_DIR`, `TEST_MIT_BIN` (both in `$TEST_MIT_DIR/env`) |
| `*_AD` (AD's PACs and compressed claims, clock skew, LDAP with SASL GSSAPI and SID lookups, FAST and compound identity, S4U) | an Active Directory DC (`test/ad`) | `TEST_AD_DIR`, `TEST_AD_PASSWORD_FILE`; for LDAP `TEST_AD_LDAP`, `TEST_AD_DC_HOST` |
| the older integration tests (`TEST.GOKRB5`) | the docker images of https://github.com/go-krb5/krb5-test | `TESTAD`, `TESTPRIVILEGED`, `TEST_KDC_ADDR`, ... |

Everything the tests start listens on 127.0.0.1 only.

## MIT KDCs on loopback

`test/mitkdc/mitkdc.py` makes two realms with MIT's KDC (1.20 or later, for
PAC signatures; 1.22 tested) in a directory of its own and runs them until
Ctrl-C:

- `A.TEST`: alice (`alice-pw`), bob (`bob-pw`, pre-authentication
  required), `HTTP/svc.a.test` and `host/svc.a.test` in `svc.keytab`, and
  the realm's krbtgt keys in `krbtgt.keytab` (for checking the KDC's PAC
  signatures), `HTTP/proxy.a.test` (`+ok_to_auth_as_delegate`) and
  `HTTP/self.a.test` in `s4u.keytab`;
- `K.TEST`: kim (`kim-pw`), `HTTP/svc.k.test`, served by a second krb5kdc
  whose clock runs 900 seconds ahead (`krb5kdc -T`), for clock skew.
- `B.TEST`: bea (`bea-pw`), `HTTP/svc.b.test` in `b.keytab`; a two-way trust
  with `A.TEST`, for cross-realm.
- `F.TEST`: grace (`grace-pw`), `host/fast.f.test` (in `fast.keytab`: its
  TGT is the FAST armor), `HTTP/svc.f.test`; its KDC has no encrypted
  timestamp, so a password works only through FAST's encrypted challenge.
- `S.TEST`: sam (`sam-pw`) and sam-ETYPE (one type each), SPAKE in all four
  groups, no encrypted timestamp; `O.TEST`: olga (`olga-pw`), an optimistic
  edwards25519 SPAKE challenge.
- `P.TEST`, `Q.TEST`, `R.TEST`, `N.TEST`: PKINIT (pat, quinn, rita, nate;
  P.TEST also anonymous), certificates made by `test/mitkdc/pki.py`
  (OpenSSL) in `$TEST_MIT_DIR/pki`.

macOS (Homebrew's MIT krb5 is keg-only; the `kinit` on the PATH is
Heimdal's, which the tests use too, as a second reader of our caches):

    brew install krb5
    python3 test/mitkdc/mitkdc.py --dir /tmp/mitkdc &
    set -a; . /tmp/mitkdc/env; set +a
    INTEGRATION=1 go test ./...

Debian or Ubuntu: `apt install krb5-kdc krb5-admin-server krb5-user`, stop
the packaged `krb5-kdc` service (it listens on every address), then the
same with `--mit /usr`. `$TEST_MIT_DIR/kdc-a.log` and `kdc-k.log` are the
KDCs' logs.

## An Active Directory domain controller

[test/ad/README.md](ad/README.md) takes a bare Windows Server to a DC of its
own forest, `goose.test`, with everything the `*_AD` tests use, says which
test needs what, and has the scripts (`test/ad/provision.sh` runs them over
ssh). Once it is up:

    test/ad/provision.sh tunnel Administrator@DC &
    INTEGRATION=1 TEST_AD_DIR=$DIR TEST_AD_PASSWORD_FILE=$DIR/users-password.txt \
        TEST_AD_LDAP=127.0.0.1:3890 TEST_AD_DC_HOST=<the DC's host name> \
        go test -count=1 ./... -run '_AD$|TestAD_LDAP'
