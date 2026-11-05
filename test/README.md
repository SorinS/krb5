# Tests

`go test ./...` runs the unit tests: vectors, MIT's and Windows' outputs
kept in `testdata`, no network. The integration tests need a KDC and are
skipped unless `INTEGRATION=1` and their environment are set:

| Tests | Needs | Environment |
|---|---|---|
| `*_MIT` (PAC KDC signatures, clock skew, credential caches read and written by MIT's tools, Camellia, `gsskrb5` against MIT's gss-client and gss-server, SASL, FAST, SPAKE, PKINIT, S4U2Self) | MIT KDCs from `test/mitkdc/mitkdc.py` | `TEST_MIT_DIR`, `TEST_MIT_BIN` (both in `$TEST_MIT_DIR/env`) |
| `*_AD` (AD's PACs and compressed claims, clock skew, LDAP with SASL GSSAPI and SID lookups, FAST and compound identity, S4U) | an Active Directory DC (`test/windows`) | `TEST_AD_DIR`, `TEST_AD_PASSWORD_FILE`; for LDAP `TEST_AD_LDAP`, `TEST_AD_DC_HOST` |
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

`test/windows` turns a Windows Server (2019, 2022 or 2025) host into the DC
of its own forest, `goose.test` (NetBIOS `GOOSE`), with AD's ports blocked
from outside: the KDC (88) and LDAP (389) are reached through ssh tunnels
to the DC's loopback. Copy the scripts to `C:\Goose\scripts` and run them
as Administrator, in this order (each says more in its header):

1. `state.ps1`: what the host is and listens on (read-only).
2. `firewall.ps1`: inbound block rules for AD's ports, then the AD DS role.
3. `schedule.ps1` with the DSRM password in `C:\Goose\dc_p.txt`: runs
   `promote.ps1` as SYSTEM, which makes the forest and reboots.
4. `setup.ps1` with the test users' password in `C:\Goose\dc\users.txt`
   (deleted once read): users alice and bob, the service svc-web
   (`HTTP/web.goose.test`) and its keytab `C:\Goose\dc\web.keytab`, claims
   turned on with a `department` claim for alice, the computer goosepc$.
5. `claims.ps1` (the same password file): the user carol with six string
   claims, enough for the KDC to compress her claims set.
6. `s4u.ps1` (the same password file): service accounts with delegation
   policy (`svc-proxy`, `svc-kerb`, `svc-self`, `svc-target`, `svc-rbcd`,
   `svc-rbcdt`) and a sensitive user (`sens`), for the S4U tests.
7. `xpress.ps1` (no password): vectors from Windows' own compressor for
   `pac/xpress` (`testdata/windows.txt.gz` was made by it).

Then, on the test machine:

    ssh -N -L 127.0.0.1:8888:127.0.0.1:88 -L 127.0.0.1:3890:127.0.0.1:389 Administrator@DC &
    scp Administrator@DC:C:/Goose/dc/web.keytab $DIR/web.keytab

`$DIR/krb5.conf`:

    [libdefaults]
        default_realm = GOOSE.TEST
        dns_lookup_kdc = false
        udp_preference_limit = 1
    [realms]
        GOOSE.TEST = {
            kdc = 127.0.0.1:8888
        }
    [domain_realm]
        .goose.test = GOOSE.TEST

and

    INTEGRATION=1 TEST_AD_DIR=$DIR TEST_AD_PASSWORD_FILE=users-password.txt \
        TEST_AD_LDAP=127.0.0.1:3890 TEST_AD_DC_HOST=<the DC's host name>.goose.test go test ./...

(ssh forwards TCP only, hence `udp_preference_limit = 1`.)
