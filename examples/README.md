# Examples

Small programs, one thing each, to copy from. They run against the test KDCs:
MIT's on loopback (`test/mitkdc`) and an Active Directory DC (`test/ad`).
Passwords are read from stdin and never taken as flags. `krb5.conf` comes from
`$KRB5_CONFIG`.

| Example | Shows | MIT | AD |
|---|---|---|---|
| [tgt-password](tgt-password/main.go) | a TGT from a user's password | yes | yes |
| [tgt-keytab](tgt-keytab/main.go) | a TGT from a keytab | yes | yes |
| [service-ticket](service-ticket/main.go) | a ticket for an SPN, from a password, keytab or credential cache | yes | yes |
| [ccache](ccache/main.go) | saving tickets to a credential cache and using them without the password | yes | |
| [cross-realm](cross-realm/main.go) | a ticket to a service in a realm that trusts the user's | yes | |
| [impersonate](impersonate/main.go) | S4U2Self: a service gets a ticket in a user's name, and reads the PAC | yes | yes |
| [kcd](kcd/main.go) | constrained delegation: S4U2Self, S4U2Proxy, then calling the back end as the user | | yes |
| [spnego-server](spnego-server/main.go) | an HTTP server taking Kerberos, with a keytab | yes | yes |
| [spnego-client](spnego-client/main.go) | calling such a server | yes | yes |
| [gss-echo](gss-echo/main.go) | GSS-API on a plain TCP connection: mutual authentication, encrypted messages | yes | |
| [ldap-whoami](ldap-whoami/main.go) | binding to AD's LDAP with Kerberos, reading a user's groups | | yes |
| [fast](fast/main.go) | a login under FAST armor | yes | |
| [pkinit](pkinit/main.go) | a TGT from a certificate, or an anonymous one | yes | |
| [keytab-make](keytab-make/main.go) | a keytab from a password | yes | yes |

A blank column means it was not run there, not that it cannot work, except that
MIT's DB2 back end refuses S4U2Proxy, and `ldap-whoami` reads AD's own attributes.

## Against MIT's KDCs

    brew install krb5                                  # Debian: see test/README.md
    python3 test/mitkdc/mitkdc.py --dir /tmp/mitkdc &
    set -a; . /tmp/mitkdc/env; set +a

`KRB5_CONFIG` now names the realms `mitkdc.py` made (its header lists them).

    # A TGT, two ways
    echo alice-pw | go run ./examples/tgt-password -user alice -realm A.TEST
    go run ./examples/tgt-keytab -keytab $TEST_MIT_DIR/svc.keytab -principal HTTP/svc.a.test -realm A.TEST

    # A service ticket
    echo alice-pw | go run ./examples/service-ticket -user alice -spn HTTP/svc.a.test

    # A credential cache, which MIT's klist reads
    echo alice-pw | go run ./examples/ccache -user alice -path /tmp/alice.cc -spn HTTP/svc.a.test
    $TEST_MIT_BIN/klist -c /tmp/alice.cc

    # Across the trust between A.TEST and B.TEST
    echo alice-pw | go run ./examples/cross-realm -user alice -realm A.TEST \
        -spn HTTP/svc.b.test -keytab $TEST_MIT_DIR/b.keytab

    # S4U2Self
    go run ./examples/impersonate -keytab $TEST_MIT_DIR/s4u.keytab \
        -service HTTP/proxy.a.test -realm A.TEST -user alice

    # An SPNEGO server and a client of it
    go run ./examples/spnego-server -keytab $TEST_MIT_DIR/svc.keytab -addr 127.0.0.1:8080 &
    echo alice-pw | go run ./examples/spnego-client -user alice -spn HTTP/svc.a.test -url http://127.0.0.1:8080/

    # GSS-API on a socket
    go run ./examples/gss-echo -listen 127.0.0.1:9000 -keytab $TEST_MIT_DIR/svc.keytab &
    echo alice-pw | go run ./examples/gss-echo -connect 127.0.0.1:9000 -user alice -spn host/svc.a.test -message hello

    # FAST: F.TEST takes a password no other way
    echo grace-pw | go run ./examples/fast -user grace -realm F.TEST \
        -armor-keytab $TEST_MIT_DIR/fast.keytab -armor-principal host/fast.f.test -spn HTTP/svc.f.test

    # PKINIT
    go run ./examples/pkinit -user pat -realm P.TEST \
        -identity FILE:$TEST_MIT_DIR/pki/pat.pem,$TEST_MIT_DIR/pki/pat.key
    go run ./examples/pkinit -anonymous -realm P.TEST

## Against Active Directory

[test/ad/README.md](../test/ad/README.md) sets up the DC, the tunnels and `DIR`
(`TEST_AD_DIR`), which holds `krb5.conf`, `users-password.txt` and `web.keytab`.

    export KRB5_CONFIG=$DIR/krb5.conf
    P=$DIR/users-password.txt

    go run ./examples/tgt-password -user alice -realm GOOSE.TEST < $P

    # An SPNEGO server with the keytab ktpass made; the PAC gives alice's groups
    go run ./examples/spnego-server -keytab $DIR/web.keytab -addr 127.0.0.1:8080 &
    go run ./examples/spnego-client -user alice -realm GOOSE.TEST \
        -spn HTTP/web.goose.test -url http://127.0.0.1:8080/ < $P

    # LDAP with Kerberos, encrypted; -dc is the DC's host name
    go run ./examples/ldap-whoami -user alice -realm GOOSE.TEST \
        -ldap 127.0.0.1:3890 -dc $TEST_AD_DC_HOST < $P

Constrained delegation, end to end. `svc-proxy` may delegate to
`HTTP/target.goose.test` (`test/ad/s4u.ps1` sets that policy), and `svc-target`
is the back end. A keytab needs the account's key version, which any ticket to
the account shows:

    go run ./examples/service-ticket -user alice -realm GOOSE.TEST -spn HTTP/proxy.goose.test < $P    # kvno N
    go run ./examples/service-ticket -user alice -realm GOOSE.TEST -spn HTTP/target.goose.test < $P   # kvno M
    go run ./examples/keytab-make -principal svc-proxy  -realm GOOSE.TEST -kvno N -out /tmp/proxy.keytab  < $P
    go run ./examples/keytab-make -principal svc-target -realm GOOSE.TEST -kvno M -out /tmp/target.keytab < $P

    # The back end: tickets are addressed to the SPN, the key is the account's
    go run ./examples/spnego-server -keytab /tmp/target.keytab -principal svc-target -addr 127.0.0.1:8081 &

    # The front end: no password of alice's anywhere
    go run ./examples/kcd -keytab /tmp/proxy.keytab -service svc-proxy -realm GOOSE.TEST -user alice \
        -target HTTP/target.goose.test -url http://127.0.0.1:8081/

The back end answers `hello alice@GOOSE.TEST`, with her groups from the PAC.

## Keeping them working

`examples_test.go` runs all of the above, and is skipped without the KDCs:

    INTEGRATION=1 go test ./examples/                       # with mitkdc's env, as above
    INTEGRATION=1 TEST_AD_DIR=$DIR TEST_AD_PASSWORD_FILE=$P \
        TEST_AD_LDAP=127.0.0.1:3890 TEST_AD_DC_HOST=... go test ./examples/

These are examples, not hardened services. A real server would set timeouts on
its `http.Server`, use TLS, and decide which realms' users to let in.
