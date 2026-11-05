# Kerberos test KDCs: MIT on loopback, and an Active Directory DC

How the Kerberos tests of `gslib.git/krb5` (Goose) and
this repository (Go) get their KDCs. Both sets of scripts do
everything below; this page is what they do, and how to do it by hand.

**Rule for every host:** nothing listens on a public address. The MIT
KDCs bind 127.0.0.1 only; the DC's AD ports are blocked inbound and reached
through ssh tunnels to its loopback.

## 1. MIT KDC on loopback

### The scripted way

| Repo | Script | Realms |
|---|---|---|
| Go | `test/mitkdc/mitkdc.py [--dir DIR] [--mit PREFIX]` | A.TEST (alice, bob, HTTP/ and host/svc.a.test, S4U services, krbtgt keys exported), K.TEST (KDC clock +900 s), F.TEST (FAST only), S.TEST/O.TEST (SPAKE), P/Q/R/N.TEST (PKINIT) |
| Goose | `krb5/scripts/kdc.py [--dir DIR]` | A.TEST/B.TEST (trust), F.TEST (FAST only), S.TEST/O.TEST (SPAKE), P/Q/R/N.TEST (PKINIT) |

Both write `DIR/krb5.conf` and keytabs, start `krb5kdc -n` per realm
group on free loopback ports, and stop on Ctrl-C. The Go one also writes
`DIR/env` (`KRB5_CONFIG`, `TEST_MIT_DIR`, `TEST_MIT_BIN`, ports):

    python3 test/mitkdc/mitkdc.py --dir /tmp/mitkdc &
    set -a; . /tmp/mitkdc/env; set +a
    INTEGRATION=1 go test ./...

### Installing MIT krb5

- **macOS:** `brew install krb5`. It is keg-only: the binaries are in
  `$(brew --prefix krb5)/bin` and `/sbin` (`krb5kdc`, `kdb5_util`,
  `kadmin.local`, `kinit`, `klist`, `kvno`, `gss-client`, `gss-server`).
  The `kinit`/`klist` on the PATH are Apple's Heimdal: useful as a
  second implementation, but not MIT.
- **Debian/Ubuntu:** `apt install krb5-kdc krb5-admin-server krb5-user`
  (gss-sample: `krb5-gss-samples`). Stop and disable the packaged
  `krb5-kdc`/`krb5-admin-server` services: they listen on all addresses.
  Use `--mit /usr`.
- 1.20 or later issues PACs with server, KDC, ticket and full signatures;
  1.22 has everything both test suites use (SPAKE, PKINIT with ECDH).

### By hand (one realm)

Everything lives in one directory `$D`; `KRB5_CONFIG` and
`KRB5_KDC_PROFILE` point the tools at it, so nothing in `/etc` is touched.

`$D/kdc.conf` (`kdc_listen` with an address is what keeps it on loopback):

    [kdcdefaults]
        kdc_listen = 127.0.0.1:61088
        kdc_tcp_listen = 127.0.0.1:61088
    [realms]
        A.TEST = {
            database_name = /D/a/principal
            key_stash_file = /D/a/stash
            acl_file = /D/a/kadm5.acl
            kdc_listen = 127.0.0.1:61088
            kdc_tcp_listen = 127.0.0.1:61088
            kadmind_listen = 127.0.0.1:61749
            kpasswd_listen = 127.0.0.1:61464
            master_key_type = aes256-cts
            supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal arcfour-hmac:normal camellia256-cts-cmac:normal camellia128-cts-cmac:normal
            max_life = 10h
            max_renewable_life = 7d
        }
    [logging]
        kdc = FILE:/D/kdc.log

`$D/krb5.conf`:

    [libdefaults]
        default_realm = A.TEST
        dns_lookup_kdc = false
        dns_lookup_realm = false
        rdns = false
        forwardable = true
        allow_weak_crypto = true
    [realms]
        A.TEST = {
            kdc = 127.0.0.1:61088
        }
    [domain_realm]
        .a.test = A.TEST

Then:

    export KRB5_CONFIG=$D/krb5.conf KRB5_KDC_PROFILE=$D/kdc.conf
    mkdir -p $D/a && touch $D/a/kadm5.acl
    kdb5_util -r A.TEST create -s -P master-a
    kadmin.local -r A.TEST -q "addprinc -pw alice-pw alice"
    kadmin.local -r A.TEST -q "addprinc -pw bob-pw +requires_preauth bob"
    kadmin.local -r A.TEST -q "addprinc -randkey HTTP/svc.a.test"
    kadmin.local -r A.TEST -q "ktadd -k $D/svc.keytab HTTP/svc.a.test"
    kadmin.local -r A.TEST -q "ktadd -k $D/krbtgt.keytab -norandkey krbtgt/A.TEST"   # PAC KDC signatures
    krb5kdc -n -r A.TEST &           # -n: stay in the foreground
    lsof -nP -iTCP -sTCP:LISTEN | grep krb5kdc   # must show 127.0.0.1 only

Variations the suites use:
- **A skewed KDC:** a second `krb5kdc -n -r K.TEST -T 900` (its own
  `kdc.conf`, port and database): its clock runs 900 s ahead.
- **A KDC without encrypted timestamp** (FAST/SPAKE only):
  `[plugins] kdcpreauth = { disable = encrypted_timestamp }` in that KDC's
  profile. It is process-wide, hence a separate krb5kdc.
- **SPAKE:** `[libdefaults] spake_preauth_groups = edwards25519 P-256 ...`
  in the KDC's profile, `+requires_preauth` principals.
- **PKINIT:** `pkinit_identity`, `pkinit_anchors` per realm; certificates
  from `krb5/scripts/pki.py`.
- **Cross-realm:** the same `krbtgt/B.TEST@A.TEST` and
  `krbtgt/A.TEST@B.TEST` (same password, same enctypes) in both databases.
- **gss-server** binds `0.0.0.0` on its own: run it as
  `gss-server -inetd` on a connection you accepted on 127.0.0.1 (the Go
  tests hand it the socket as stdin/stdout).

## 2. An Active Directory DC on a Windows Server

The host: `Administrator@DC` (Windows Server 2022, EC2), public,
no firewall in front. It is the DC of the forest `goose.test` (NetBIOS
`GOOSE`). Scripts live in `C:\Goose\scripts`; `C:\Goose\dc` holds what
they make (logs, the keytab) and password files they read once and delete.
Passwords are never typed on a command line or printed: copy them in as
files (`scp`), the script reads and deletes them.

Scripts: `gslib.git/krb5/scripts/windows` (Goose; also `trust.ps1`) and
[`test/ad`](../test/ad/README.md) (the same, plus `claims.ps1`,
`s4u.ps1`, `xpress.ps1`, `verify.ps1`, `provision.sh`; its README is the
full walkthrough for Go).

### Steps

1. **`state.ps1`** (read-only): DNS, interfaces, the inbound rules that
   admit ssh, what listens. Run before and after each step.
2. **`firewall.ps1`**: inbound *block* rules for AD's TCP (53, 88, 135,
   139, 389, 445, 464, 593, 636, 3268-9, 5722, 9389, 49152-65535) and UDP
   ports, *before* promotion (block rules beat the allow rules the
   promotion adds; loopback is not filtered, so tunnels still work), then
   `Install-WindowsFeature AD-Domain-Services`.
3. **`schedule.ps1`** with the DSRM password in `C:\Goose\dc_p.txt`: a
   scheduled task runs **`promote.ps1`** as SYSTEM
   (`Install-ADDSForest -DomainName goose.test -DomainNetbiosName GOOSE
   -InstallDns`, then reboot), so the promotion survives the ssh session.
   Log: `C:\Goose\dc\promote.log`.
4. **`setup.ps1`** with the users' password in `C:\Goose\dc\users.txt`:
   - users alice (AES only) and bob (AES and RC4), group GooseTesters;
   - service account svc-web, SPNs `HTTP/web.goose.test` and
     `host/web.goose.test`, AES only, claims and compound identity
     supported (msDS-SupportedEncryptionTypes bits 18, 17);
   - its keytab by `ktpass` → `C:\Goose\dc\web.keytab` (ktpass resets the
     account's password to the users' one and sets its UPN to the SPN, so
     the AES salt AD uses and ktpass's agree: the usual ktpass pitfall);
   - claims: the policy "KDC support for claims, compound authentication
     and Kerberos armoring" as registry values (`EnableCbacAndArmor`,
     `CbacAndArmorLevel` = 1), a claim type on `department`, alice's set;
   - the computer goosepc$ (the device for compound identity).
5. **`claims.ps1`** (Go; the same password file): user carol with six
   string claim types (title, company, ...), 64 characters each, which
   makes AD compress her claims set (LZ77+Huffman).
6. **`s4u.ps1`** (Go; the same password file): service accounts with
   delegation policy and a sensitive user, for S4U2Self and S4U2Proxy.
7. **`trust.ps1`** (Goose; password in `C:\Goose\dc\trust.txt`): a
   two-way realm trust with MIT's A.TEST (`netdom trust /realm /twoway`,
   `ksetup` AES), the account mit-alice mapped to alice@A.TEST.
8. **`xpress.ps1`** (Go, no password): vectors from ntdll's
   `RtlCompressBuffer`/`RtlDecompressBufferEx` for the claims
   decompressor.

### Reaching it

    ssh -N -L 127.0.0.1:8888:127.0.0.1:88 -L 127.0.0.1:3890:127.0.0.1:389 Administrator@DC
    scp Administrator@DC:C:/Goose/dc/web.keytab web.keytab

ssh forwards TCP only: the client's krb5.conf has
`kdc = 127.0.0.1:8888` and `udp_preference_limit = 1` (Heimdal-style
`tcp/127.0.0.1:8888` is not understood by MIT's tools). The DC's host
name (`<dc-host>.goose.test`) is its LDAP service's name
(`ldap/<dc-host>.goose.test`).

Goose: `python3 krb5/scripts/ad.py --password-file ... --keytab web.keytab
--dc-host <dc-host>.goose.test [--trust-password-file ...]`.
Go: see `test/ad/README.md` (`TEST_AD_DIR`, `TEST_AD_PASSWORD_FILE`,
`TEST_AD_LDAP`, `TEST_AD_DC_HOST`).

### What AD does that MIT does not (found with these tests)

- No claims in the PAC unless the request carries PA-PAC-OPTIONS with
  the claims bit.
- With armoring support on, the AS reply's encrypted padata has
  PA-REQ-ENC-PA-REP and no PA-FX-FAST (go-krb5 refused every login).
- PACs have ticket and full checksums (since November 2022); AD's krbtgt
  key is not available to tests, so only their presence is checked there
  (MIT's are verified with the exported krbtgt key).
- Large claims sets come compressed with MS-XCA LZ77+Huffman.
- `msDS-SupportedEncryptionTypes` governs tickets *to* the account only.
- Compound identity: explicit TGS armor by a computer's TGT gives device
  info and claims.
- A realm trust: AD refuses an MIT cross-realm TGT carrying MIT's PAC
  (`+no_auth_data_required` on `krbtgt/GOOSE.TEST@A.TEST`).
- S4U: a service with delegation targets but no protocol transition gets a
  non-forwardable S4U2Self ticket; one with no delegation at all gets a
  forwardable one, which S4U2Proxy still refuses. The ticket is forwardable
  only if the service's TGT is. MIT's DB2 back end refuses S4U2Proxy.
- SASL GSSAPI binds work with no layer, integrity or confidentiality here;
  domains that require LDAP signing refuse the first.
