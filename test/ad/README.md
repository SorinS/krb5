# An Active Directory domain controller for the live tests

From a bare Windows Server to the `*_AD` tests passing. It makes a new forest
of its own, `goose.test` (NetBIOS `GOOSE`), so use a host you can throw away:
**promotion takes over the machine** and is undone only by demoting it or
reinstalling it.

Everything here is tested on Windows Server 2022 Datacenter (EC2, 2 vCPUs,
4 GB). The scripts should do on 2019 and 2025 too, but were not run there.

## What you need

On the host:

- Windows Server, not yet a domain controller, its Administrator's login.
- OpenSSH Server with PowerShell as its shell, reachable on port 22. EC2's
  images have it; otherwise, at a console:

      Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
      Set-Service sshd -StartupType Automatic; Start-Service sshd
      New-NetFirewallRule -DisplayName 'OpenSSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22
      New-ItemProperty HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Force `
          -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

- If you want the host name to be anything but what it has, rename it now,
  and reboot: it becomes the DC's name (`TEST_AD_DC_HOST`) and is awkward to
  change afterwards.

On the test machine: `ssh`, `scp`, `openssl`, Go.

**Nothing may listen on a public address.** Such a host is often public with
nothing in front of it. Step 2 blocks AD's ports inbound *before* promotion
(a block rule beats the allow rules promotion adds); loopback is not
filtered, so the tests reach the KDC and LDAP through ssh tunnels to the
DC's own 127.0.0.1. Only ssh stays open: keep its password strong, or use a
key.

## The short way

`provision.sh` runs from the test machine. `$HOST` is `Administrator@address`,
`$DIR` a directory of your own, outside the repository.

    test/ad/provision.sh passwords $DIR        # 1. two random password files
    test/ad/provision.sh prepare $HOST         # 2. firewall, AD DS role
    test/ad/provision.sh promote $HOST $DIR    # 3. the forest; the host reboots
    # wait for ssh to come back (5 to 15 minutes), then:
    test/ad/provision.sh domain $HOST $DIR     # 4. accounts, policy, keytab, krb5.conf
    test/ad/provision.sh tunnel $HOST &        # 5. KDC on 127.0.0.1:8888, LDAP on :3890

`domain` ends with `verify.ps1`, which says what is there and prints the DC's
host name. Then:

    INTEGRATION=1 TEST_AD_DIR=$DIR TEST_AD_PASSWORD_FILE=$DIR/users-password.txt \
        TEST_AD_LDAP=127.0.0.1:3890 TEST_AD_DC_HOST=<the DC's host name> \
        go test -count=1 ./... -run '_AD$|TestAD_LDAP'

Not plain `go test ./...` with `INTEGRATION=1`: go-krb5's older integration
tests also key on it and wait on their docker KDCs.

`domain` and `verify` can be run again at any time. **A second `domain`
changes one thing to watch for:** ktpass raises svc-web's key version, so
any `web.keytab` copied earlier is stale; `$DIR/web.keytab` is refreshed.

## The steps, one by one

`C:\Goose\scripts` holds the scripts, `C:\Goose\dc` what they make: logs and
the keytab. A password goes over as a file, read once and deleted by the
script that reads it, never on a command line of ours, never printed.
(`ktpass` takes `-pass` on its own command line, on the host; there is no other
way to have it set a known password, and its output is discarded.)

**The password files.** One line each. `provision.sh passwords` makes
`<32 hex digits>-Aa1`: if you choose your own, it must meet AD's complexity
rules and contain nothing cmd.exe treats specially (`& | < > ^ % "`).
`dsrm-password.txt` is Directory Services Restore Mode's, needed only for
disaster recovery. `users-password.txt` is every test account's.

1. **`state.ps1`** (read-only; `prepare` runs it first): DNS, interfaces, the
   inbound rules admitting ssh, what listens. Worth a look before and after.
2. **`firewall.ps1`**: inbound block rules for AD's TCP (53, 88, 135, 139,
   389, 445, 464, 593, 636, 3268-9, 5722, 9389, 49152-65535) and UDP (53, 88,
   123, 137-8, 389, 464, 500, 4500) ports, then
   `Install-WindowsFeature AD-Domain-Services`. These rules also block RPC and
   SMB from outside: remote management tools will not work, use ssh.
3. **`schedule.ps1`**, then **`promote.ps1`**: reads `C:\Goose\dc_p.txt` and
   starts a scheduled task as SYSTEM, so the promotion survives the ssh
   session, which it would otherwise kill. `Install-ADDSForest` with DNS, at
   the Windows Server 2016 functional level, then a reboot. Its log is
   `C:\Goose\dc\promote.log`.
4. **`setup.ps1`**: see below. It restarts the KDC, for the claims policy.
5. **`claims.ps1`**, **`s4u.ps1`**: see below.
   For the cross-realm tests, with a second forest and a two-way trust
   (test/README.md), **`xrealm-s4u.ps1 -ProxySID <the other forest's
   svc-proxy's SID>`** on each (not part of `provision.sh`; copy the users'
   password to `C:\Goose\dc\users.txt` first, as `provision.sh` does).
6. **`xpress.ps1`** (not part of `provision.sh`; run it only to regenerate
   vectors): Windows' own compressor over many inputs:

       powershell -ExecutionPolicy Bypass -File C:\Goose\scripts\xpress.ps1 -Out C:\Goose\xpress.txt

   then copy it back and `gzip -9` it to `pac/xpress/testdata/windows.txt.gz`.
   That file is in the repository, so no live DC is needed for the test.

To run a step by hand, as Administrator on the host: put the password file
in `C:\Goose\dc\users.txt`, and
`powershell -ExecutionPolicy Bypass -File C:\Goose\scripts\NAME.ps1`. Each of
`setup`, `claims`, `s4u` deletes it, so copy it again for the next.

The client side by hand, should you not use `provision.sh`:

    ssh -N -L 127.0.0.1:8888:127.0.0.1:88 -L 127.0.0.1:3890:127.0.0.1:389 Administrator@DC &
    scp Administrator@DC:C:/Goose/dc/web.keytab $DIR/web.keytab

and `$DIR/krb5.conf`:

    [libdefaults]
        default_realm = GOOSE.TEST
        dns_lookup_kdc = false
        rdns = false
        udp_preference_limit = 1
        default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
        default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    [realms]
        GOOSE.TEST = {
            kdc = 127.0.0.1:8888
        }
    [domain_realm]
        .goose.test = GOOSE.TEST
        goose.test = GOOSE.TEST

`udp_preference_limit = 1` because ssh forwards TCP only.

## What is in the domain

All have the users' password, and never expiring. "AES" is
`msDS-SupportedEncryptionTypes = 0x18`.

| Account | Script | What it is |
|---|---|---|
| `alice` | setup | a user, AES; department `Engineering`, hence a claim; in GooseTesters |
| `bob` | setup | a user, AES and RC4 (0x1c); in GooseTesters |
| `svc-web` | setup | the service `HTTP/web.goose.test` and `host/web.goose.test`, AES with claims and compound identity supported (0x60018); its key in `web.keytab` |
| `goosepc$` | setup | a computer, AES: the device whose TGT armors a request |
| `carol` | claims | a user, AES, with six long string claims: enough that the KDC compresses them |
| `svc-proxy` | s4u | `HTTP/proxy.goose.test`: protocol transition, and may delegate to `HTTP/target.goose.test` |
| `svc-kerb` | s4u | `HTTP/kerb.goose.test`: may delegate to the target, without protocol transition |
| `svc-self` | s4u | `HTTP/self.goose.test`: no delegation at all |
| `svc-target` | s4u | `HTTP/target.goose.test`: the delegation target |
| `svc-rbcd` | s4u | `HTTP/rbcd.goose.test`: no delegation of its own |
| `svc-rbcdt` | s4u | `HTTP/rbcdt.goose.test`: lets svc-rbcd delegate to it (resource-based) |
| `sens` | s4u | a user, "sensitive and cannot be delegated" |
| `certie` | s4u | a user mapped to a certificate: `altSecurityIdentities` = `X509:<SKI>...`, the bytes of `goose-s4u-certie-ski` |

And the group `GooseTesters`; the claim types `department` and `goose-title`,
`-company`, `-streetAddress`, `-physicalDeliveryOfficeName`, `-displayName`,
`-l`; the KDC policy "KDC support for claims, compound authentication and
Kerberos armoring" (registry values `EnableCbacAndArmor` and
`CbacAndArmorLevel` = 1, under `...\Policies\System\KDC\Parameters`, as a
GPO would set them).

## Which test needs what

| Scenario | Test | Uses |
|---|---|---|
| Logging in to a KDC with armoring support on (it answers without PA-FX-FAST) | every test here | the KDC policy |
| A PAC's server signature, client info, logon info; a KDC signature's presence | `messages`: `TestTicket_PAC_AD` | alice, bob, `web.keytab` |
| Claims in the PAC: plain, and compressed with LZ77+Huffman | `pac`: `TestPAC_Claims_AD` | alice, carol, `web.keytab` |
| Windows' compressor against our decompressor | `pac/xpress`: `windows_test.go` | no DC: `testdata/windows.txt.gz`, from `xpress.ps1` |
| Clock skew learned from the KDC, the client 20 minutes off either way | `client`: `TestClient_ClockSkew_AD` | alice |
| FAST: armored logins, an AS request refused inside the armor, compound identity (device info and claims in the PAC) | `client`: `TestClient_FAST_AD` | goosepc$, alice, `web.keytab` |
| S4U2Self by name and enterprise name; S4U2Proxy from S4U2Self's ticket and the user's own; the target reads the PAC and delegation info | `client`: `TestClient_S4U_AD` | svc-proxy, svc-target, alice |
| A target not allowed | the same | svc-proxy, svc-rbcdt |
| Kerberos-only delegation: S4U2Self's ticket not forwardable and refused, the user's own works | the same | svc-kerb, alice |
| No delegation configured: forwardable all the same, S4U2Proxy refuses | the same | svc-self |
| A sensitive user: S4U2Proxy refused | the same | sens, svc-proxy |
| Resource-based delegation, allowed and not | the same | svc-rbcd, svc-rbcdt, svc-target |
| S4U armored with FAST | the same | svc-proxy |
| S4U2Self by certificate, on to S4U2Proxy, armored; a certificate mapped to nobody; no protocol transition: not forwardable | `client`: `TestClient_S4UCert_AD` | certie, svc-proxy, svc-target, svc-kerb |
| Cross-realm S4U2Self: the peer forest's users, their PAC; a user it has not | `client`: `TestClient_S4UCrossRealm_AD`, needing `TEST_AD_PEER_REALM` | svc-proxy, the peer's alice and bob |
| Cross-realm S4U2Proxy: to the peer's target by a proxy TGT, the delegation info; the peer's user to a target here; the peer's user back to the peer refused | `client`: `TestClient_S4UProxyCrossRealm_AD`, needing `TEST_AD_PEER_PASSWORD_FILE` too | svc-proxy, svc-target, the peer's svc-xtarget and bob |
| LDAP with SASL GSSAPI at each protection level, Who am I, SID lookups, tokenGroups against the PAC's groups | `ldap`: `TestAD_LDAP`, needing `TEST_AD_LDAP`, `TEST_AD_DC_HOST` | alice, GooseTesters, `web.keytab` |

S4U2Self by certificate needs no CA on the DC. The test makes its certificates
itself, RSA client certificates with the identifier `certie` is mapped to,
from a CA the DC does not know. Server 2022's KDC issued tickets for those, and
for an expired one. That shape is the only one known to work: keep new tests
to it.

## When something is off

- **`verify.ps1`** says what is missing. Each script can be rerun on its own.
- **A login fails with a pre-authentication error:** the account's password is
  not `users-password.txt`'s. `domain` sets them all again.
- **No key found in `web.keytab` for a ticket's key version:** the keytab is
  older than the last `domain`. Copy it again.
- **The KDC or LDAP is unreachable:** the tunnel is down. From outside the host
  those ports are blocked, as they should be.
- **S4U tests say "not forwardable":** the service's TGT must be forwardable;
  the tests set it, your own code needs `forwardable = true`.
- **The promotion seems stuck:** `C:\Goose\dc\promote.log`. On a small host it
  takes minutes, then ssh drops for the reboot.
- **DNS on the host changes at promotion:** it becomes its own DNS server,
  forwarding to the old ones. A warning about a static address is normal on
  DHCP hosts, which is why `Install-ADDSForest` runs with `-Force`.

## Taking it down

The domain cannot be left behind in pieces. Terminate the host, or
`Uninstall-ADDSDomainController -LastDomainControllerInDomain -RemoveApplicationPartitions`
(asks for a new local Administrator password, reboots). The firewall rules go with
`Remove-NetFirewallRule -DisplayName 'Goose: block AD*'`.
