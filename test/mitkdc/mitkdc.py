#!/usr/bin/env python3
"""MIT KDCs for this module's integration tests, on 127.0.0.1 only.

The KDCs, their databases, keytabs and krb5.conf live in one directory
(DIR, a new temporary one unless --dir names it). Tests find it through
TEST_MIT_DIR (see test/README.md):

    python3 test/mitkdc/mitkdc.py --dir /tmp/mitkdc &
    INTEGRATION=1 TEST_MIT_DIR=/tmp/mitkdc go test ./...

A.TEST, served by one krb5kdc on a free loopback port (UDP and TCP):

    alice     password "alice-pw", aes, sha2, rc4 and camellia keys
    bob       password "bob-pw", pre-authentication required
    HTTP/svc.a.test, host/svc.a.test   random keys, in DIR/svc.keytab
    krbtgt/A.TEST   its keys exported to DIR/krbtgt.keytab, so that tests
                    can check the KDC's signatures in PACs

K.TEST, served by a second krb5kdc whose clock runs SKEW seconds (900)
ahead of ours (krb5kdc -T), for the clock skew tests:

    kim       password "kim-pw", pre-authentication required
    HTTP/svc.k.test   random key, in DIR/svc.keytab

F.TEST, served by a krb5kdc whose encrypted-timestamp module is disabled
([plugins] kdcpreauth), so that a password works only through FAST's
encrypted challenge:

    grace     password "grace-pw", pre-authentication required
    host/fast.f.test   random aes keys, in DIR/fast.keytab: its TGT (no
                       pre-authentication) is the armor
    HTTP/svc.f.test    random key

S.TEST, served by a krb5kdc offering SPAKE in all four groups and not
encrypted timestamp:

    sam       password "sam-pw", pre-authentication required
    sam-ETYPE password "sam-ETYPE-pw", keys of that type only (aes128,
              aes256, sha2-128, sha2-256, rc4, cam128, cam256)
    host/fast.s.test   random aes keys, in DIR/s-fast.keytab (the armor)

O.TEST, served by a krb5kdc that sends an optimistic edwards25519 SPAKE
challenge and takes edwards25519 and P-256 only:

    olga      password "olga-pw", pre-authentication required

P.TEST, Q.TEST, R.TEST and N.TEST, served by one krb5kdc with PKINIT; their
certificates are made by pki.py (OpenSSL) in DIR/pki, CA DIR/pki/ca.pem:

    P.TEST    pat (password "pat-pw" too), WELLKNOWN/ANONYMOUS (anonymous
              PKINIT), HTTP/svc.p.test; UPN SANs taken
    Q.TEST    quinn: freshness tokens required, groups of 4096 bits and up
    R.TEST    rita: the KDC's certificate names it by dNSName kdc.r.test only
    N.TEST    nate: the KDC's certificate has the EKU serverAuth, not KPKdc

The MIT KDC issues PACs (1.20 and later) with server, KDC, full and
ticket signatures. Its binaries are Homebrew's keg-only krb5
(`brew --prefix krb5`) unless --mit names another prefix (Debian:
--mit /usr, with krb5-kdc and krb5-admin-server installed); macOS's own
kinit on the PATH is Heimdal's.

DIR/env holds KRB5_CONFIG, TEST_MIT_DIR, the ports and TEST_MIT_BIN (MIT's
kinit, klist, kvno, for the tests that check what this module writes), as
shell assignments. Ctrl-C (or SIGTERM) stops the KDCs.
"""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pki import Pki  # noqa: E402

REALM_A = "A.TEST"
REALM_K = "K.TEST"
REALM_F = "F.TEST"
REALM_S = "S.TEST"
REALM_O = "O.TEST"
PKINIT_REALMS = ("P.TEST", "Q.TEST", "R.TEST", "N.TEST")
# S.TEST's one-type users: their names' suffixes and MIT's enctype names.
SAM_ETYPES = [("aes128", "aes128-cts-hmac-sha1-96"), ("aes256", "aes256-cts-hmac-sha1-96"),
              ("sha2-128", "aes128-cts-hmac-sha256-128"), ("sha2-256", "aes256-cts-hmac-sha384-192"),
              ("rc4", "arcfour-hmac"), ("cam128", "camellia128-cts-cmac"), ("cam256", "camellia256-cts-cmac")]
AES = "aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal"
NO_TIMESTAMP = """[plugins]
    kdcpreauth = {
        disable = encrypted_timestamp
    }
"""
SKEW = 900
ENCTYPES = ("aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal "
            "aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal "
            "arcfour-hmac:normal camellia256-cts-cmac:normal camellia128-cts-cmac:normal")


def mit_prefix(arg=None):
    if arg:
        return arg
    try:
        p = subprocess.run(["brew", "--prefix", "krb5"], capture_output=True, text=True, check=True).stdout.strip()
        if p and os.path.isdir(p):
            return p
    except (OSError, subprocess.CalledProcessError):
        pass
    for p in ("/opt/homebrew/opt/krb5", "/usr/local/opt/krb5", "/usr"):
        if os.path.exists(os.path.join(p, "sbin", "krb5kdc")):
            return p
    sys.exit("no MIT krb5 found: pass --mit PREFIX")


def free_port():
    # A port free for both UDP and TCP on 127.0.0.1.
    for _ in range(100):
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.bind(("127.0.0.1", 0))
        port = t.getsockname()[1]
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            u.close()
            t.close()
    raise RuntimeError("no free port")


class Kdc:
    def __init__(self, directory=None, mit=None, quiet=True):
        self.mit = mit_prefix(mit)
        self.own_dir = directory is None
        self.dir = directory or tempfile.mkdtemp(prefix="mitkdc-")
        self.quiet = quiet
        self.port_a = free_port()
        self.port_k = free_port()
        self.port_f = free_port()
        self.port_s = free_port()
        self.port_o = free_port()
        self.ports_p = {r: free_port() for r in PKINIT_REALMS}
        self.procs = []

    def bin(self, name):
        for sub in ("sbin", "bin"):
            p = os.path.join(self.mit, sub, name)
            if os.path.exists(p):
                return p
        raise FileNotFoundError(name)

    def path(self, name):
        return os.path.join(self.dir, name)

    def run(self, args, env):
        p = subprocess.run(args, env=env, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"{' '.join(args)}: {p.stdout}{p.stderr}")
        return p.stdout

    def kadmin(self, realm, query):
        return self.run([self.bin("kadmin.local"), "-r", realm, "-q", query], self.envs[realm])

    def realm_block(self, name, realm, port, more=""):
        d = self.dir
        os.makedirs(self.path(name), exist_ok=True)
        open(self.path(f"{name}/kadm5.acl"), "w").close()
        return f"""    {realm} = {{
        database_name = {d}/{name}/principal
        key_stash_file = {d}/{name}/stash
        acl_file = {d}/{name}/kadm5.acl
        kdc_listen = 127.0.0.1:{port}
        kdc_tcp_listen = 127.0.0.1:{port}
        kadmind_listen = 127.0.0.1:{free_port()}
        kpasswd_listen = 127.0.0.1:{free_port()}
        master_key_type = aes256-cts
        supported_enctypes = {ENCTYPES}
        max_life = 10h
        max_renewable_life = 7d{more}
    }}
"""

    # kdc-NAME.conf: one realm on its own port, `extra` after its [realms],
    # `kdcdefaults` added to its [kdcdefaults].
    def realm_conf(self, name, realm, port, extra="", kdcdefaults=""):
        d = self.dir
        conf = self.path(f"kdc-{name}.conf")
        with open(conf, "w") as f:
            f.write(f"""[kdcdefaults]
    kdc_listen = 127.0.0.1:{port}
    kdc_tcp_listen = 127.0.0.1:{port}{kdcdefaults}

[realms]
{self.realm_block(name, realm, port)}
{extra}
[logging]
    kdc = FILE:{d}/kdc-{name}.log
""")
        return dict(os.environ, KRB5_CONFIG=self.path("krb5.conf"), KRB5_KDC_PROFILE=conf)

    # kdc-p.conf: the PKINIT realms, in one krb5kdc, each on its own port.
    def pkinit_conf(self):
        d, pki = self.dir, self.path("pki")
        Pki(pki).make()
        idents = {"P.TEST": "kdc", "Q.TEST": "kdc", "R.TEST": "kdc-dns", "N.TEST": "kdc-noeku"}
        extra = {"P.TEST": "pkinit_allow_upn = true",
                 "Q.TEST": "pkinit_require_freshness = true\n        pkinit_dh_min_bits = 4096"}
        realms = ""
        for r in PKINIT_REALMS:
            realms += self.realm_block("p" + r[0].lower(), r, self.ports_p[r], f"""
        pkinit_identity = FILE:{pki}/{idents[r]}.pem,{pki}/{idents[r]}.key
        pkinit_anchors = FILE:{pki}/ca.pem
        {extra.get(r, "")}""")
        ports = ",".join(f"127.0.0.1:{self.ports_p[r]}" for r in PKINIT_REALMS)
        conf = self.path("kdc-p.conf")
        with open(conf, "w") as f:
            f.write(f"""[kdcdefaults]
    kdc_listen = {ports}
    kdc_tcp_listen = {ports}

[realms]
{realms}
[logging]
    kdc = FILE:{d}/kdc-p.log
""")
        return dict(os.environ, KRB5_CONFIG=self.path("krb5.conf"), KRB5_KDC_PROFILE=conf)

    def write_conf(self):
        pki = self.path("pki")
        pkinit_client = "\n".join(f"""    {r} = {{
        kdc = 127.0.0.1:{self.ports_p[r]}
        pkinit_anchors = FILE:{pki}/ca.pem
    }}""" for r in PKINIT_REALMS)
        with open(self.path("krb5.conf"), "w") as f:
            f.write(f"""[libdefaults]
    default_realm = {REALM_A}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true
    allow_weak_crypto = true
    allow_rc4 = true
    permitted_enctypes = aes256-cts aes128-cts aes256-sha2 aes128-sha2 rc4-hmac camellia256-cts-cmac camellia128-cts-cmac

[realms]
    {REALM_A} = {{
        kdc = 127.0.0.1:{self.port_a}
    }}
    {REALM_K} = {{
        kdc = 127.0.0.1:{self.port_k}
    }}
    {REALM_F} = {{
        kdc = 127.0.0.1:{self.port_f}
    }}
    {REALM_S} = {{
        kdc = 127.0.0.1:{self.port_s}
    }}
    {REALM_O} = {{
        kdc = 127.0.0.1:{self.port_o}
    }}
{pkinit_client}

[domain_realm]
    .a.test = {REALM_A}
    a.test = {REALM_A}
    .k.test = {REALM_K}
    k.test = {REALM_K}
    .f.test = {REALM_F}
    .s.test = {REALM_S}
    .p.test = P.TEST
""")
        # A KDC's [libdefaults] (its profile is kdc.conf and krb5.conf)
        # holds its SPAKE groups, which no client reads.
        self.envs = {REALM_A: self.realm_conf("a", REALM_A, self.port_a),
                     REALM_K: self.realm_conf("k", REALM_K, self.port_k),
                     REALM_F: self.realm_conf("f", REALM_F, self.port_f, NO_TIMESTAMP),
                     REALM_S: self.realm_conf("s", REALM_S, self.port_s, NO_TIMESTAMP + """
[libdefaults]
    spake_preauth_groups = edwards25519 P-256 P-384 P-521
"""),
                     REALM_O: self.realm_conf("o", REALM_O, self.port_o, """
[libdefaults]
    spake_preauth_groups = edwards25519 P-256
""", """
    spake_preauth_kdc_challenge = edwards25519""")}
        penv = self.pkinit_conf()
        for r in PKINIT_REALMS:
            self.envs[r] = penv

    def create(self):
        for r in (REALM_A, REALM_K, REALM_F, REALM_S, REALM_O) + PKINIT_REALMS:
            self.run([self.bin("kdb5_util"), "-r", r, "create", "-s", "-P", "master-" + r.lower()], self.envs[r])
        a, k = REALM_A, REALM_K
        self.kadmin(a, "addprinc -pw alice-pw alice")
        self.kadmin(a, "addprinc -pw bob-pw +requires_preauth bob")
        self.kadmin(a, "addprinc -randkey HTTP/svc.a.test")
        self.kadmin(a, "addprinc -randkey host/svc.a.test")
        self.kadmin(a, f"ktadd -k {self.path('svc.keytab')} HTTP/svc.a.test host/svc.a.test")
        self.kadmin(a, f"ktadd -k {self.path('krbtgt.keytab')} -norandkey krbtgt/{a}")
        self.kadmin(k, "addprinc -pw kim-pw +requires_preauth kim")
        self.kadmin(k, "addprinc -randkey HTTP/svc.k.test")
        self.kadmin(k, f"ktadd -k {self.path('svc.keytab')} HTTP/svc.k.test")
        f = REALM_F
        self.kadmin(f, "addprinc -pw grace-pw +requires_preauth grace")
        self.kadmin(f, f"addprinc -randkey -e {AES} host/fast.f.test")
        self.kadmin(f, f"ktadd -k {self.path('fast.keytab')} host/fast.f.test")
        self.kadmin(f, "addprinc -randkey HTTP/svc.f.test")
        s_ = REALM_S
        self.kadmin(s_, "addprinc -pw sam-pw +requires_preauth sam")
        for suffix, etype in SAM_ETYPES:
            self.kadmin(s_, f"addprinc -pw sam-{suffix}-pw +requires_preauth -e {etype}:normal sam-{suffix}")
        self.kadmin(s_, f"addprinc -randkey -e {AES} host/fast.s.test")
        self.kadmin(s_, f"ktadd -k {self.path('s-fast.keytab')} host/fast.s.test")
        self.kadmin(REALM_O, "addprinc -pw olga-pw +requires_preauth olga")
        p = "P.TEST"
        self.kadmin(p, "addprinc -pw pat-pw +requires_preauth pat")
        self.kadmin(p, "addprinc -randkey WELLKNOWN/ANONYMOUS")
        self.kadmin(p, "addprinc -randkey HTTP/svc.p.test")
        self.kadmin("Q.TEST", "addprinc -randkey +requires_preauth quinn")
        self.kadmin("R.TEST", "addprinc -randkey +requires_preauth rita")
        self.kadmin("N.TEST", "addprinc -randkey +requires_preauth nate")

    def start(self):
        out = subprocess.DEVNULL if self.quiet else None
        self.procs.append(subprocess.Popen([self.bin("krb5kdc"), "-n", "-r", REALM_A], env=self.envs[REALM_A],
                                           stdout=out, stderr=out))
        self.procs.append(subprocess.Popen([self.bin("krb5kdc"), "-n", "-r", REALM_K, "-T", str(SKEW)],
                                           env=self.envs[REALM_K], stdout=out, stderr=out))
        for r in (REALM_F, REALM_S, REALM_O):
            self.procs.append(subprocess.Popen([self.bin("krb5kdc"), "-n", "-r", r], env=self.envs[r], stdout=out, stderr=out))
        self.procs.append(subprocess.Popen([self.bin("krb5kdc"), "-n"] + [x for r in PKINIT_REALMS for x in ("-r", r)],
                                           env=self.envs["P.TEST"], stdout=out, stderr=out))
        deadline = time.time() + 10
        while time.time() < deadline:
            if any(p.poll() is not None for p in self.procs):
                raise RuntimeError("krb5kdc exited: see the kdc-*.log files in " + self.dir)
            try:
                for port in (self.port_a, self.port_k, self.port_f, self.port_s, self.port_o, *self.ports_p.values()):
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("krb5kdc did not start")
        with open(self.path("env"), "w") as f:
            f.write(f"KRB5_CONFIG={self.path('krb5.conf')}\nTEST_MIT_DIR={self.dir}\n"
                    f"TEST_MIT_PORT_A={self.port_a}\nTEST_MIT_PORT_K={self.port_k}\nTEST_MIT_SKEW={SKEW}\n"
                    f"TEST_MIT_BIN={os.path.dirname(self.bin('klist'))}\n")

    def stop(self):
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()

    def __enter__(self):
        self.write_conf()
        self.create()
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        if self.own_dir:
            shutil.rmtree(self.dir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dir", help="the directory for the KDCs' files (emptied first)")
    ap.add_argument("--mit", help="MIT krb5's install prefix")
    args = ap.parse_args()
    if args.dir:
        shutil.rmtree(args.dir, ignore_errors=True)
        os.makedirs(args.dir)
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    with Kdc(args.dir, args.mit, quiet=False) as k:
        print(f"TEST_MIT_DIR={k.dir}")
        print(f"A.TEST on 127.0.0.1:{k.port_a}, K.TEST on 127.0.0.1:{k.port_k} (clock +{SKEW}s), "
              f"F.TEST :{k.port_f}, S.TEST :{k.port_s}, O.TEST :{k.port_o}, "
              + ", ".join(f"{r} :{p}" for r, p in k.ports_p.items()) + "; Ctrl-C to stop")
        sys.stdout.flush()
        try:
            signal.pause()
        except (KeyboardInterrupt, SystemExit):
            pass


if __name__ == "__main__":
    main()
