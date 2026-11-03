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

The MIT KDC issues PACs (1.20 and later) with server, KDC, full and
ticket signatures. Its binaries are Homebrew's keg-only krb5
(`brew --prefix krb5`) unless --mit names another prefix (Debian:
--mit /usr, with krb5-kdc and krb5-admin-server installed); macOS's own
kinit on the PATH is Heimdal's.

DIR/env holds KRB5_CONFIG, TEST_MIT_DIR and the ports, as shell
assignments. Ctrl-C (or SIGTERM) stops the KDCs.
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

REALM_A = "A.TEST"
REALM_K = "K.TEST"
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

    def realm_conf(self, name, realm, port):
        d = self.dir
        os.makedirs(self.path(name), exist_ok=True)
        open(self.path(f"{name}/kadm5.acl"), "w").close()
        conf = self.path(f"kdc-{name}.conf")
        with open(conf, "w") as f:
            f.write(f"""[kdcdefaults]
    kdc_listen = 127.0.0.1:{port}
    kdc_tcp_listen = 127.0.0.1:{port}

[realms]
    {realm} = {{
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
        max_renewable_life = 7d
    }}

[logging]
    kdc = FILE:{d}/kdc-{name}.log
""")
        return dict(os.environ, KRB5_CONFIG=self.path("krb5.conf"), KRB5_KDC_PROFILE=conf)

    def write_conf(self):
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

[domain_realm]
    .a.test = {REALM_A}
    a.test = {REALM_A}
    .k.test = {REALM_K}
    k.test = {REALM_K}
""")
        self.envs = {REALM_A: self.realm_conf("a", REALM_A, self.port_a),
                     REALM_K: self.realm_conf("k", REALM_K, self.port_k)}

    def create(self):
        for name, r in (("a", REALM_A), ("k", REALM_K)):
            self.run([self.bin("kdb5_util"), "-r", r, "create", "-s", "-P", "master-" + name], self.envs[r])
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

    def start(self):
        out = subprocess.DEVNULL if self.quiet else None
        self.procs.append(subprocess.Popen([self.bin("krb5kdc"), "-n", "-r", REALM_A], env=self.envs[REALM_A],
                                           stdout=out, stderr=out))
        self.procs.append(subprocess.Popen([self.bin("krb5kdc"), "-n", "-r", REALM_K, "-T", str(SKEW)],
                                           env=self.envs[REALM_K], stdout=out, stderr=out))
        deadline = time.time() + 10
        while time.time() < deadline:
            if any(p.poll() is not None for p in self.procs):
                raise RuntimeError("krb5kdc exited: see the kdc-*.log files in " + self.dir)
            try:
                for port in (self.port_a, self.port_k):
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("krb5kdc did not start")
        with open(self.path("env"), "w") as f:
            f.write(f"KRB5_CONFIG={self.path('krb5.conf')}\nTEST_MIT_DIR={self.dir}\n"
                    f"TEST_MIT_PORT_A={self.port_a}\nTEST_MIT_PORT_K={self.port_k}\nTEST_MIT_SKEW={SKEW}\n")

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
        print(f"A.TEST on 127.0.0.1:{k.port_a}, K.TEST on 127.0.0.1:{k.port_k} (clock +{SKEW}s); Ctrl-C to stop")
        sys.stdout.flush()
        try:
            signal.pause()
        except (KeyboardInterrupt, SystemExit):
            pass


if __name__ == "__main__":
    main()
