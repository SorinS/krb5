#!/usr/bin/env python3
"""Certificates for PKINIT's tests, made by OpenSSL (independent of this module's
own code): a CA for P.TEST and Q.TEST, the KDCs' certificates, users'
certificates, and a second CA nobody trusts.

    python3 test/mitkdc/pki.py DIR

writes into DIR, as PEM (NAME.pem with NAME.key):

    ca             the trusted CA (RSA 2048)
    kdc            P.TEST's and Q.TEST's KDC: EKU id-pkinit-KPKdc, id-pkinit-san
                   krbtgt/P.TEST@P.TEST and krbtgt/Q.TEST@Q.TEST
    kdc-dns        a KDC certificate (R.TEST) with a dNSName (kdc.r.test)
                   and no id-pkinit-san, for pkinit_kdc_hostname
    kdc-noeku      a KDC certificate (N.TEST) with the id-pkinit-san but EKU
                   serverAuth
    pat            pat@P.TEST, RSA 2048, EKU id-pkinit-KPClientAuth
    pat-p256       pat@P.TEST, ECDSA P-256
    pat-p384       pat@P.TEST, ECDSA P-384
    pat-p521       pat@P.TEST, ECDSA P-521
    pat-rsa3072    pat@P.TEST, RSA 3072, signed with SHA-384
    pat-inter      pat@P.TEST issued by an intermediate CA (inter.pem), which
                   the client sends with it
    pat-upn        pat@P.TEST as a Microsoft UPN SAN only
    pat-noeku      pat@P.TEST with EKU serverAuth only
    pat-other      pat@P.TEST from the untrusted CA (rogue)
    pat-expired    pat@P.TEST, expired
    quinn          quinn@Q.TEST, RSA 2048
    rita           rita@R.TEST and nate@N.TEST, RSA 2048
    rogue          the untrusted CA
    pat.p12        pat's key and certificate as PKCS #12, password "pat-p12"
"""

import os
import subprocess
import sys
import zlib


def openssl():
    for p in ("/opt/homebrew/bin/openssl", "/usr/local/opt/openssl/bin/openssl", "/usr/bin/openssl"):
        if os.path.exists(p):
            return p
    return "openssl"


# An otherName SAN holding a KRB5PrincipalName (RFC 4556 §3.2.2), in
# OpenSSL's ASN1_generate_nconf syntax, as MIT's pkinit-certs use it.
def princ_section(tag, realm, name_type, names):
    comps = "\n".join(f"c{i} = GeneralString:{n}" for i, n in enumerate(names))
    return f"""[{tag}]
realm = EXP:0,GeneralString:{realm}
principal_name = EXP:1,SEQUENCE:{tag}_name
[{tag}_name]
name_type = EXP:0,INTEGER:{name_type}
name_string = EXP:1,SEQUENCE:{tag}_comps
[{tag}_comps]
{comps}
"""


class Pki:
    def __init__(self, d):
        self.d = d
        self.ssl = openssl()
        os.makedirs(d, exist_ok=True)

    def path(self, name):
        return os.path.join(self.d, name)

    def run(self, args):
        p = subprocess.run([self.ssl] + args, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"openssl {' '.join(args)}: {p.stdout}{p.stderr}")

    def key(self, name, kind):
        out = self.path(name + ".key")
        if kind.startswith("rsa"):
            self.run(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:" + kind[3:], "-out", out])
        else:
            self.run(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + kind, "-out", out])

    def ca(self, name, cn, kind="rsa2048"):
        self.key(name, kind)
        conf = self.path(name + ".cnf")
        with open(conf, "w") as f:
            f.write("""[req]
distinguished_name = dn
[dn]
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
""")
        self.run(["req", "-x509", "-new", "-key", self.path(name + ".key"), "-subj", f"/O=Goose Tests/CN={cn}",
                  "-days", "3650", "-sha256", "-config", conf, "-extensions", "ext", "-out", self.path(name + ".pem")])

    # A certificate for NAME issued by ISSUER: `ext` holds the extension
    # lines, `sections` any sections they name.
    def cert(self, name, cn, issuer, ext, sections="", kind="rsa2048", days="365", digest="sha256", start=None):
        self.key(name, kind)
        csr = self.path(name + ".csr")
        self.run(["req", "-new", "-key", self.path(name + ".key"), "-subj", f"/O=Goose Tests/CN={cn}", "-out", csr])
        conf = self.path(name + ".ext")
        with open(conf, "w") as f:
            f.write("[ext]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n" + ext + "\n" + sections)
        args = ["x509", "-req", "-in", csr, "-CA", self.path(issuer + ".pem"), "-CAkey", self.path(issuer + ".key"),
                "-set_serial", str(zlib.crc32(name.encode()) + 1000), "-" + digest,
                "-extfile", conf, "-extensions", "ext", "-out", self.path(name + ".pem")]
        if start:
            args += ["-not_before", start[0], "-not_after", start[1]]
        else:
            args += ["-days", days]
        self.run(args)

    def make(self):
        self.ca("ca", "PKINIT Test CA")
        self.ca("rogue", "Rogue CA")
        kdc_san = (princ_section("kdc_p", "P.TEST", 2, ["krbtgt", "P.TEST"]) +
                   princ_section("kdc_q", "Q.TEST", 2, ["krbtgt", "Q.TEST"]))
        kdc_names = "otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_p,otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_q"
        self.cert("kdc", "kdc.p.test", "ca", f"""basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectAltName = {kdc_names}
""", kdc_san)
        self.cert("kdc-dns", "kdc.r.test", "ca", """basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.5
subjectAltName = DNS:kdc.r.test
""")
        self.cert("kdc-noeku", "kdc.s.test", "ca", """basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_n
""", princ_section("kdc_n", "N.TEST", 2, ["krbtgt", "N.TEST"]))
        pat = princ_section("pat", "P.TEST", 1, ["pat"])
        user = """basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:pat
"""
        self.cert("pat", "pat", "ca", user, pat)
        self.cert("pat-p256", "pat", "ca", user, pat, kind="P-256")
        self.cert("pat-p384", "pat", "ca", user, pat, kind="P-384")
        self.cert("pat-p521", "pat", "ca", user, pat, kind="P-521")
        self.cert("pat-rsa3072", "pat", "ca", user, pat, kind="rsa3072", digest="sha384")
        self.ca("inter", "PKINIT Intermediate CA")
        # The intermediate, re-issued by the root.
        self.run(["x509", "-in", self.path("inter.pem"), "-CA", self.path("ca.pem"), "-CAkey", self.path("ca.key"),
                  "-set_serial", "77", "-days", "3650", "-sha256", "-copy_extensions", "copyall",
                  "-out", self.path("inter.pem")])
        self.cert("pat-inter", "pat", "inter", user, pat)
        self.cert("pat-upn", "pat", "ca", """basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = 1.3.6.1.5.2.3.4
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:pat@P.TEST
""")
        self.cert("pat-noeku", "pat", "ca", user.replace("1.3.6.1.5.2.3.4", "serverAuth"), pat)
        self.cert("pat-other", "pat", "rogue", user, pat)
        self.cert("pat-expired", "pat", "ca", user, pat, start=("20200101000000Z", "20210101000000Z"))
        self.cert("quinn", "quinn", "ca", user.replace("SEQUENCE:pat", "SEQUENCE:quinn"),
                  princ_section("quinn", "Q.TEST", 1, ["quinn"]))
        self.cert("rita", "rita", "ca", user.replace("otherName:1.3.6.1.5.2.2;SEQUENCE:pat",
                                                     "otherName:1.3.6.1.5.2.2;SEQUENCE:rita,otherName:1.3.6.1.5.2.2;SEQUENCE:nate"),
                  princ_section("rita", "R.TEST", 1, ["rita"]) + princ_section("nate", "N.TEST", 1, ["nate"]))
        self.run(["pkcs12", "-export", "-in", self.path("pat.pem"), "-inkey", self.path("pat.key"),
                  "-passout", "pass:pat-p12", "-out", self.path("pat.p12")])


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: pki.py DIR")
    Pki(sys.argv[1]).make()


if __name__ == "__main__":
    main()
