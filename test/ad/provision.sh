#!/bin/sh
# Sets up the AD domain controller the live tests use, from the test machine,
# over ssh to a Windows Server host. README.md explains every step.
#
#   test/ad/provision.sh passwords DIR       make the two password files in DIR
#   test/ad/provision.sh prepare HOST        scripts copied, ports blocked, AD DS role
#   test/ad/provision.sh promote HOST DIR    the forest; the host reboots
#   test/ad/provision.sh domain HOST DIR     accounts and policy; keytab and krb5.conf to DIR
#   test/ad/provision.sh verify HOST         read-only check of all of it
#   test/ad/provision.sh tunnel HOST         ssh tunnels to the KDC and LDAP, in the foreground
#
# HOST is user@address; the user must be an administrator of the host. DIR
# holds dsrm-password.txt, users-password.txt, krb5.conf and web.keytab: it
# is TEST_AD_DIR, and the password files never leave it but to be read and
# deleted on the host. SSH_OPTS adds options to ssh and scp. Passwords are
# never put on a command line here, nor printed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
ssh_opts=${SSH_OPTS:-}

usage() {
    sed -n '/^#   test/p' "$0" | sed 's/^#   //' >&2
    exit 2
}

remote() {
    # shellcheck disable=SC2086
    ssh $ssh_opts "$host" "$@"
}

copy() {
    # shellcheck disable=SC2086
    scp -q $ssh_opts "$@"
}

run() {
    echo "--- $1" >&2
    remote "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Goose\\scripts\\$1.ps1"
}

# The password file each script reads and deletes; a script that fails
# before reading it leaves it, so it goes over again for the next.
run_with_users() {
    copy "$dir/users-password.txt" "$host:C:/Goose/dc/users.txt"
    run "$1"
}

cmd=${1:-}
[ $# -ge 1 ] && shift

case "$cmd" in
passwords)
    [ $# -eq 1 ] || usage
    dir=$1
    mkdir -p "$dir"
    chmod 700 "$dir"
    umask 077
    # Hex and a fixed tail: AD's complexity rules are met, and nothing in it
    # means anything to cmd.exe, through which ktpass takes the password.
    for f in dsrm-password.txt users-password.txt; do
        if [ -e "$dir/$f" ]; then
            echo "keeping $dir/$f" >&2
        else
            printf '%s-Aa1\n' "$(openssl rand -hex 16)" > "$dir/$f"
            echo "made $dir/$f" >&2
        fi
    done
    ;;
prepare)
    [ $# -eq 1 ] || usage
    host=$1
    remote 'New-Item -ItemType Directory -Force -Path C:\Goose\scripts,C:\Goose\dc | Out-Null'
    copy "$here"/*.ps1 "$host:C:/Goose/scripts/"
    run state
    run firewall
    ;;
promote)
    [ $# -eq 2 ] || usage
    host=$1 dir=$2
    if remote '(Get-CimInstance Win32_ComputerSystem).DomainRole' | grep -q '^[45]'; then
        echo "$host is a domain controller already: not promoting" >&2
        exit 1
    fi
    copy "$dir/dsrm-password.txt" "$host:C:/Goose/dc_p.txt"
    run schedule
    echo 'The host reboots when the promotion is done (minutes). Then: provision.sh domain' >&2
    ;;
domain)
    [ $# -eq 2 ] || usage
    host=$1 dir=$2
    copy "$here"/*.ps1 "$host:C:/Goose/scripts/"
    run_with_users setup
    run_with_users claims
    run_with_users s4u
    umask 077
    copy "$host:C:/Goose/dc/web.keytab" "$dir/web.keytab"
    realm=$(remote '(Get-ADDomain).DNSRoot.ToUpper()' | tr -d '\r')
    domain=$(remote '(Get-ADDomain).DNSRoot' | tr -d '\r')
    cat > "$dir/krb5.conf" <<EOF
[libdefaults]
    default_realm = $realm
    dns_lookup_kdc = false
    rdns = false
    udp_preference_limit = 1
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    $realm = {
        kdc = 127.0.0.1:8888
    }

[domain_realm]
    .$domain = $realm
    $domain = $realm
EOF
    run verify
    ;;
verify)
    [ $# -eq 1 ] || usage
    host=$1
    copy "$here/verify.ps1" "$host:C:/Goose/scripts/"
    run verify
    ;;
tunnel)
    [ $# -eq 1 ] || usage
    host=$1
    # shellcheck disable=SC2086
    exec ssh -N $ssh_opts -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
        -L 127.0.0.1:8888:127.0.0.1:88 -L 127.0.0.1:3890:127.0.0.1:389 "$host"
    ;;
*)
    usage
    ;;
esac
