#!/bin/sh
## Generates the certificates and keys used by the TLS tests (valid for 100 years).
## The CA keys are discarded, only the files used by the tests are kept.
## Usage: sh make-certs.sh (in this directory), OPENSSL can point to the openssl tool
set -e
: ${OPENSSL=openssl}
DAYS=36500
T=`mktemp -d`
trap 'rm -rf "$T"' EXIT

key() { "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

## <name> <subject> <extensions> <issuer cert> <issuer key>
cert() {
    key "$T/$1.key"
    "$OPENSSL" req -new -key "$T/$1.key" -subj "$2" -out "$T/$1.csr"
    printf '%s\n' "$3" > "$T/$1.ext"
    if [ -z "$4" ]; then
        "$OPENSSL" x509 -req -in "$T/$1.csr" -signkey "$T/$1.key" -days $DAYS -extfile "$T/$1.ext" -out "$T/$1.pem"
    else
        "$OPENSSL" x509 -req -in "$T/$1.csr" -CA "$4" -CAkey "$5" -CAcreateserial -days $DAYS -extfile "$T/$1.ext" -out "$T/$1.pem"
    fi
}

CA='basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign'
CLIENT='basicConstraints=CA:FALSE
extendedKeyUsage=clientAuth'

## server side: root CA -> intermediate CA -> localhost
cert ca "/CN=Rserve test root CA" "$CA"
cert inter "/CN=Rserve test intermediate CA" "$CA" "$T/ca.pem" "$T/ca.key"
cert server "/CN=localhost" 'basicConstraints=CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1' "$T/inter.pem" "$T/inter.key"

## client side: client CA -> alice, bob.example.org, carol; rogue CA -> alice
cert client-ca "/CN=Rserve test client CA" "$CA"
cert rogue-ca "/CN=Rserve test rogue CA" "$CA"
cert alice "/CN=alice" "$CLIENT" "$T/client-ca.pem" "$T/client-ca.key"
cert bob "/CN=bob.example.org" "$CLIENT" "$T/client-ca.pem" "$T/client-ca.key"
cert carol "/CN=carol" "$CLIENT" "$T/client-ca.pem" "$T/client-ca.key"
cert rogue "/CN=alice" "$CLIENT" "$T/rogue-ca.pem" "$T/rogue-ca.key"

cp "$T/ca.pem" "$T/inter.pem" "$T/server.pem" "$T/server.key" "$T/client-ca.pem" .
for c in alice bob carol rogue; do cat "$T/$c.pem" "$T/$c.key" > $c.pem; done
cat "$T/server.pem" "$T/inter.pem" > server-chain.pem
cat "$T/server.key" "$T/server.pem" "$T/inter.pem" > server-combined.pem
"$OPENSSL" pkey -in "$T/server.key" -aes256 -passout pass:test -out server-enc.key
