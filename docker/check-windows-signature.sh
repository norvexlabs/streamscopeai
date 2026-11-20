#!/bin/sh
# Succeed only when an executable carries exactly one Authenticode signature, made by the given
# certificate, with a valid RFC 3161 timestamp — the signature the Windows CLI is served with.
#
#   check-windows-signature.sh <exe> <certificate.cer (DER)>
#
# `osslsigncode verify` alone does not say that: it exits 0 when ANY of several nested signatures
# verifies (a foreign primary signature, the one Windows shows, with ours nested under it passes),
# and when the signature has no timestamp at all (it then dies with the certificate). Hence the
# three checks after it. Needs osslsigncode, openssl and the system CA bundle (the timestamp
# authority's chain). Reads no CRL: the certificate is self-signed and names no distribution point,
# and a check must not depend on reaching the timestamp authority's.
set -eu
exe=$1
cer=$2
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() {
  [ ! -s "$t/verify.log" ] || cat "$t/verify.log" >&2
  echo "ERROR: $exe: $*" >&2
  exit 1
}

openssl x509 -inform DER -in "$cer" -out "$t/ca.pem"
osslsigncode verify -CAfile "$t/ca.pem" -TSA-CAfile /etc/ssl/certs/ca-certificates.crt -ignore-crl \
  -in "$exe" >"$t/verify.log" 2>&1 || fail "its signature does not verify against $(basename "$cer")"
[ "$(grep -c '^Signature Index:' "$t/verify.log")" = 1 ] || fail "it carries more than one signature"
grep -qx 'Timestamp Server Signature verification: ok' "$t/verify.log" \
  || fail "its signature has no valid timestamp"
# The primary signature's own certificate set: exactly the signer's, and it is ours.
osslsigncode extract-signature -pem -in "$exe" -out "$t/sig.pem" >/dev/null 2>&1 \
  || fail "its signature cannot be extracted"
openssl pkcs7 -in "$t/sig.pem" -print_certs -out "$t/certs.pem"
[ "$(grep -c 'BEGIN CERTIFICATE' "$t/certs.pem")" = 1 ] \
  || fail "its signature carries a certificate besides the signer's"
[ "$(openssl x509 -in "$t/certs.pem" -noout -fingerprint -sha256)" \
  = "$(openssl x509 -in "$t/ca.pem" -noout -fingerprint -sha256)" ] \
  || fail "its signer is not $(basename "$cer")"
