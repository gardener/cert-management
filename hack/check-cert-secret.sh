#!/usr/bin/env bash 
#
# Tool for extracting X509 certificate (and revocation information) from the certificate secret object.
# Run ./check-cert-secret to see commands
#
#

set -e

usage()
{
    cat <<EOM
Usage:
Helper for extracting information about the X509 certificate from the secret of a certificate object

./check-cert-secret.sh show-pem <namespace> <certificate name>
   show certificate PEM 

./check-cert-secret.sh show-txt <namespace> <certificate name>
   show certificate as text

./check-cert-secret.sh show-txt-all <namespace> <certificate name>
   show certificate and chain as text

./check-cert-secret.sh show-ocsp <namespace> <certificate name>
   show OCSP response using OpenSSL as text

./check-cert-secret.sh check-revoke <namespace> <certificate name>
   check OCSP revocation using OpenSSL

Prerequisites: 'kubectl' and 'openssl' must be on PATH. kubectl will use the current context.

EOM
}

if [ $# -ne 3 ]; then
  usage
  exit 1
fi

NS=$2
CERTNAME=$3
PREFIX="${TMPDIR}check-secret"
X509CERT="$PREFIX/cert"
certfile="$PREFIX/cert-0.pem"
immediatefile="$PREFIX/cert-1.pem"
ocspresponsefile="$PREFIX/ocsp.txt"

prepareParts()
{
    mkdir -p "$PREFIX"
    # extract certificate from certificate secret
    kubectl -n $NS get secret $(kubectl -n $NS get certificates.cert.gardener.cloud $CERTNAME  -o=jsonpath='{.spec.secretRef.name}') -o=jsonpath='{.data.tls\.crt}' | base64 -d > "$X509CERT"

    CSPLIT=gcsplit # use gnu csplit on mac (install with "brew install coreutils")
    which $CSPLIT || export CSPLIT=csplit
    # split certificate and chain
    $CSPLIT -s -z -f "$PREFIX/cert-" -b "%d.pem" $X509CERT '/-----BEGIN CERTIFICATE-----/' '{*}'
}

cleanup()
{
    rm -rf "$PREFIX"
}

showPEM()
{
    prepareParts
    cat $certfile
    cleanup
}

showTXT()
{
    prepareParts
    openssl x509 -noout -text -in $certfile
    cleanup
}

showTXTAll()
{
    prepareParts
    for f in $PREFIX/cert*.pem
    do
      openssl x509 -noout -text -in $f
      echo ""
      echo ""
    done
    cleanup
}

getOCSP()
{
  OSCP_URI=$(openssl x509 -noout -ocsp_uri -in $certfile)
  HOST=$(echo $OSCP_URI | awk '-F[/:]' '{print $4}')

  if [[ ! -f "$immediatefile" ]]; then
    immediatefile="$certfile"
  fi

  # Checking OCSP revocation using OpenSSL
  openssl ocsp -header HOST $HOST -no_nonce -issuer "$immediatefile" -cert "$certfile" -text -url $OSCP_URI > "$ocspresponsefile"
}

showOCSP()
{
    prepareParts
    getOCSP
    cat $ocspresponsefile
    cleanup
}

checkRevoke()
{
    prepareParts
    getOCSP

    STATUS=$(grep "Cert Status:" "$ocspresponsefile" || echo "")
    echo $STATUS
    if [  "$STATUS" = "" ]; then
        echo "error: Cert Status not found in OCSP response"
    fi
    if [[ $STATUS == *"good"* ]]; then
        echo "=> certificate is NOT revoked"
    fi

    if [[ $STATUS == *"revoked"* ]]; then
        echo "=> certificate is revoked"
    fi

    cleanup
}

case $1 in 
  show-pem )   shift
               showPEM
               ;;
  show-txt )   shift
               showTXT
               ;;
  show-txt-all )   shift
                   showTXTAll
                   ;;
  show-ocsp )  shift
               showOCSP
               ;;
  check-revoke ) shift
                 checkRevoke 
                 ;;  
  * )          shift
               usage
               exit 1
esac
