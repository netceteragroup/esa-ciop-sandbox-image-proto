#!/bin/sh
CERTURL=https://some.place.com/certificatedownload?user=$1&format=Ppem
if test "$1" == "" ; then echo usage: $0 '<username>' ; exit 1; fi
curl -s -o - --insecure "$CERTURL" | openssl x509 -inform pem -in /dev/stdin -noout -pubkey | ssh-keygen -f /dev/stdin -i -m PKCS8
