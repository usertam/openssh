#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_SYS_DIR: path to system OpenSSL installation; default /usr
#  - PREFIX: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

case "$OSTYPE" in
    darwin*)  OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr/local/opt/openssl"} ;;
    linux*)   OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr"} ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac

PREFIX=${PREFIX:-"`pwd`/tmp/install"}

cd tmp/liboqs
autoreconf -i
if [ "x${CIRCLECI}" == "xtrue" ]; then
    BIKEARG="--disable-kem-bike"
    # FIXME: BIKE doesn't work on CircleCI due to symbol _CMP_LT_OS not being defined
else
    BIKEARG=
fi
./configure --prefix=${PREFIX} --with-pic=yes --enable-openssl --with-openssl-dir=${OPENSSL_SYS_DIR} ${BIKEARG}
if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi
make install
