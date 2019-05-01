#!/bin/bash

###########
# Build OpenSSH
#
# Must be run after OQS has been installed
###########

set -exo pipefail

PREFIX=${PREFIX:-"`pwd`/tmp/install"}
WITH_OPENSSL=${WITH_OPENSSL:-"true"}
WITH_PQAUTH=${WITH_PQAUTH:-"true"}

case "$OSTYPE" in
    darwin*)  OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr/local/opt/openssl"} ;;
    linux*)   OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr"} ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac

if [ "x${WITH_PQAUTH}" == "xtrue" ]; then
    PQAUTH_ARG="--enable-pq-auth --enable-hybrid-auth"
else
    PQAUTH_ARG=""
fi

cd ..
autoreconf -i
if [ "x${WITH_OPENSSL}" == "xtrue" ]; then
    ./configure --prefix="${PREFIX}" --enable-pq-kex --enable-hybrid-kex ${PQAUTH_ARG} --with-ldflags="-Wl,-rpath -Wl,${PREFIX}/lib" --with-libs=-lm --with-ssl-dir="${OPENSSL_SYS_DIR}" --with-liboqs-dir="${PREFIX}" --with-cflags="-I${PREFIX}/include" --sysconfdir="${PREFIX}"
else
    ./configure --prefix="${PREFIX}" --enable-pq-kex --enable-hybrid-kex ${PQAUTH_ARG} --with-ldflags="-Wl,-rpath -Wl,${PREFIX}/lib" --with-libs=-lm --without-openssl --with-liboqs-dir="${PREFIX}" --with-cflags="-I${PREFIX}/include" --sysconfdir="${PREFIX}"
fi
if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi
make install
