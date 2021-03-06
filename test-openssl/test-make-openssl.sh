#!/bin/bash

sudo apt-get install build-essential

#https://askubuntu.com/a/914260

wget https://openssl.org/source/openssl-1.0.2k.tar.gz
tar -xvf openssl-1.0.2k.tar.gz
(
cd openssl-1.0.2k/
# --prefix will make sure that make install copies the files locally instead of system-wide
# --openssldir will make sure that the binary will look in the regular system location for openssl.cnf
# no-shared builds a mostly static binary
./config --prefix=`pwd`/local --openssldir=/usr/lib/ssl enable-ssl2 enable-ssl3 no-shared enable-weak-ssl-ciphers
make depend
make
make -i install
)

echo ./openssl-1.0.2k/local/bin/openssl version
./openssl-1.0.2k/local/bin/openssl version
