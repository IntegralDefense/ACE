#!/usr/bin/env bash

#
# installs and configures SSL certificates for ACE
#

source installer/common.sh

if [ -z "$SAQ_HOME" ]
then
    echo "missing SAQ_HOME environment variable"
    exit 1
fi

cd "$SAQ_HOME" || { echo "cannot cd to $SAQ_HOME"; exit 1; }

# initialize root certificate directory
(
    cd ssl/root/ca && \
    rm -rf certs crl newcerts private && \
    mkdir -p certs crl newcerts private && \
    chmod 700 private && \
    touch index.txt && \
    echo 1000 > serial
) || { echo "directory prep for CA failed"; exit 1; }

# create root CA key (requires password)
echo "You will be prompted for a password for the root CA here."
( 
    cd ssl/root/ca && \
    openssl genrsa -aes256 -out private/ca.key.pem 4096 && \
    chmod 400 private/ca.key.pem
) || { echo "unable to create root CA key"; exit 1; }

# create root CA certificate
(
    cd ssl/root/ca && \
    openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -out certs/ca.cert.pem && \
    chmod 444 certs/ca.cert.pem
) || { echo "unable to create root CA cert"; exit 1; }
    
# prepare intermediate directory
(
    cd ssl/root/ca/intermediate && \
    rm -rf certs crl csr newcerts private && \
    mkdir -p certs crl csr newcerts private && \
    chmod 700 private && \
    touch index.txt && \
    echo 1000 > serial && \
    echo 1000 > crlnumber
) || { echo "directory prep for intermediate failed"; exit 1; }

# create intermediate key
(
    cd ssl/root/ca && \
    openssl genrsa -aes256 -out intermediate/private/intermediate.key.pem 4096 && \
    chmod 400 intermediate/private/intermediate.key.pem
) || { echo "unable to create intermediate key"; exit 1; }

# create intermediate CA
(
    cd ssl/root/ca && \
    openssl req -config intermediate/openssl.cnf -new -sha256 -key intermediate/private/intermediate.key.pem -out intermediate/csr/intermediate.csr.pem && \
    openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem && \
    chmod 444 intermediate/certs/intermediate.cert.pem && \
    openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem && \
    cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem && \
    chmod 444 intermediate/certs/ca-chain.cert.pem
) || { echo "unable to create intermediate cert"; exit 1; }

# create the symlink for the CA root cert bundle
(cd ssl && ln -s root/intermediate/certs/ca-chain.cert.pem .)
