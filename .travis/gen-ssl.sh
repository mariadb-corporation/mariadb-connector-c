#!/bin/bash
set -e

log () {
  echo "$@" 1>&2
}

print_error () {
  echo "$@" 1>&2
  exit 1
}

print_usage () {
  print_error "Usage: gen-ssl-cert-key <fqdn> <output-dir>"
}

gen_cert_subject () {
  local fqdn="$1"
  [[ "${fqdn}" != "" ]] || print_error "FQDN cannot be blank"
  echo "/C=XX/ST=X/O=X/localityName=X/CN=${fqdn}/organizationalUnitName=X/emailAddress=X/"
}

main () {
  local fqdn="$1"
  local sslDir="$2"
  [[ "${fqdn}" != "" ]] || print_usage
  [[ -d "${sslDir}" ]] || print_error "Directory does not exist: ${sslDir}"

  local caCertFile="${sslDir}/ca.crt"
  local caKeyFile="${sslDir}/ca.key"
  local certFile="${sslDir}/server.crt"
  local certShaFile="${sslDir}/server-cert.sha1"
  local keyFile="${sslDir}/server.key"
  local csrFile=$(mktemp)
  local clientCertFile="${sslDir}/client-cert.pem"
  local clientKeyFile="${sslDir}/client-key.pem"
  local clientEncryptedKeyFile="${sslDir}/client-key-enc.pem"
  local clientCombinedFile="${sslDir}/client-certkey.pem"
  local clientKeystoreFile="${sslDir}/client-keystore.jks"
  local fullClientKeystoreFile="${sslDir}/fullclient-keystore.jks"
  local tmpKeystoreFile=$(mktemp)
  local pcks12FullKeystoreFile="${sslDir}/fullclient-keystore.p12"
  local clientReqFile=$(mktemp)

  rm -rf demoCA
  mkdir demoCA demoCA/newcerts
  touch demoCA/index.txt
  echo 01 > demoCA/serial
  echo 01 > demoCA/crlnumber

  log "# Generating CA key"
  openssl genrsa -out "${caKeyFile}" 2048

  log "# Generating CA certificate"
  openssl req \
    -x509 \
    -newkey rsa:2048 -keyout "${caKeyFile}" \
    -out "${caCertFile}" \
    -days 3650 \
    -nodes \
    -subj "$(gen_cert_subject ca.example.com)" \
    -text

  log "# Server certificate signing request and private key"
  openssl req \
    -newkey rsa:2048 -keyout "${keyFile}" \
    -out "./demoCA/server-req.pem" \
    -nodes \
    -subj "$(gen_cert_subject "$fqdn")"


  log "# Convert the key to yassl compatible format"
  openssl rsa -in "${keyFile}" -out "${keyFile}"

  log "# Sign the server certificate with CA certificate"
  openssl ca -keyfile "${caKeyFile}" -days 3650 -batch \
    -cert "${caCertFile}" -policy policy_anything -out "${certFile}" -in "./demoCA/server-req.pem"

  log "Generating client certificate"
  openssl req \
    -newkey rsa:2048 \
    -keyout "${clientKeyFile}" \
    -out demoCA/client-req.pem \
    -days 7300 \
    -nodes \
    -subj /CN=client/C=FI/ST=Helsinki/L=Helsinki/O=MariaDB 

  openssl rsa \
     -in "${clientKeyFile}" \
     -out "${clientKeyFile}"

  openssl ca -keyfile "${caKeyFile}" \
      -days 7300 \
      -batch \
      -cert "${caCertFile}" \
      -policy policy_anything \
      -out "${clientCertFile}" \
      -in demoCA/client-req.pem

  log "Generating password protected client key file"
  openssl rsa \
     -aes256 \
     -in "${clientKeyFile}" \
     -out "${clientEncryptedKeyFile}" \
     -passout pass:qwerty

   log "combined"
   cat "${clientCertFile}" "${clientKeyFile}" > "${clientCombinedFile}"

   log "Generating finger print of server certificate"
   openssl x509 \
     -noout \
     -fingerprint \
     -sha1 \
     -inform pem \
     -in "${certFile}" | \
     sed -e  "s/SHA1 Fingerprint=//g" \
     > "${certShaFile}"

  log "copy ca file"
    cp "${caCertFile}" "${sslDir}/cacert.pem"

  # Clean up CSR file:
  rm "$csrFile"
  rm "$clientReqFile"
  rm "$tmpKeystoreFile"
#  rm -rf demoCA 

  log "Generated key file and certificate in: ${sslDir}"
  ls -l "${sslDir}"
}

main "$@"

