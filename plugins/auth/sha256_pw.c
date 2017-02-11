/************************************************************************************
   Copyright (C) 2017 MariaDB Corporation AB

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc.,
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA
*************************************************************************************/
#ifndef _WIN32
#define _GNU_SOURCE 1
#endif

#include <ma_global.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <memory.h>
#include <errmsg.h>
#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>

#ifndef WIN32
#include <dlfcn.h>
#endif

#if defined(HAVE_OPENSSL)
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#elif defined(HAVE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#define MAX_PW_LEN 1024

/* function prototypes */
static int auth_sha256_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql);
static int auth_sha256_init(char *unused1,
                            size_t unused2,
                            int unused3,
                            va_list);


#ifndef HAVE_SHA256PW_DYNAMIC
struct st_mysql_client_plugin_AUTHENTICATION sha256_password_client_plugin=
#else
struct st_mysql_client_plugin_AUTHENTICATION _mysql_client_plugin_declaration_ =
#endif
{
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN,
  MYSQL_CLIENT_AUTHENTICATION_PLUGIN_INTERFACE_VERSION,
  "sha256_password",
  "Georg Richter",
  "SHA256 Authentication Plugin",
  {0,1,0},
  "LGPL",
  NULL,
  auth_sha256_init,
  NULL,
  NULL,
  auth_sha256_client
};


/* {{{ static int auth_256_client */
static int auth_sha256_client(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  unsigned char *packet;
  int packet_length;
  char passwd[MAX_PW_LEN];
  unsigned char rsa_enc_pw[MAX_PW_LEN];
  unsigned int pwlen, i;
  unsigned int rsa_size;
#if defined(HAVE_OPENSSL)
  RSA *pubkey= NULL;
#elif defined(HAVE_GNUTLS)
  gnutls_pubkey_t pubkey= NULL;
  gnutls_x509_crt_t crt;
#endif


  /* read error */
  if ((packet_length= vio->read_packet(vio, &packet)) < 0)
    return CR_ERROR;

  if (packet_length != SCRAMBLE_LENGTH + 1)
    return CR_SERVER_HANDSHAKE_ERR;

  memmove(mysql->scramble_buff, packet, SCRAMBLE_LENGTH);
  mysql->scramble_buff[SCRAMBLE_LENGTH]= 0;

  /* if a tls session is active we need to send plain password */
  if (mysql_get_ssl_cipher(mysql))
  {
    if (vio->write_packet(vio, (unsigned char *)mysql->passwd, strlen(mysql->passwd) + 1))
      return CR_ERROR;
    return CR_OK;
  }

  /* send empty packet if no password was provided */
  if (!mysql->passwd || !mysql->passwd[0])
  {
    if (vio->write_packet(vio, 0, 0))
      return CR_ERROR;
    return CR_OK;
  }

#if defined(HAVE_GNUTLS)
  if (gnutls_pubkey_init(&pubkey) < 0)
    return CR_ERROR;
#endif

  /* if no public key file was specified, try to obtain public key from server */
  if (!mysql->options.extension ||
      !mysql->options.extension->server_public_key)
  {
    unsigned char buf= 1;
    if (vio->write_packet(vio, &buf, 1))
      return CR_ERROR;
    if ((packet_length=vio->read_packet(vio, &packet)) == -1)
      return CR_ERROR;
    else {
#if defined(HAVE_OPENSSL)
      BIO* bio= BIO_new_mem_buf(packet, packet_length);
      if ((pubkey= PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)))
        rsa_size= RSA_size(pubkey);
      BIO_free(bio);
      ERR_clear_error();
#elif defined(HAVE_SCHANNEL)
#elif defined(HAVE_GNUTLS)
      gnutls_datum_t t;
      t.data= packet;
      t.size= packet_length;
      if (gnutls_pubkey_import(pubkey, &t, GNUTLS_X509_FMT_PEM) < 0)
        goto error;
#endif
      if (!pubkey)
        return CR_ERROR;
    }
  }
  pwlen= strlen(mysql->passwd) + 1;  /* include terminating zero */
  if (pwlen > MAX_PW_LEN ||
      pwlen + 41 > rsa_size)
    goto error;
  memcpy(passwd, mysql->passwd, pwlen);

  /* xor password with scramble */
  for (i=0; i < pwlen; i++)
    passwd[i]^= *(mysql->scramble_buff + i % SCRAMBLE_LENGTH);

#if defined(HAVE_OPENSSL)
  if (RSA_public_encrypt(pwlen, (unsigned char *)passwd, rsa_enc_pw, pubkey, RSA_PKCS1_OAEP_PADDING) < 0)
    goto error;
  if (vio->write_packet(vio, rsa_enc_pw, rsa_size))
    goto error;
#elif defined(HAVE_GNUTLS)
  {
    gnutls_datum_t ct, pt;
    int rc;
    pt.data= passwd;
    pt.size= pwlen;
    /* todo: GnuTLS doesn't support OAEP padding yet, so we need to
       write our own padding (nettle only supports PKCS v.15 padding) */
    if ((rc= gnutls_pubkey_encrypt_data(pubkey, 0, &pt, &ct)) < 0)
      goto error;
    rc= vio->write_packet(vio, ct.data, ct.size);
    gnutls_free(ct.data);
    if (rc)
      goto error;
  }
#endif
  if (pubkey)
#if defined(HAVE_OPENSSL)
    RSA_free(pubkey);
#elif defined(HAVE_GNUTLS)
    gnutls_pubkey_deinit(pubkey);
#endif
  return CR_OK;
error:
  if (pubkey)
#if defined(HAVE_OPENSSL)
    RSA_free(pubkey);
#elif defined(HAVE_GNUTLS)
    gnutls_pubkey_deinit(pubkey);
#endif
  return CR_ERROR;
}
/* }}} */

/* {{{ static int auth_sha256_init */
/*
  Initialization routine

  SYNOPSIS
    auth_sha256_init
      unused1
      unused2
      unused3
      unused4

  DESCRIPTION
    Init function checks if the caller provides own dialog function.
    The function name must be mariadb_auth_dialog or
    mysql_authentication_dialog_ask. If the function cannot be found,
    we will use owr own simple command line input.

  RETURN
    0           success
*/
static int auth_sha256_init(char *unused1 __attribute__((unused)), 
                            size_t unused2  __attribute__((unused)), 
                            int unused3     __attribute__((unused)), 
                            va_list unused4 __attribute__((unused)))
{
  return 0;
}
/* }}} */
