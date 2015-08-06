/************************************************************************************
  Copyright (C) 2014 MariaDB Corporation AB

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
#ifdef HAVE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <my_global.h>
#include <my_sys.h>
#include <ma_common.h>
#include <ma_cio.h>
#include <errmsg.h>
#include <my_pthread.h>
#include <mysql/client_plugin.h>
#include <string.h>

pthread_mutex_t LOCK_gnutls_config;
static my_bool my_gnutls_initialized= FALSE;

static gnutls_certificate_credentials_t GNUTLS_xcred;

#define MAX_SSL_ERR_LEN 100

int cio_gnutls_start(char *errmsg, size_t errmsg_len, int count, va_list);
int cio_gnutls_end();
void *cio_gnutls_init(MARIADB_SSL *cssl, MYSQL *mysql);
my_bool cio_gnutls_connect(MARIADB_SSL *cssl);
size_t cio_gnutls_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
size_t cio_gnutls_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
my_bool cio_gnutls_close(MARIADB_SSL *cssl);
int cio_gnutls_verify_server_cert(MARIADB_SSL *cssl);
const char *cio_gnutls_cipher(MARIADB_SSL *cssl);
static int my_verify_callback(gnutls_session_t ssl);

struct st_ma_cio_ssl_methods cio_gnutls_methods= {
  cio_gnutls_init,
  cio_gnutls_connect,
  cio_gnutls_read,
  cio_gnutls_write,
  cio_gnutls_close,
  cio_gnutls_verify_server_cert,
  cio_gnutls_cipher
};

MARIADB_CIO_PLUGIN cio_gnutls_plugin=
{
  MYSQL_CLIENT_CIO_PLUGIN,
  MYSQL_CLIENT_CIO_PLUGIN_INTERFACE_VERSION,
  "cio_gnutls",
  "Georg Richter",
  "MariaDB communication IO plugin for GnuTLS SSL communication",
  {1, 0, 0},
  "LGPL",
  NULL,
  cio_gnutls_start,
  cio_gnutls_end,
  NULL,
  &cio_gnutls_methods,
  NULL
};

static void cio_gnutls_set_error(MYSQL *mysql, int ssl_errno)
{
  char  ssl_error[MAX_SSL_ERR_LEN];
  const char *ssl_error_reason;
  MARIADB_CIO *cio= mysql->net.cio;

  if (!ssl_errno)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return;
  }
  if ((ssl_error_reason= gnutls_strerror(ssl_errno)))
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0, 
                   ssl_error_reason);
    return;
  }
  my_snprintf(ssl_error, MAX_SSL_ERR_LEN, "SSL errno=%lu", ssl_errno, mysql->charset);
  cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                 ssl_error);
}


static void cio_gnutls_get_error(char *errmsg, size_t length, int ssl_errno)
{
  const char *ssl_error_reason;

  if (!ssl_errno)
  {
    strncpy(errmsg, "Unknown SSL error", length);
    return;
  }
  if ((ssl_error_reason= gnutls_strerror(ssl_errno)))
  {
    strncpy(errmsg, ssl_error_reason, length);
    return;
  }
  snprintf(errmsg, length, "SSL errno=%lu", ssl_errno);
}

/*
  Initializes SSL and allocate global
  context SSL_context

  SYNOPSIS
    my_gnutls_start
      mysql        connection handle

  RETURN VALUES
    0  success
    1  error
*/
int cio_gnutls_start(char *errmsg, size_t errmsg_len, int count, va_list list)
{
  int rc= 0;

  pthread_mutex_init(&LOCK_gnutls_config,MY_MUTEX_INIT_FAST);
  pthread_mutex_lock(&LOCK_gnutls_config);

  if (!my_gnutls_initialized)
  {
    if ((rc= gnutls_global_init()) != GNUTLS_E_SUCCESS)
    {
      cio_gnutls_get_error(errmsg, errmsg_len, rc);
      goto end;
    }
    my_gnutls_initialized= TRUE;
  }
  /* Allocate a global context for credentials */
  rc= gnutls_certificate_allocate_credentials(&GNUTLS_xcred);
end:
  pthread_mutex_unlock(&LOCK_gnutls_config);
  return rc;
}

/*
   Release SSL and free resources
   Will be automatically executed by 
   mysql_server_end() function

   SYNOPSIS
     my_gnutls_end()
       void

   RETURN VALUES
     void
*/
int cio_gnutls_end()
{
  pthread_mutex_lock(&LOCK_gnutls_config);
  if (my_gnutls_initialized)
  {
    gnutls_certificate_free_keys(GNUTLS_xcred);
    gnutls_certificate_free_cas(GNUTLS_xcred);
    gnutls_certificate_free_crls(GNUTLS_xcred);
    gnutls_certificate_free_ca_names(GNUTLS_xcred);
    gnutls_certificate_free_credentials(GNUTLS_xcred);
    gnutls_global_deinit();
    my_gnutls_initialized= FALSE;
  }
  pthread_mutex_unlock(&LOCK_gnutls_config);
  pthread_mutex_destroy(&LOCK_gnutls_config);
  return 0;
}

static int cio_gnutls_set_certs(MYSQL *mysql, MARIADB_SSL *cssl)
{
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key;
  char *cipher= NULL;
  int  ssl_error= 0;

  if (mysql->options.ssl_ca)
  {

    ssl_error= gnutls_certificate_set_x509_trust_file(GNUTLS_xcred,
                                                      mysql->options.ssl_ca,
                                                      GNUTLS_X509_FMT_PEM);
    if (ssl_error < 0)
      goto error;
  }
  gnutls_certificate_set_verify_function(GNUTLS_xcred,
                                         my_verify_callback);

  /* GNUTLS doesn't support ca_path */

  if (keyfile && !certfile)
    certfile= keyfile;
  if (certfile && !keyfile)
    keyfile= certfile;

  /* set key */
  if (certfile || keyfile)
  {
    if ((ssl_error= gnutls_certificate_set_x509_key_file(GNUTLS_xcred,
                                                         certfile, keyfile,
                                                         GNUTLS_X509_FMT_PEM)) < 0)
      goto error;
  }
  return 1;

error:
  if (cipher)
    my_free(cipher));
  return ssl_error;
}

void *cio_gnutls_init(MARIADB_SSL *cssl, MYSQL *mysql)
{
  gnutls_session_t ssl= NULL;
  int ssl_error= 0;
  const char *err;

  pthread_mutex_lock(&LOCK_gnutls_config);

  if ((ssl_error= cio_gnutls_set_certs(mysql, cssl)) < 0)
    goto error;

  if ((ssl_error = gnutls_init(&ssl, GNUTLS_CLIENT & GNUTLS_NONBLOCK)) < 0)
    goto error;
  gnutls_session_set_ptr(ssl, (void *)mysql);

  ssl_error= gnutls_priority_set_direct(ssl, "NORMAL:-DHE-RSA", &err);
  if (ssl_error < 0)
    goto error;

  if ((ssl_error= gnutls_credentials_set(ssl, GNUTLS_CRD_CERTIFICATE, GNUTLS_xcred)) < 0)
    goto error;
  
  cssl->ssl= ssl;
  pthread_mutex_unlock(&LOCK_gnutls_config);
  return (void *)ssl;
error:
  cio_gnutls_set_error(mysql, ssl_error);
  if (ssl)
    gnutls_deinit(ssl);
  pthread_mutex_unlock(&LOCK_gnutls_config);
  return NULL;
} 

my_bool cio_gnutls_connect(MARIADB_SSL *cssl)
{
  gnutls_session_t ssl = (gnutls_session_t)cssl->ssl;
  my_bool blocking;
  MYSQL *mysql;
  MARIADB_CIO *cio;
  int ret;
  mysql= (MYSQL *)gnutls_session_get_ptr(ssl);

  if (!mysql)
    return 1;

  cio= mysql->net.cio;

  /* Set socket to blocking if not already set */
  if (!(blocking= cio->methods->is_blocking(cio)))
    cio->methods->blocking(cio, TRUE, 0);

  gnutls_transport_set_int(ssl, cio->methods->get_socket(cio));
  gnutls_handshake_set_timeout(ssl, mysql->options.connect_timeout);

  do {
    ret = gnutls_handshake(ssl);
  } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0)
  {
    cio_gnutls_set_error(mysql, ret);
    /* restore blocking mode */
    if (!blocking)
      cio->methods->blocking(cio, FALSE, 0);
    return 1;
  }
  cssl->ssl= (void *)ssl;

  return 0;
}

size_t cio_gnutls_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  return gnutls_record_recv((gnutls_session_t )cssl->ssl, (void *)buffer, length);
}

size_t cio_gnutls_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{ 
  return gnutls_record_send((gnutls_session_t )cssl->ssl, (void *)buffer, length);
}

my_bool cio_gnutls_close(MARIADB_SSL *cssl)
{
  gnutls_bye((gnutls_session_t )cssl->ssl, GNUTLS_SHUT_WR);
  gnutls_deinit((gnutls_session_t )cssl->ssl);
  cssl->ssl= NULL;

  return 0;
}

int cio_gnutls_verify_server_cert(MARIADB_SSL *cssl)
{
  /* server verification is already handled before */
  return 0;
}

const char *cio_gnutls_cipher(MARIADB_SSL *cssl)
{
  if (!cssl || !cssl->ssl)
    return NULL;
  return gnutls_cipher_get_name (gnutls_cipher_get((gnutls_session_t )cssl->ssl));
}

static int my_verify_callback(gnutls_session_t ssl)
{
  unsigned int status;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  int ret;
  MYSQL *mysql= (MYSQL *)gnutls_session_get_ptr(ssl);
  MARIADB_CIO *cio= mysql->net.cio;
  gnutls_x509_crt_t cert;
  const char *hostname;

  /* read hostname */
  hostname = mysql->host;

  /* skip verification if no ca_file/path was specified */
  if (!mysql->options.ssl_ca)
    return 0;

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers2 (ssl, &status);
  if (ret < 0)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "CA verification failed");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }

//  mysql->net.vio->status= status;

  if (status & GNUTLS_CERT_INVALID)
  {
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  /* Up to here the process is the same for X.509 certificates and
   * OpenPGP keys. From now on X.509 certificates are assumed. This can
   * be easily extended to work with openpgp keys as well.
   */
  if (gnutls_certificate_type_get (ssl) != GNUTLS_CRT_X509)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Expected X509 certificate");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  if (gnutls_x509_crt_init (&cert) < 0)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Error during certificate initialization");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  cert_list = gnutls_certificate_get_peers (ssl, &cert_list_size);
  if (cert_list == NULL)
  {
    gnutls_x509_crt_deinit (cert);
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "No certificate found");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
  {
    gnutls_x509_crt_deinit (cert);
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }

  if ((mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT) &&
      gnutls_x509_crt_check_hostname (cert, hostname) < 0)
  {
    printf("Error:  %s does not match\n", hostname);
    gnutls_x509_crt_deinit (cert);
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Hostname in certificate doesn't match");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  gnutls_x509_crt_deinit (cert);
  /* notify gnutls to continue handshake normally */

  CLEAR_CLIENT_ERROR(mysql);
  return 0;
}

#endif /* HAVE_GNUTLS */
