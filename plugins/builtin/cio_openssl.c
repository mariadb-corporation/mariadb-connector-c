/************************************************************************************
  Copyright (C) 2012 Monty Program AB

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
#include <my_global.h>
#include <my_sys.h>
#include <ma_common.h>
#include <ma_cio.h>
#include <errmsg.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <openssl/ssl.h> /* SSL and SSL_CTX */
#include <openssl/err.h> /* error reporting */
#include <openssl/conf.h>

#ifndef HAVE_OPENSSL_DEFAULT
#include <memory.h>
#define my_malloc(A,B) malloc((A))
#undef my_free
#define my_free(A,B) free((A))
#define my_snprintf snprintf
#define my_vsnprintf vsnprintf
#undef SAFE_MUTEX
#endif
#include <my_pthread.h>

static my_bool my_openssl_initialized= FALSE;
static SSL_CTX *SSL_context= NULL;

#define MAX_SSL_ERR_LEN 100

static pthread_mutex_t LOCK_openssl_config;
static pthread_mutex_t *LOCK_crypto= NULL;

int cio_openssl_start(char *errmsg, size_t errmsg_len, int count, va_list);
int cio_openssl_end();
void *cio_openssl_init(MARIADB_SSL *cssl, MYSQL *mysql);
my_bool cio_openssl_connect(MARIADB_SSL *cssl);
size_t cio_openssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
size_t cio_openssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
my_bool cio_openssl_close(MARIADB_SSL *cssl);
int cio_openssl_verify_server_cert(MARIADB_SSL *cssl);
const char *cio_openssl_cipher(MARIADB_SSL *cssl);

struct st_ma_cio_ssl_methods cio_openssl_methods= {
  cio_openssl_init,
  cio_openssl_connect,
  cio_openssl_read,
  cio_openssl_write,
  cio_openssl_close,
  cio_openssl_verify_server_cert,
  cio_openssl_cipher
};

MARIADB_CIO_PLUGIN cio_openssl_plugin=
{
  MYSQL_CLIENT_CIO_PLUGIN,
  MYSQL_CLIENT_CIO_PLUGIN_INTERFACE_VERSION,
  "cio_openssl",
  "Georg Richter",
  "MariaDB communication IO plugin for OpenSSL communication",
  {1, 0, 0},
  "LGPL",
  cio_openssl_start,
  cio_openssl_end,
  NULL,
  &cio_openssl_methods,
  NULL
};

static void cio_openssl_set_error(MYSQL *mysql)
{
  ulong ssl_errno= ERR_get_error();
  char  ssl_error[MAX_SSL_ERR_LEN];
  const char *ssl_error_reason;
  MARIADB_CIO *cio= mysql->net.cio;

  if (!ssl_errno)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return;
  }
  if ((ssl_error_reason= ERR_reason_error_string(ssl_errno)))
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                   0, ssl_error_reason);
    return;
  }
  snprintf(ssl_error, MAX_SSL_ERR_LEN, "SSL errno=%lu", ssl_errno, mysql->charset);
  cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0, ssl_error);
  return;
}


static void cio_openssl_get_error(char *errmsg, size_t length)
{
  ulong ssl_errno= ERR_get_error();
  const char *ssl_error_reason;

  if (!ssl_errno)
  {
    strncpy(errmsg, "Unknown SSL error", length);
    return;
  }
  if ((ssl_error_reason= ERR_reason_error_string(ssl_errno)))
  {
    strncpy(errmsg, ssl_error_reason, length);
    return;
  }
  snprintf(errmsg, length, "SSL errno=%lu", ssl_errno);
}

/* 
   thread safe callbacks for OpenSSL 
   Crypto call back functions will be
   set during ssl_initialization
 */
#if (OPENSSL_VERSION_NUMBER < 0x10000000) 
static unsigned long my_cb_threadid(void)
{
  /* cast pthread_t to unsigned long */
  return (unsigned long) pthread_self();
}
#else
static void my_cb_threadid(CRYPTO_THREADID *id)
{
  CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
#endif

static void my_cb_locking(int mode, int n, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&LOCK_crypto[n]);
  else
    pthread_mutex_unlock(&LOCK_crypto[n]);
}


static int ssl_thread_init()
{
  int i, max= CRYPTO_num_locks();

  if (LOCK_crypto == NULL)
  {
    if (!(LOCK_crypto= 
          (pthread_mutex_t *)my_malloc(sizeof(pthread_mutex_t) * max, MYF(0))))
      return 1;

    for (i=0; i < max; i++)
      pthread_mutex_init(&LOCK_crypto[i], NULL);
  }

#if (OPENSSL_VERSION_NUMBER < 0x10000000) 
  CRYPTO_set_id_callback(my_cb_threadid);
#else
  CRYPTO_THREADID_set_callback(my_cb_threadid);
#endif
  CRYPTO_set_locking_callback(my_cb_locking);

  return 0;
}


/*
  Initializes SSL and allocate global
  context SSL_context

  SYNOPSIS
    my_ssl_start
      mysql        connection handle

  RETURN VALUES
    0  success
    1  error
*/
int cio_openssl_start(char *errmsg, size_t errmsg_len, int count, va_list list)
{
  int rc= 1;
  /* lock mutex to prevent multiple initialization */
  pthread_mutex_init(&LOCK_openssl_config,MY_MUTEX_INIT_FAST);
  pthread_mutex_lock(&LOCK_openssl_config);
  if (!my_openssl_initialized)
  {
    if (ssl_thread_init())
    {
      strncpy(errmsg, "Not enough memory", errmsg_len);
      goto end;
    }
    SSL_library_init();

#if SSLEAY_VERSION_NUMBER >= 0x00907000L
    OPENSSL_config(NULL);
#endif
    /* load errors */
    SSL_load_error_strings();
    /* digests and ciphers */
    OpenSSL_add_all_algorithms();

    if (!(SSL_context= SSL_CTX_new(TLSv1_client_method())))
    {
      cio_openssl_get_error(errmsg, errmsg_len);
      goto end;
    }
    rc= 0;
    my_openssl_initialized= TRUE;
  }
end:
  pthread_mutex_unlock(&LOCK_openssl_config);
  return rc;
}

/*
   Release SSL and free resources
   Will be automatically executed by 
   mysql_server_end() function

   SYNOPSIS
     my_ssl_end()
       void

   RETURN VALUES
     void
*/
int cio_openssl_end()
{
  pthread_mutex_lock(&LOCK_openssl_config);
  if (my_openssl_initialized)
  {
    int i;
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    for (i=0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_destroy(&LOCK_crypto[i]);

    my_free((gptr)LOCK_crypto, MYF(0));
    LOCK_crypto= NULL;

    if (SSL_context)
    {
      SSL_CTX_free(SSL_context);
      SSL_context= NULL;
    }
    ERR_remove_state(0);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    //ENGINE_cleanup();
    CONF_modules_free();
    CONF_modules_unload(1);
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    my_openssl_initialized= FALSE;
  }
  pthread_mutex_unlock(&LOCK_openssl_config);
  pthread_mutex_destroy(&LOCK_openssl_config);
  return 0;
}

static int cio_openssl_set_certs(MYSQL *mysql)
{
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key;
  
  /* add cipher */
  if ((mysql->options.ssl_cipher && 
        mysql->options.ssl_cipher[0] != 0) &&
      SSL_CTX_set_cipher_list(SSL_context, mysql->options.ssl_cipher) == 0)
    goto error;

  /* ca_file and ca_path */
  if (SSL_CTX_load_verify_locations(SSL_context, 
                                    mysql->options.ssl_ca,
                                    mysql->options.ssl_capath) == 0)
  {
    if (mysql->options.ssl_ca || mysql->options.ssl_capath)
      goto error;
    if (SSL_CTX_set_default_verify_paths(SSL_context) == 0)
      goto error;
  }

  if (keyfile && !certfile)
    certfile= keyfile;
  if (certfile && !keyfile)
    keyfile= certfile;

  /* set cert */
  if (certfile  && certfile[0] != 0)  
    if (SSL_CTX_use_certificate_file(SSL_context, certfile, SSL_FILETYPE_PEM) != 1)
      goto error; 

  /* set key */
  if (keyfile && keyfile[0])
  {
    if (SSL_CTX_use_PrivateKey_file(SSL_context, keyfile, SSL_FILETYPE_PEM) != 1)
      goto error;
  }
  /* verify key */
  if (certfile && !SSL_CTX_check_private_key(SSL_context))
    goto error;
  
  if (mysql->options.extension &&
      (mysql->options.extension->ssl_crl || mysql->options.extension->ssl_crlpath))
  {
    X509_STORE *certstore;

    if ((certstore= SSL_CTX_get_cert_store(SSL_context)))
    {
      if (X509_STORE_load_locations(certstore, mysql->options.ssl_ca,
                                     mysql->options.ssl_capath) == 0 ||
			    X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK |
                                         X509_V_FLAG_CRL_CHECK_ALL) == 0)
        goto error;
    }
  }
  return 0;

error:
  cio_openssl_set_error(mysql);
  return 1;
}

static int my_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  X509 *check_cert;
  SSL *ssl;
  MYSQL *mysql;

  ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  mysql= (MYSQL *)SSL_get_app_data(ssl);

  /* skip verification if no ca_file/path was specified */
  if (!mysql->options.ssl_ca && !mysql->options.ssl_capath)
  {
    ok= 1;
    return 1;
  }

  if (!ok)
  {
    uint depth;
    if (!(check_cert= X509_STORE_CTX_get_current_cert(ctx)))
      return 0;
    depth= X509_STORE_CTX_get_error_depth(ctx);
    if (depth == 0)
      ok= 1;
  }

  return ok;
}

void *cio_openssl_init(MARIADB_SSL *cssl, MYSQL *mysql)
{
  int verify;
  SSL *ssl= NULL;

  pthread_mutex_lock(&LOCK_openssl_config);
  if (cio_openssl_set_certs(mysql))
    goto error;

  if (!(ssl= SSL_new(SSL_context)))
    goto error;

  if (!SSL_set_app_data(ssl, mysql))
    goto error;

  verify= (!mysql->options.ssl_ca && !mysql->options.ssl_capath) ?
           SSL_VERIFY_NONE : SSL_VERIFY_PEER;

  SSL_CTX_set_verify(SSL_context, verify, my_verify_callback);
  SSL_CTX_set_verify_depth(SSL_context, 1);

  pthread_mutex_unlock(&LOCK_openssl_config);
  return (void *)ssl;
error:
  pthread_mutex_unlock(&LOCK_openssl_config);
  if (ssl)
    SSL_free(ssl);
  return NULL;
}

my_bool cio_openssl_connect(MARIADB_SSL *cssl)
{
  SSL *ssl = (SSL *)cssl->ssl;
  my_bool blocking;
  MYSQL *mysql;
  MARIADB_CIO *cio;

  mysql= (MYSQL *)SSL_get_app_data(ssl);
  cio= mysql->net.cio;

  /* Set socket to blocking if not already set */
  if (!(blocking= cio->methods->is_blocking(cio)))
    cio->methods->blocking(cio, TRUE, 0);

  SSL_clear(ssl);
  SSL_SESSION_set_timeout(SSL_get_session(ssl),
                          mysql->options.connect_timeout);
  SSL_set_fd(ssl, mysql_get_socket(mysql));

  if (SSL_connect(ssl) != 1)
  {
    cio_openssl_set_error(mysql);
    /* restore blocking mode */
    if (!blocking)
      cio->methods->blocking(cio, FALSE, 0);
    return 1;
  }
  cio->cssl->ssl= cssl->ssl= (void *)ssl;

  return 0;
}

size_t cio_openssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  return SSL_read((SSL *)cssl->ssl, (void *)buffer, (int)length);
}

size_t cio_openssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{ 
  return SSL_write((SSL *)cssl->ssl, (void *)buffer, (int)length);
}

my_bool cio_openssl_close(MARIADB_SSL *cssl)
{
  int i, rc;
  SSL *ssl;

  if (!cssl || !cssl->ssl)
    return 1;
  ssl= (SSL *)cssl->ssl;

  SSL_set_quiet_shutdown(ssl, 1); 
  /* 2 x pending + 2 * data = 4 */ 
  for (i=0; i < 4; i++)
    if ((rc= SSL_shutdown(ssl)))
      break;

  SSL_free(ssl);
  cssl->ssl= NULL;

  return rc;
}

int cio_openssl_verify_server_cert(MARIADB_SSL *cssl)
{
  X509 *cert;
  MYSQL *mysql;
  MARIADB_CIO *cio;
  SSL *ssl;
  char *p1, *p2, buf[256];

  if (!cssl || !cssl->ssl)
    return 1;
  ssl= (SSL *)cssl->ssl;

  mysql= (MYSQL *)SSL_get_app_data(ssl);
  cio= mysql->net.cio;

  if (!mysql->host)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0,
                        "Invalid (empty) hostname");
    return 1;
  }

  if (!(cert= SSL_get_peer_certificate(ssl)))
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0,
                        "Unable to get server certificate");
    return 1;
  }

  X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);
  X509_free(cert);

  /* Extract the server name from buffer:
     Format: ....CN=/hostname/.... */
  if ((p1= strstr(buf, "/CN=")))
  {
    p1+= 4;
    if ((p2= strchr(p1, '/')))
      *p2= 0;
    if (!strcmp(mysql->host, p1))
      return(0);
  }
  cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0,
                       "Validation of SSL server certificate failed");
  return 1;
}

const char *cio_openssl_cipher(MARIADB_SSL *cssl)
{
  if (!cssl || !cssl->ssl)
    return NULL;
  return SSL_get_cipher_name(cssl->ssl);
}
