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
#include <ma_pvio.h>
#include <errmsg.h>
#include <string.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <openssl/ssl.h> /* SSL and SSL_CTX */
#include <openssl/err.h> /* error reporting */
#include <openssl/conf.h>

#ifndef HAVE_OPENSSL_DEFAULT
#include <memory.h>
#define my_malloc(A,B) malloc((A))
#undef my_free
#define my_free(A) free((A))
#define my_snprintf snprintf
#define my_vsnprintf vsnprintf
#undef SAFE_MUTEX
#endif
#include <my_pthread.h>

extern my_bool ma_ssl_initialized;
extern unsigned int mariadb_deinitialize_ssl;
static SSL_CTX *SSL_context= NULL;

#define MAX_SSL_ERR_LEN 100

static pthread_mutex_t LOCK_openssl_config;
static pthread_mutex_t *LOCK_crypto= NULL;


static void ma_ssl_set_error(MYSQL *mysql)
{
  ulong ssl_errno= ERR_get_error();
  char  ssl_error[MAX_SSL_ERR_LEN];
  const char *ssl_error_reason;
  MARIADB_PVIO *pvio= mysql->net.pvio;

  if (!ssl_errno)
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return;
  }
  if ((ssl_error_reason= ERR_reason_error_string(ssl_errno)))
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                   0, ssl_error_reason);
    return;
  }
  snprintf(ssl_error, MAX_SSL_ERR_LEN, "SSL errno=%lu", ssl_errno, mysql->charset);
  pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0, ssl_error);
  return;
}


static void ma_ssl_get_error(char *errmsg, size_t length)
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
int ma_ssl_start(char *errmsg, size_t errmsg_len)
{
  int rc= 1;
  /* lock mutex to prevent multiple initialization */
  pthread_mutex_init(&LOCK_openssl_config,MY_MUTEX_INIT_FAST);
  pthread_mutex_lock(&LOCK_openssl_config);
  if (!ma_ssl_initialized)
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
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    if (!(SSL_context= SSL_CTX_new(TLS_client_method())))
#else
    if (!(SSL_context= SSL_CTX_new(SSLv23_client_method())))
#endif
    {
      ma_ssl_get_error(errmsg, errmsg_len);
      goto end;
    }
    rc= 0;
    ma_ssl_initialized= TRUE;
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
void ma_ssl_end()
{
  pthread_mutex_lock(&LOCK_openssl_config);
  if (ma_ssl_initialized)
  {
    int i;
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);

    for (i=0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_destroy(&LOCK_crypto[i]);

    my_free((gptr)LOCK_crypto);
    LOCK_crypto= NULL;

    if (SSL_context)
    {
      SSL_CTX_free(SSL_context);
      SSL_context= NULL;
    }
    if (mariadb_deinitialize_ssl)
    {
      ERR_remove_state(0);
      EVP_cleanup();
      CRYPTO_cleanup_all_ex_data();
      ERR_free_strings();
      CONF_modules_free();
      CONF_modules_unload(1);
      sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    }
    ma_ssl_initialized= FALSE;
  }
  pthread_mutex_unlock(&LOCK_openssl_config);
  pthread_mutex_destroy(&LOCK_openssl_config);
  return;
}

int ma_ssl_get_password(char *buf, int size, int rwflag, void *userdata)
{
  bzero(buf, size);
  if (userdata)
    strncpy(buf, (char *)userdata, size);
  return strlen(buf);
}


static int ma_ssl_set_certs(MYSQL *mysql)
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

  /* If the private key file is encrypted, we need to register a callback function
   * for providing password. */
  if (OPT_HAS_EXT_VAL(mysql, ssl_pw))
  {
    SSL_CTX_set_default_passwd_cb_userdata(SSL_context, (void *)mysql->options.extension->ssl_pw);
    SSL_CTX_set_default_passwd_cb(SSL_context, ma_ssl_get_password);
  }

  if (keyfile && keyfile[0])
  {
    if (SSL_CTX_use_PrivateKey_file(SSL_context, keyfile, SSL_FILETYPE_PEM) != 1)
    {
      unsigned long err= ERR_peek_error();
      if (!(ERR_GET_LIB(err) == ERR_LIB_X509 &&
	  ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE))
        goto error;
    }
  }
  if (OPT_HAS_EXT_VAL(mysql, ssl_pw))
  {
    SSL_CTX_set_default_passwd_cb_userdata(SSL_context, NULL);
    SSL_CTX_set_default_passwd_cb(SSL_context, NULL);
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
      if (X509_STORE_load_locations(certstore, mysql->options.extension->ssl_crl,
                                               mysql->options.extension->ssl_crlpath) == 0 ||
          X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 0)
        goto error;
    }
  }
  return 0;

error:
  ma_ssl_set_error(mysql);
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


void *ma_ssl_init(MYSQL *mysql)
{
  int verify;
  SSL *ssl= NULL;

  pthread_mutex_lock(&LOCK_openssl_config);

  if (ma_ssl_set_certs(mysql))
  {
    goto error;
  }

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

my_bool ma_ssl_connect(MARIADB_SSL *cssl)
{
  SSL *ssl = (SSL *)cssl->ssl;
  my_bool blocking;
  MYSQL *mysql;
  MARIADB_PVIO *pvio;
  int rc;

  mysql= (MYSQL *)SSL_get_app_data(ssl);
  pvio= mysql->net.pvio;

  /* Set socket to blocking if not already set */
  if (!(blocking= pvio->methods->is_blocking(pvio)))
    pvio->methods->blocking(pvio, TRUE, 0);

  SSL_clear(ssl);
  SSL_SESSION_set_timeout(SSL_get_session(ssl),
                          mysql->options.connect_timeout);
  SSL_set_fd(ssl, mysql_get_socket(mysql));

  if (SSL_connect(ssl) != 1)
  {
    ma_ssl_set_error(mysql);
    /* restore blocking mode */
    if (!blocking)
      pvio->methods->blocking(pvio, FALSE, 0);
    return 1;
  }
  rc= SSL_get_verify_result(ssl);
  if (rc != X509_V_OK)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                 ER(CR_SSL_CONNECTION_ERROR), X509_verify_cert_error_string(rc));
    /* restore blocking mode */
    if (!blocking)
      pvio->methods->blocking(pvio, FALSE, 0);

    return 1;
  }

  pvio->cssl->ssl= cssl->ssl= (void *)ssl;

  return 0;
}

size_t ma_ssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  return SSL_read((SSL *)cssl->ssl, (void *)buffer, (int)length);
}

size_t ma_ssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{ 
  return SSL_write((SSL *)cssl->ssl, (void *)buffer, (int)length);
}

my_bool ma_ssl_close(MARIADB_SSL *cssl)
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

int ma_ssl_verify_server_cert(MARIADB_SSL *cssl)
{
  X509 *cert;
  MYSQL *mysql;
  X509_NAME *x509sn;
  int cn_pos;
  X509_NAME_ENTRY *cn_entry;
  ASN1_STRING *cn_asn1;
  const char *cn_str;
  SSL *ssl;
  MARIADB_PVIO *pvio;

  if (!cssl || !cssl->ssl)
    return 1;
  ssl= (SSL *)cssl->ssl;

  mysql= (MYSQL *)SSL_get_app_data(ssl);
  pvio= mysql->net.pvio;

  if (!mysql->host)
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                    ER(CR_SSL_CONNECTION_ERROR), "Invalid (empty) hostname");
    return 1;
  }

  if (!(cert= SSL_get_peer_certificate(ssl)))
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                    ER(CR_SSL_CONNECTION_ERROR), "Unable to get server certificate");
    return 1;
  }

  x509sn= X509_get_subject_name(cert);

  if ((cn_pos= X509_NAME_get_index_by_NID(x509sn, NID_commonName, -1)) < 0)
    goto error;

  if (!(cn_entry= X509_NAME_get_entry(x509sn, cn_pos)))
    goto error;

  if (!(cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry)))
    goto error;

  cn_str = (char *)ASN1_STRING_data(cn_asn1);

  /* Make sure there is no embedded \0 in the CN */
  if ((size_t)ASN1_STRING_length(cn_asn1) != strlen(cn_str))
    goto error;

  if (strcmp(cn_str, mysql->host))
    goto error;

  X509_free(cert);

  return 0;
error:
  X509_free(cert);

  pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                  ER(CR_SSL_CONNECTION_ERROR), "Validation of SSL server certificate failed");
  return 1;
}

const char *ma_ssl_get_cipher(MARIADB_SSL *cssl)
{
  if (!cssl || !cssl->ssl)
    return NULL;
  return SSL_get_cipher_name(cssl->ssl);
}

unsigned int ma_ssl_get_finger_print(MARIADB_SSL *cssl, unsigned char *fp, unsigned int len)
{
  EVP_MD *digest= (EVP_MD *)EVP_sha1();
  X509 *cert;
  MYSQL *mysql;
  unsigned int fp_len;

  if (!cssl || !cssl->ssl)
    return 0;

  mysql= SSL_get_app_data(cssl->ssl);

  if (!(cert= SSL_get_peer_certificate(cssl->ssl)))
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Unable to get server certificate");
    return 0;
  }

  if (len < EVP_MAX_MD_SIZE)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Finger print buffer too small");
    return 0;
  }
  fp_len= len;
  if (!X509_digest(cert, digest, fp, &fp_len))
  {
    my_free(fp);
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "invalid finger print of server certificate");
    return 0;
  }
  return (fp_len);
}


extern char *ssl_protocol_version[5];

my_bool ma_ssl_get_protocol_version(MARIADB_SSL *cssl, struct st_ssl_version *version)
{
  SSL *ssl;

  if (!cssl || !cssl->ssl)
    return 1;

  ssl = (SSL *)cssl->ssl;
  switch(ssl->version)
  {
    case SSL3_VERSION:
      version->iversion= 1;
      break;
    case TLS1_VERSION:
      version->iversion= 2;
      break;
    case TLS1_1_VERSION:
      version->iversion= 3;
      break;
    case TLS1_2_VERSION:
      version->iversion= 4;
      break;
    default:
      version->iversion= 0;
      break;
  }
  version->cversion= ssl_protocol_version[version->iversion];
  return 0;  
}

