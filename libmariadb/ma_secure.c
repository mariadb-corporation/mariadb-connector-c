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
unsigned int mariadb_deinitialize_ssl= 1;
#ifdef HAVE_OPENSSL

#include <my_global.h>
#include <my_sys.h>
#include <ma_common.h>
#include <ma_secure.h>
#include <errmsg.h>
#include <violite.h>
#include <mysql_async.h>
#include <my_context.h>

static my_bool my_ssl_initialized= FALSE;
static SSL_CTX *SSL_context= NULL;

#define MAX_SSL_ERR_LEN 100

extern pthread_mutex_t LOCK_ssl_config;
static pthread_mutex_t *LOCK_crypto= NULL;

/*
 SSL error handling
*/
static void my_SSL_error(MYSQL *mysql)
{
  ulong ssl_errno= ERR_get_error();
  char  ssl_error[MAX_SSL_ERR_LEN];
  const char *ssl_error_reason;

  DBUG_ENTER("my_SSL_error");

  if (mysql_errno(mysql))
    DBUG_VOID_RETURN;

  if (!ssl_errno)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    DBUG_VOID_RETURN;
  }
  if ((ssl_error_reason= ERR_reason_error_string(ssl_errno)))
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                 ER(CR_SSL_CONNECTION_ERROR), ssl_error_reason);
    DBUG_VOID_RETURN;
  }
  my_snprintf(ssl_error, MAX_SSL_ERR_LEN, "SSL errno=%lu", ssl_errno, mysql->charset);
  my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
               ER(CR_SSL_CONNECTION_ERROR), ssl_error);
  DBUG_VOID_RETURN;
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


static int ssl_crypto_init()
{
  int i, rc= 1, max= CRYPTO_num_locks();

#if (OPENSSL_VERSION_NUMBER < 0x10000000) 
  CRYPTO_set_id_callback(my_cb_threadid);
#else
  rc= CRYPTO_THREADID_set_callback(my_cb_threadid);
#endif

  /* if someone else already set callbacks 
   * there is nothing do */
  if (!rc)
    return 0;

  if (LOCK_crypto == NULL)
  {
    if (!(LOCK_crypto= 
          (pthread_mutex_t *)my_malloc(sizeof(pthread_mutex_t) * max, MYF(0))))
      return 1;

    for (i=0; i < max; i++)
      pthread_mutex_init(&LOCK_crypto[i], NULL);
  }

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
int my_ssl_start(MYSQL *mysql)
{
  int rc= 0;
  DBUG_ENTER("my_ssl_start");
  /* lock mutex to prevent multiple initialization */
  pthread_mutex_lock(&LOCK_ssl_config);
  if (!my_ssl_initialized)
  {
    if (ssl_crypto_init())
      goto end;
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
      my_SSL_error(mysql);
      rc= 1;
      goto end;
    }
    my_ssl_initialized= TRUE;
  }
end:
  pthread_mutex_unlock(&LOCK_ssl_config);
  DBUG_RETURN(rc);
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
void my_ssl_end()
{
  DBUG_ENTER("my_ssl_end");
  pthread_mutex_lock(&LOCK_ssl_config);
  if (my_ssl_initialized)
  {
    int i;

    if (LOCK_crypto)
    {
      CRYPTO_set_locking_callback(NULL);
      CRYPTO_set_id_callback(NULL);

      for (i=0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&LOCK_crypto[i]);

      my_free(LOCK_crypto);
      LOCK_crypto= NULL;
    }

    if (SSL_context)
    {
      SSL_CTX_free(SSL_context);
      SSL_context= FALSE;
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
    my_ssl_initialized= FALSE;
  }
  pthread_mutex_unlock(&LOCK_ssl_config);
  pthread_mutex_destroy(&LOCK_ssl_config);
  DBUG_VOID_RETURN;
}

/* 
  Set certification stuff.
*/
static int my_ssl_set_certs(MYSQL *mysql)
{
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key;
  
  DBUG_ENTER("my_ssl_set_certs");

  /* Make sure that ssl was allocated and 
     ssl_system was initialized */
  DBUG_ASSERT(my_ssl_initialized == TRUE);

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
      if (X509_STORE_load_locations(certstore, mysql->options.extension->ssl_crl,
                                    mysql->options.extension->ssl_crlpath) == 0 ||
          X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 0)
        goto error;
    }
  }

  DBUG_RETURN(0);

error:
  my_SSL_error(mysql);
  DBUG_RETURN(1);
}

static unsigned int ma_get_cert_fingerprint(X509 *cert, EVP_MD *digest, 
                                            unsigned char *fingerprint, unsigned int *fp_length)
{
  if (*fp_length < EVP_MD_size(digest))
    return 0;
  if (!X509_digest(cert, digest, fingerprint, fp_length))
    return 0;
  return *fp_length;
} 

static my_bool ma_check_fingerprint(char *fp1, unsigned int fp1_len,
                                    char *fp2, unsigned int fp2_len)
{
  /* SHA1 fingerprint (160 bit) / 8 * 2 + 1 */
  char hexstr[41];

  fp1_len= (unsigned int)mysql_hex_string(hexstr, fp1, fp1_len);
#ifdef _WIN32
  if (_strnicmp(hexstr, fp2, fp1_len) != 0)
#else
  if (strncasecmp(hexstr, fp2, fp1_len) != 0)
#endif
   return 1;
  return 0;
}

int my_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  X509 *check_cert;
  SSL *ssl;
  MYSQL *mysql;
  DBUG_ENTER("my_verify_callback");

  ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
  DBUG_ASSERT(ssl != NULL);
  mysql= (MYSQL *)SSL_get_app_data(ssl);
  DBUG_ASSERT(mysql != NULL);

  /* skip verification if no ca_file/path was specified */
  if (!mysql->options.ssl_ca && !mysql->options.ssl_capath)
  {
    ok= 1;
    DBUG_RETURN(1);
  }

  if (!ok)
  {
    uint depth;
    if (!(check_cert= X509_STORE_CTX_get_current_cert(ctx)))
      DBUG_RETURN(0);
    depth= X509_STORE_CTX_get_error_depth(ctx);
    if (depth == 0)
      ok= 1;
  }

/*
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        X509_verify_cert_error_string(ctx->error));
*/
  DBUG_RETURN(ok);
}


/*
   allocates a new ssl object

   SYNOPSIS
     my_ssl_init
       mysql     connection object

   RETURN VALUES
     NULL on error
     SSL  new SSL object
*/
SSL *my_ssl_init(MYSQL *mysql)
{
  int verify;
  SSL *ssl= NULL;

  DBUG_ENTER("my_ssl_init");

  DBUG_ASSERT(mysql->net.vio->ssl == NULL);

  if (!my_ssl_initialized)
    my_ssl_start(mysql); 

  pthread_mutex_lock(&LOCK_ssl_config);
  if (my_ssl_set_certs(mysql))
    goto error;

  if (!(ssl= SSL_new(SSL_context)))
    goto error;

  if (!SSL_set_app_data(ssl, mysql))
    goto error;

  verify= (!mysql->options.ssl_ca && !mysql->options.ssl_capath) ?
           SSL_VERIFY_NONE : SSL_VERIFY_PEER;

  SSL_CTX_set_verify(SSL_context, verify, my_verify_callback);
  SSL_CTX_set_verify_depth(SSL_context, 1);

  pthread_mutex_unlock(&LOCK_ssl_config);
  DBUG_RETURN(ssl);
error:
  pthread_mutex_unlock(&LOCK_ssl_config);
  if (ssl)
    SSL_free(ssl);
  DBUG_RETURN(NULL);
} 

/*
  establish SSL connection between client 
  and server

  SYNOPSIS
    my_ssl_connect
      ssl      ssl object

  RETURN VALUES
    0  success
    1  error
*/
int my_ssl_connect(SSL *ssl)
{
  my_bool blocking;
  MYSQL *mysql;
  long rc;

  DBUG_ENTER("my_ssl_connect");

  DBUG_ASSERT(ssl != NULL);

  mysql= (MYSQL *)SSL_get_app_data(ssl);
  CLEAR_CLIENT_ERROR(mysql);

  /* Set socket to blocking if not already set */
  if (!(blocking= vio_is_blocking(mysql->net.vio)))
    vio_blocking(mysql->net.vio, TRUE, 0);

  SSL_clear(ssl);
  SSL_SESSION_set_timeout(SSL_get_session(ssl),
                          mysql->options.connect_timeout);
  SSL_set_fd(ssl, mysql->net.vio->sd);

  if (SSL_connect(ssl) != 1)
  {
    my_SSL_error(mysql);
    /* restore blocking mode */
    if (!blocking)
      vio_blocking(mysql->net.vio, FALSE, 0);
    DBUG_RETURN(1);
  }

  rc= SSL_get_verify_result(ssl);
  if (rc != X509_V_OK)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                 ER(CR_SSL_CONNECTION_ERROR), X509_verify_cert_error_string(rc));
    /* restore blocking mode */
    if (!blocking)
      vio_blocking(mysql->net.vio, FALSE, 0);

    DBUG_RETURN(1);
  }

  vio_reset(mysql->net.vio, VIO_TYPE_SSL, mysql->net.vio->sd, 0, 0);
  mysql->net.vio->ssl= ssl;
  DBUG_RETURN(0);
}

int ma_ssl_verify_fingerprint(SSL *ssl)
{
  X509 *cert= SSL_get_peer_certificate(ssl);
  MYSQL *mysql= (MYSQL *)SSL_get_app_data(ssl);
  unsigned char fingerprint[EVP_MAX_MD_SIZE];
  EVP_MD *digest;
  unsigned int fp_length;

  DBUG_ENTER("ma_ssl_verify_fingerprint");

  if (!cert)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Unable to get server certificate");
    DBUG_RETURN(1);
  }

  digest= (EVP_MD *)EVP_sha1();
  fp_length= sizeof(fingerprint);

  if (!ma_get_cert_fingerprint(cert, digest, fingerprint, &fp_length))
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Unable to get finger print of server certificate");
    DBUG_RETURN(1);
  }

  /* single finger print was specified */
  if (mysql->options.extension->ssl_fp)
  {
    if (ma_check_fingerprint(fingerprint, fp_length, mysql->options.extension->ssl_fp,
                             strlen(mysql->options.extension->ssl_fp)))
    {
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                          ER(CR_SSL_CONNECTION_ERROR), 
                          "invalid finger print of server certificate");
      DBUG_RETURN(1);
    }
  }

  /* white list of finger prints was specified */
  if (mysql->options.extension->ssl_fp_list)
  {
    FILE *fp;
    char buff[255];

    if (!(fp = my_fopen(mysql->options.extension->ssl_fp_list ,O_RDONLY, MYF(0))))
    {
      my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                          ER(CR_SSL_CONNECTION_ERROR), 
                          "Can't open finger print list");
      DBUG_RETURN(1);
    }

    while (fgets(buff, sizeof(buff)-1, fp))
    {
      /* remove trailing new line character */
      char *pos= strchr(buff, '\r');
      if (!pos)
        pos= strchr(buff, '\n');
      if (pos)
        *pos= '\0';
        
      if (!ma_check_fingerprint(fingerprint, fp_length, buff, strlen(buff)))
      {
        /* finger print is valid: close file and exit */
        my_fclose(fp, MYF(0));
        DBUG_RETURN(0);
      }
    }

    /* No finger print matched - close file and return error */
    my_fclose(fp, MYF(0));
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                 ER(CR_SSL_CONNECTION_ERROR), 
                 "invalid finger print of server certificate");
    DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
}

/* 
  verify server certificate

  SYNOPSIS
    my_ssl_verify_server_cert()
      MYSQL        mysql
      mybool       verify_server_cert;

  RETURN VALUES
     1 Error
     0 OK
*/

int my_ssl_verify_server_cert(SSL *ssl)
{
  X509 *cert;
  MYSQL *mysql;
  X509_NAME *x509sn;
  int cn_pos;
  X509_NAME_ENTRY *cn_entry;
  ASN1_STRING *cn_asn1;
  const char *cn_str;

  DBUG_ENTER("my_ssl_verify_server_cert");

  mysql= (MYSQL *)SSL_get_app_data(ssl);

  if (!mysql->host)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Invalid (empty) hostname");
    DBUG_RETURN(1);
  }

  if (!(cert= SSL_get_peer_certificate(ssl)))
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Unable to get server certificate");
    DBUG_RETURN(1);
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

  DBUG_RETURN(0);

error:
  X509_free(cert);

  my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                      ER(CR_SSL_CONNECTION_ERROR), 
                      "Validation of SSL server certificate failed");
  DBUG_RETURN(1);
}
/*
   write to ssl socket

   SYNOPSIS
     my_ssl_write()
       vio         vio
       buf         write buffer
       size        size of buffer

   RETURN VALUES
     bytes written
*/
size_t my_ssl_write(Vio *vio, const uchar* buf, size_t size)
{
  size_t written;
  DBUG_ENTER("my_ssl_write");
  if (vio->async_context && vio->async_context->active)
    written= my_ssl_write_async(vio->async_context, (SSL *)vio->ssl, buf,
                            size);
  else
    written= SSL_write((SSL*) vio->ssl, buf, size);
  DBUG_RETURN(written);
}

/*
    read from ssl socket

    SYNOPSIS
      my_ssl_read()
        vio        vio
        buf        read buffer
        size_t     max number of bytes to read

    RETURN VALUES
      number of bytes read
*/
size_t my_ssl_read(Vio *vio, uchar* buf, size_t size)
{
  size_t read;
  DBUG_ENTER("my_ssl_read");

  if (vio->async_context && vio->async_context->active)
    read= my_ssl_read_async(vio->async_context, (SSL *)vio->ssl, buf, size);
  else
    read= SSL_read((SSL*) vio->ssl, buf, size);
  DBUG_RETURN(read);
}

/* 
   close ssl connection and free
   ssl object

   SYNOPSIS
     my_ssl_close()
       vio     vio

   RETURN VALUES
     1  ok
     0 or -1 on error
*/
int my_ssl_close(Vio *vio)
{
  int i, rc;
  DBUG_ENTER("my_ssl_close");

  if (!vio || !vio->ssl)
    DBUG_RETURN(1);

  SSL_set_quiet_shutdown(vio->ssl, 1); 
  /* 2 x pending + 2 * data = 4 */ 
  for (i=0; i < 4; i++)
    if ((rc= SSL_shutdown(vio->ssl)))
      break;

  SSL_free(vio->ssl);
  vio->ssl= NULL;

  DBUG_RETURN(rc);
}

#endif /* HAVE_OPENSSL */
