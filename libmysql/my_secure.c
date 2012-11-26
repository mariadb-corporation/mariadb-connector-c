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
#ifdef HAVE_OPENSSL

#include <my_global.h>
#include <my_sys.h>
#include <my_secure.h>
#include <errmsg.h>
#include <violite.h>

static my_bool my_ssl_initialized= FALSE;
static SSL_CTX *SSL_context= NULL;

#define MAX_SSL_ERR_LEN 100

#ifdef THREAD
extern pthread_mutex_t LOCK_ssl_config;
static pthread_mutex_t *LOCK_crypto;
#endif

/* 
 SSL error handling
*/
static void my_SSL_error(MYSQL *mysql)
{
  ulong ssl_errno= ERR_get_error();
  char  ssl_error[MAX_SSL_ERR_LEN];
  const char *ssl_error_reason;

  DBUG_ENTER("my_SSL_error");

  if (!ssl_errno)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "No SSL error");
    DBUG_VOID_RETURN;
  }
  if ((ssl_error_reason= ERR_reason_error_string(ssl_errno)))
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, ssl_error_reason);
    DBUG_VOID_RETURN;
  }
  my_snprintf(ssl_error, MAX_SSL_ERR_LEN, "SSL errno=%lu", ssl_errno, mysql->charset);
  my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, ssl_error);
  DBUG_VOID_RETURN;
}

#ifdef THREAD
/* 
   thread safe callbacks for OpenSSL 
   Crypto call back functions will be
   set during ssl_initialization
 */
static unsigned long my_cb_threadid(void)
{
  /* chast pthread_t to unsigned long */
	return (unsigned long) pthread_self();
}

static void
my_cb_locking(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&LOCK_crypto[n]);
	else
		pthread_mutex_unlock(&LOCK_crypto[n]);
}
#endif

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
#ifdef THREAD
  /* lock mutex to prevent multiple initialization */
  pthread_mutex_lock(&LOCK_ssl_config);
#endif

  if (!my_ssl_initialized)
  {
#ifdef THREAD
    if (!(LOCK_crypto= 
          (pthread_mutex_t *)my_malloc(sizeof(pthread_mutex_t) * 
                                       CRYPTO_num_locks(), MYF(0))))
    {
      rc= 1;
      goto end;
    } else
    {
      int i;

      for (i=0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&LOCK_crypto[i], NULL);
      CRYPTO_set_id_callback(my_cb_threadid);
			CRYPTO_set_locking_callback(my_cb_locking);
    }
#endif
#if SSLEAY_VERSION_NUMBER >= 0x00907000L
    OPENSSL_config(NULL);
#endif

    /* always returns 1, so we can discard return code */
    SSL_library_init();
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
#ifdef THREAD
  pthread_mutex_unlock(&LOCK_ssl_config);
#endif
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
#ifdef THREAD
  pthread_mutex_lock(&LOCK_ssl_config);
#endif
  if (my_ssl_initialized)
  {
#ifdef THREAD
    int i;
    CRYPTO_set_locking_callback(NULL);
		CRYPTO_set_id_callback(NULL);

    for (i=0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_destroy(&LOCK_crypto[i]);

    my_free((gptr)LOCK_crypto, MYF(0));
#endif    
    if (SSL_context)
    {
      SSL_CTX_free(SSL_context);
      SSL_context= FALSE;
    }
    ERR_free_strings();
    EVP_cleanup();
    CONF_modules_unload(1);
    CRYPTO_cleanup_all_ex_data();
    my_ssl_initialized= FALSE;
  }
#ifdef THREAD
  pthread_mutex_unlock(&LOCK_ssl_config);
#endif
  DBUG_VOID_RETURN;
}

#ifdef THREAD
#endif

/* 
  Set certification stuff.
*/
static int my_ssl_set_certs(SSL *ssl)
{
  int have_cert= 0;
  MYSQL *mysql;

  DBUG_ENTER("my_ssl_connect");

  /* Make sure that ssl was allocated and 
     ssl_system was initialized */
  DBUG_ASSERT(ssl != NULL);
  DBUG_ASSERT(my_ssl_initialized == TRUE);

  /* get connection for current ssl */
  mysql= (MYSQL *)SSL_get_app_data(ssl);

  /* add cipher */
  if ((mysql->options.ssl_cipher && 
        mysql->options.ssl_cipher[0] != 0) &&
      SSL_set_cipher_list(ssl, mysql->options.ssl_cipher) == 0)
    goto error;

  /* set cert */
  if (mysql->options.ssl_cert && mysql->options.ssl_cert[0] != 0)  
  {
    if ((SSL_CTX_use_certificate_chain_file(SSL_context, mysql->options.ssl_cert) != 1) &&
        (SSL_use_certificate_file(ssl, mysql->options.ssl_cert, SSL_FILETYPE_PEM) != 1))
      goto error;
    have_cert= 1;
  }

  /* set key */
  if (mysql->options.ssl_key && mysql->options.ssl_key[0])
  {
    if (SSL_use_PrivateKey_file(ssl, mysql->options.ssl_key, SSL_FILETYPE_PEM) != 1)
      goto error;

    /* verify key */
    if (have_cert && SSL_check_private_key(ssl) != 1)
      goto error;
  }
  /* ca_file and ca_path */
  if (SSL_CTX_load_verify_locations(SSL_context, 
                                    mysql->options.ssl_ca,
                                    mysql->options.ssl_capath) == 0)
  {
    if (SSL_CTX_set_default_verify_paths(SSL_context) == 0)
      goto error;
  }
  DBUG_RETURN(0);

error:
  my_SSL_error(mysql);
  DBUG_RETURN(1);
}

static int my_verify_callback(int ok, X509_STORE_CTX *ctx)
{
  /* since we don't have access to the mysql structure, we just return */
  return ok;
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

  DBUG_ENTER("my_get_ssl");

  DBUG_ASSERT(mysql->net.vio->ssl == NULL);

  if (!my_ssl_initialized)
    my_ssl_start(mysql); 

  if (!(ssl= SSL_new(SSL_context)))
    goto error;

  if (!SSL_set_app_data(ssl, mysql))
    goto error;

  if (my_ssl_set_certs(ssl))
    goto error;

  verify= (!mysql->options.ssl_ca && !mysql->options.ssl_capath) ?
           SSL_VERIFY_NONE : SSL_VERIFY_PEER;
  SSL_set_verify(ssl, verify, my_verify_callback);

  DBUG_RETURN(ssl);
error:
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

  DBUG_ENTER("my_ssl_connect");

  DBUG_ASSERT(ssl != NULL);

  mysql= (MYSQL *)SSL_get_app_data(ssl);

  /* Set socket to blocking if not already set */
  if (!(blocking= vio_is_blocking(mysql->net.vio)))
    vio_blocking(mysql->net.vio, TRUE);

  SSL_clear(ssl);
  SSL_SESSION_set_timeout(SSL_get_session(ssl),
                          mysql->options.connect_timeout);
  SSL_set_fd(ssl, mysql->net.vio->sd);

  if (SSL_connect(ssl) != 1)
  {
    my_SSL_error(mysql);
    /* restore blocking mode */
    if (!blocking)
      vio_blocking(mysql->net.vio, FALSE);
    DBUG_RETURN(1);
  }

  vio_reset(mysql->net.vio, VIO_TYPE_SSL, mysql->net.vio->sd, 0, 0);
  mysql->net.vio->ssl= ssl;
  DBUG_RETURN(0);
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

  /* 2 x pending + 2 * data = 4 */ 
  for (i=0; i < 4; i++)
    if ((rc= SSL_shutdown(vio->ssl)))
      break;

  SSL_free(vio->ssl);
  vio->ssl= NULL;

  return rc;
}

#endif /* HAVE_OPENSSL */
