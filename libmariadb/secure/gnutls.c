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
#include <gnutls/abstract.h>
#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>
#include <ma_pvio.h>
#include <ma_errmsg.h>
#include <ma_pthread.h>
#include <mysql/client_plugin.h>
#include <string.h>
#include <ma_tls.h>

pthread_mutex_t LOCK_gnutls_config;

static gnutls_certificate_credentials_t GNUTLS_xcred;
extern my_bool ma_tls_initialized;
extern unsigned int mariadb_deinitialize_ssl;

static int my_verify_callback(gnutls_session_t ssl);

struct st_gnutls_data {
  MYSQL *mysql;
  gnutls_privkey_t key;
  gnutls_pcert_st cert;
};

struct st_cipher_map {
  const char *openssl_name;
  const char *priority;
  gnutls_kx_algorithm_t kx;
  gnutls_cipher_algorithm_t cipher;
  gnutls_mac_algorithm_t mac;
};

const struct st_cipher_map gtls_ciphers[]=
{
  {"DHE-RSA-AES256-GCM-SHA384", ":+AEAD:+DHE-RSA:+AES-256-GCM",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_MAC_AEAD},
  {"DHE-RSA-AES256-SHA256", ":+SHA256:+DHE-RSA:+AES-256-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA256},
  {"DHE-RSA-AES256-SHA", ":+SHA1:+DHE-RSA:+AES-256-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1},
  {"DHE-RSA-CAMELLIA256-SHA", ":+SHA1:+DHE-RSA:+CAMELLIA-256-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_CAMELLIA_256_CBC, GNUTLS_MAC_SHA1},
  {"AES256-GCM-SHA384", ":+AEAD:+RSA:+AES-256-GCM",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_MAC_AEAD},
  {"AES256-SHA256", ":+SHA256:+RSA:+AES-256-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA256},
  {"AES256-SHA", ":+SHA1:+RSA:+AES-256-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1},
  {"CAMELLIA256-SHA", ":+SHA1:+RSA:+CAMELLIA-256-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_CAMELLIA_256_CBC, GNUTLS_MAC_SHA1},
  {"DHE-RSA-AES128-GCM-SHA256", ":+AEAD:+DHE-RSA:+AES-128-GCM",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_MAC_AEAD},
  {"DHE-RSA-AES128-SHA256", ":+SHA256:+DHE-RSA:+AES-128-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA256},
  {"DHE-RSA-AES128-SHA", ":+SHA1:+DHE-RSA:+AES-128-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1},
  {"DHE-RSA-CAMELLIA128-SHA", ":+SHA1:+DHE-RSA:+CAMELLIA-128-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_CAMELLIA_128_CBC, GNUTLS_MAC_SHA1},
  {"AES128-GCM-SHA256", ":+AEAD:+RSA:+AES-128-GCM",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_MAC_AEAD},
  {"AES128-SHA256", ":+SHA256:+RSA:+AES-128-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA256},
  {"AES128-SHA", ":+SHA1:+RSA:+AES-128-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1},
  {"CAMELLIA128-SHA", ":+SHA1:+RSA:+CAMELLIA-128-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_CAMELLIA_128_CBC, GNUTLS_MAC_SHA1},
  {"EDH-RSA-DES-CBC3-SHA", ":+SHA1:+DHE-RSA:+3DES-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_3DES_CBC, GNUTLS_MAC_SHA1},
  {"DES-CBC3-SHA", ":+SHA1:+RSA:+3DES-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_3DES_CBC, GNUTLS_MAC_SHA1},
  {"DHE-RSA-AES256-SHA", ":+SHA1:+DHE-RSA:+AES-256-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1},
  {"DHE-RSA-CAMELLIA256-SHA", ":+SHA1:+DHE-RSA:+CAMELLIA-256-CBC",
   GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_CAMELLIA_256_CBC, GNUTLS_MAC_SHA1},
  {"AES256-SHA", ":+SHA1:+RSA:+AES-256-CBC",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1},
  {"CAMELLIA256-SHA", ":+SHA1:+RSA:+CAMELLIA-256-CBC:",
   GNUTLS_KX_RSA, GNUTLS_CIPHER_CAMELLIA_256_CBC, GNUTLS_MAC_SHA1},
  {NULL, NULL, 0, 0, 0}
};

/* free data assigned to the connection */
static void free_gnutls_data(struct st_gnutls_data *data)
{
  if (data)
  {
    if (data->key)
      gnutls_privkey_deinit(data->key);
    gnutls_pcert_deinit(&data->cert);
    free(data);
  }
}

/* map the gnutls cipher suite (defined by key exchange algorithm, cipher
   and mac algorithm) to the corresponding OpenSSL cipher name */
static const char *openssl_cipher_name(gnutls_kx_algorithm_t kx,
                                       gnutls_cipher_algorithm_t cipher,
                                       gnutls_mac_algorithm_t mac)
{
  unsigned int i=0;
  while (gtls_ciphers[i].openssl_name)
  {
    if (gtls_ciphers[i].kx == kx &&
        gtls_ciphers[i].cipher == cipher &&
        gtls_ciphers[i].mac == mac)
      return gtls_ciphers[i].openssl_name;
    i++;
  }
  return NULL;
}

/* get priority string for a given openssl cipher name */
static const char *get_priority(const char *cipher_name)
{
  unsigned int i= 0;
  while (gtls_ciphers[i].openssl_name)
  {
    if (strcmp(gtls_ciphers[i].openssl_name, cipher_name) == 0)
      return gtls_ciphers[i].priority;
    i++;
  }
  return NULL;
}

#define MAX_SSL_ERR_LEN 100

static void ma_tls_set_error(MYSQL *mysql, void *ssl, int ssl_errno)
{
  char  ssl_error[MAX_SSL_ERR_LEN];
  const char *ssl_error_reason;
  MARIADB_PVIO *pvio= mysql->net.pvio;

  if (!ssl_errno)
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return;
  }

  /* give a more descriptive error message for alerts */
  if (ssl_errno == GNUTLS_E_FATAL_ALERT_RECEIVED)
  {
    gnutls_alert_description_t alert_desc;
    const char *alert_name;
    alert_desc= gnutls_alert_get((gnutls_session_t)ssl);
    alert_name= gnutls_alert_get_name(alert_desc);
    snprintf(ssl_error, MAX_SSL_ERR_LEN, "fatal alert received: %s",
             alert_name);
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0, 
                   ssl_error);
    return;
  }

  if ((ssl_error_reason= gnutls_strerror(ssl_errno)))
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0, 
                   ssl_error_reason);
    return;
  }
  snprintf(ssl_error, MAX_SSL_ERR_LEN, "SSL errno=%d", ssl_errno);
  pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 
                 ssl_error);
}


static void ma_tls_get_error(char *errmsg, size_t length, int ssl_errno)
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
  snprintf(errmsg, length, "SSL errno=%d", ssl_errno);
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
int ma_tls_start(char *errmsg, size_t errmsg_len)
{
  int rc= 0;

  if (ma_tls_initialized)
    return 0;

  pthread_mutex_init(&LOCK_gnutls_config,MY_MUTEX_INIT_FAST);
  pthread_mutex_lock(&LOCK_gnutls_config);

  if ((rc= gnutls_global_init()) != GNUTLS_E_SUCCESS)
  {
    ma_tls_get_error(errmsg, errmsg_len, rc);
    goto end;
  }
  /* Allocate a global context for credentials */
  rc= gnutls_certificate_allocate_credentials(&GNUTLS_xcred);
  ma_tls_initialized= TRUE;
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
void ma_tls_end()
{
  if (ma_tls_initialized)
  {
    pthread_mutex_lock(&LOCK_gnutls_config);
    gnutls_certificate_free_keys(GNUTLS_xcred);
    gnutls_certificate_free_cas(GNUTLS_xcred);
    gnutls_certificate_free_crls(GNUTLS_xcred);
    gnutls_certificate_free_ca_names(GNUTLS_xcred);
    gnutls_certificate_free_credentials(GNUTLS_xcred);
    if (mariadb_deinitialize_ssl)
      gnutls_global_deinit();
    ma_tls_initialized= FALSE;
    pthread_mutex_unlock(&LOCK_gnutls_config);
    pthread_mutex_destroy(&LOCK_gnutls_config);
  }
  return;
}

static int ma_gnutls_set_ciphers(gnutls_session_t ssl, char *cipher_str)
{
  const char *err;
  char *token;
#define PRIO_SIZE 1024  
  char prio[PRIO_SIZE];

  if (!cipher_str)
    return gnutls_priority_set_direct(ssl, "NORMAL", &err);

  token= strtok(cipher_str, ":");

  strcpy(prio, "NONE:+VERS-TLS-ALL:+SIGN-ALL:+COMP-NULL");

  while (token)
  {
    const char *p= get_priority(token);
    if (p)
      strncat(prio, p, PRIO_SIZE - strlen(prio) - 1);
    token = strtok(NULL, ":");
  }
  return gnutls_priority_set_direct(ssl, prio , &err);
}

static int ma_tls_set_certs(MYSQL *mysql)
{
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

  return 1;

error:
  return ssl_error;
}

static int
client_cert_callback(gnutls_session_t session,
                     const gnutls_datum_t * req_ca_rdn __attribute__((unused)),
                     int nreqs __attribute__((unused)),
                     const gnutls_pk_algorithm_t * sign_algos __attribute__((unused)),
                     int sign_algos_length __attribute__((unused)), 
                     gnutls_pcert_st ** pcert,
                     unsigned int *pcert_length, gnutls_privkey_t * pkey)
{
  struct st_gnutls_data *session_data;
  char *certfile, *keyfile;
  gnutls_datum_t data;
  MYSQL *mysql;
  gnutls_certificate_type_t type= gnutls_certificate_type_get(session);

  session_data= (struct st_gnutls_data *)gnutls_session_get_ptr(session);

  if (!session_data->mysql ||
      type != GNUTLS_CRT_X509)
    return -1;

  mysql= session_data->mysql;

  certfile= session_data->mysql->options.ssl_cert;
  keyfile= session_data->mysql->options.ssl_key;

  if (!certfile && !keyfile)
    return 0;
  if (keyfile && !certfile)
    certfile= keyfile;
  if (certfile && !keyfile)
    keyfile= certfile;

  if (gnutls_load_file(certfile, &data) < 0)
    return -1;
  if (gnutls_pcert_import_x509_raw(&session_data->cert, &data, GNUTLS_X509_FMT_PEM, 0) < 0)
  {
    gnutls_free(data.data);
    return -1;
  }
  gnutls_free(data.data);

  if (gnutls_load_file(keyfile, &data) < 0)
    return -1;
  gnutls_privkey_init(&session_data->key);
  if (gnutls_privkey_import_x509_raw(session_data->key, &data, 
            GNUTLS_X509_FMT_PEM,
            mysql->options.extension ? mysql->options.extension->tls_pw : NULL,
                                     0) < 0)
  {
    gnutls_free(data.data);
    return -1;
  }
  gnutls_free(data.data);

  *pcert_length= 1;
  *pcert= &session_data->cert;
  *pkey= session_data->key;
  return 0;
}

void *ma_tls_init(MYSQL *mysql)
{
  gnutls_session_t ssl= NULL;
  int ssl_error= 0;
  struct st_gnutls_data *data= NULL;

  pthread_mutex_lock(&LOCK_gnutls_config);

  if ((ssl_error= ma_tls_set_certs(mysql)) < 0)
    goto error;

  if ((ssl_error = gnutls_init(&ssl, GNUTLS_CLIENT & GNUTLS_NONBLOCK)) < 0)
    goto error;

  if (!(data= (struct st_gnutls_data *)calloc(1, sizeof(struct st_gnutls_data))))
    goto error;

  data->mysql= mysql;
  gnutls_certificate_set_retrieve_function2(GNUTLS_xcred, client_cert_callback);
  gnutls_session_set_ptr(ssl, (void *)data);
 
  ssl_error= ma_gnutls_set_ciphers(ssl, mysql->options.ssl_cipher);
  if (ssl_error < 0)
    goto error;

  /* we don't load private key and cert by default - if the server requests
     a client certificate we will send it via callback function */
  if ((ssl_error= gnutls_credentials_set(ssl, GNUTLS_CRD_CERTIFICATE, GNUTLS_xcred)) < 0)
    goto error;
  
  pthread_mutex_unlock(&LOCK_gnutls_config);
  return (void *)ssl;
error:
  free_gnutls_data(data);
  ma_tls_set_error(mysql, ssl, ssl_error);
  if (ssl)
    gnutls_deinit(ssl);
  pthread_mutex_unlock(&LOCK_gnutls_config);
  return NULL;
}

ssize_t ma_tls_push(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
  MARIADB_PVIO *pvio= (MARIADB_PVIO *)ptr;
  ssize_t rc= pvio->methods->write(pvio, data, len);
  return rc;
}

ssize_t ma_tls_pull(gnutls_transport_ptr_t ptr, void* data, size_t len)
{
  MARIADB_PVIO *pvio= (MARIADB_PVIO *)ptr;
  ssize_t rc= pvio->methods->read(pvio, data, len);
  return rc;
}

static int ma_tls_pull_timeout(gnutls_transport_ptr_t ptr, unsigned int ms)
{
  MARIADB_PVIO *pvio= (MARIADB_PVIO *)ptr;
  return pvio->methods->wait_io_or_timeout(pvio, 0, ms);
}

my_bool ma_tls_connect(MARIADB_TLS *ctls)
{
  gnutls_session_t ssl = (gnutls_session_t)ctls->ssl;
  my_bool blocking;
  MYSQL *mysql;
  MARIADB_PVIO *pvio;
  int ret;
  struct st_gnutls_data *data;
  data= (struct st_gnutls_data *)gnutls_session_get_ptr(ssl);
  mysql= data->mysql;

  if (!mysql)
    return 1;

  pvio= mysql->net.pvio;

  /* Set socket to blocking if not already set */
  if (!(blocking= pvio->methods->is_blocking(pvio)))
    pvio->methods->blocking(pvio, TRUE, 0);

  /* we don't use GnuTLS read/write functions */
  gnutls_transport_set_ptr(ssl, pvio);
  gnutls_transport_set_push_function(ssl, ma_tls_push);
  gnutls_transport_set_pull_function(ssl, ma_tls_pull);
  gnutls_transport_set_pull_timeout_function(ssl, ma_tls_pull_timeout);
  gnutls_handshake_set_timeout(ssl, pvio->timeout[PVIO_CONNECT_TIMEOUT]);

  do {
    ret = gnutls_handshake(ssl);
  } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

  if (ret < 0)
  {
    ma_tls_set_error(mysql, ssl, ret);
    /* restore blocking mode */
    gnutls_deinit((gnutls_session_t )ctls->ssl);
    free_gnutls_data(data);
    ctls->ssl= NULL;
    if (!blocking)
      pvio->methods->blocking(pvio, FALSE, 0);
    return 1;
  }
  ctls->ssl= (void *)ssl;
  return 0;
}

size_t ma_tls_read(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{
  return gnutls_record_recv((gnutls_session_t )ctls->ssl, (void *)buffer, length);
}

size_t ma_tls_write(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{ 
  return gnutls_record_send((gnutls_session_t )ctls->ssl, (void *)buffer, length);
}

my_bool ma_tls_close(MARIADB_TLS *ctls)
{
  if (ctls->ssl)
  {
    MARIADB_PVIO *pvio= ctls->pvio;
    struct st_gnutls_data *data=
      (struct st_gnutls_data *)gnutls_session_get_ptr(ctls->ssl);
    /* this would be the correct way, however can't dectect afterwards
       if the socket is closed or not, so we don't send encrypted 
       finish alert.
    rc= gnutls_bye((gnutls_session_t )ctls->ssl, GNUTLS_SHUT_WR);
    */
    free_gnutls_data(data);
    gnutls_deinit((gnutls_session_t )ctls->ssl);
    ctls->ssl= NULL;
  }
  return 0;
}

int ma_tls_verify_server_cert(MARIADB_TLS *ctls __attribute__((unused)))
{
  /* server verification is already handled before */
  return 0;
}

const char *ma_tls_get_cipher(MARIADB_TLS *ctls)
{
  gnutls_kx_algorithm_t kx;
  gnutls_cipher_algorithm_t cipher;
  gnutls_mac_algorithm_t mac;

  if (!ctls || !ctls->ssl)
    return NULL;

  mac= gnutls_mac_get((gnutls_session_t)ctls->ssl);
  cipher= gnutls_cipher_get((gnutls_session_t)ctls->ssl);
  kx= gnutls_kx_get((gnutls_session_t)ctls->ssl);
  return openssl_cipher_name(kx, cipher, mac);
}

static int my_verify_callback(gnutls_session_t ssl)
{
  unsigned int status= 0;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  struct st_gnutls_data *data= (struct st_gnutls_data *)gnutls_session_get_ptr(ssl);
  MYSQL *mysql;
  MARIADB_PVIO *pvio;
  
  gnutls_x509_crt_t cert;
  const char *hostname;

  mysql= data->mysql;
  pvio= mysql->net.pvio;

  /* read hostname */
  hostname = mysql->host;

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  if ((mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT)  &&
        gnutls_certificate_verify_peers2 (ssl, &status) < 0)
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "CA verification failed");
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
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Expected X509 certificate");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  if (gnutls_x509_crt_init (&cert) < 0)
  {
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Error during certificate initialization");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  cert_list = gnutls_certificate_get_peers (ssl, &cert_list_size);
  if (cert_list == NULL)
  {
    gnutls_x509_crt_deinit (cert);
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "No certificate found");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
  {
    gnutls_x509_crt_deinit (cert);
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }

  if ((mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT) &&
      !gnutls_x509_crt_check_hostname (cert, hostname))
  {
    gnutls_x509_crt_deinit (cert);
    pvio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Hostname in certificate doesn't match");
    return GNUTLS_E_CERTIFICATE_ERROR;
  }
  gnutls_x509_crt_deinit (cert);
  /* notify gnutls to continue handshake normally */

  CLEAR_CLIENT_ERROR(mysql);
  return 0;
}

unsigned int ma_tls_get_finger_print(MARIADB_TLS *ctls, char *fp, unsigned int len)
{
  MYSQL *mysql;
  size_t fp_len= len;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  struct st_gnutls_data *data;

  if (!ctls || !ctls->ssl)
    return 0;

  data= (struct st_gnutls_data *)gnutls_session_get_ptr(ctls->ssl);
  mysql= (MYSQL *)data->mysql;

  cert_list = gnutls_certificate_get_peers (ctls->ssl, &cert_list_size);
  if (cert_list == NULL)
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Unable to get server certificate");
    return 0;
  }

  if (gnutls_fingerprint(GNUTLS_DIG_SHA1, &cert_list[0], fp, &fp_len) == 0)
    return fp_len;
  else
  {
    my_set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                        ER(CR_SSL_CONNECTION_ERROR), 
                        "Finger print buffer too small");
    return 0;
  }
}

my_bool ma_tls_get_protocol_version(MARIADB_TLS *ctls, struct st_ssl_version *version)
{
  if (!ctls || !ctls->ssl)
    return 1;

  version->iversion= gnutls_protocol_get_version(ctls->ssl);
  version->cversion= (char *)gnutls_protocol_get_name(version->iversion);
  return 0;  
}
#endif /* HAVE_GNUTLS */
