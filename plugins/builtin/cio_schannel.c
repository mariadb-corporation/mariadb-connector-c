/************************************************************************************
  Copyright (C) 2014 MariaDB Corporation Ab

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
#include "ma_schannel.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "secur32.lib")

#define VOID void

static my_bool my_schannel_initialized= FALSE;

#define MAX_SSL_ERR_LEN 100

static pthread_mutex_t LOCK_schannel_config;
static pthread_mutex_t *LOCK_crypto= NULL;

int cio_schannel_start(char *errmsg, size_t errmsg_len, int count, va_list);
int cio_schannel_end();
void *cio_schannel_init(MARIADB_SSL *cssl, MYSQL *mysql);
my_bool cio_schannel_connect(MARIADB_SSL *cssl);
size_t cio_schannel_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
size_t cio_schannel_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length);
my_bool cio_schannel_close(MARIADB_SSL *cssl);
int cio_schannel_verify_server_cert(MARIADB_SSL *cssl);
const char *cio_schannel_cipher(MARIADB_SSL *cssl);

struct st_ma_cio_ssl_methods cio_schannel_methods= {
  cio_schannel_init,
  cio_schannel_connect,
  cio_schannel_read,
  cio_schannel_write,
  cio_schannel_close,
  cio_schannel_verify_server_cert,
  cio_schannel_cipher
};

#ifndef HAVE_SCHANNEL_DEFAULT
MARIADB_CIO_PLUGIN _mysql_client_plugin_declaration_=
#else
MARIADB_CIO_PLUGIN cio_schannel_plugin=
#endif
{
  MYSQL_CLIENT_CIO_PLUGIN,
  MYSQL_CLIENT_CIO_PLUGIN_INTERFACE_VERSION,
  "cio_schannel",
  "Georg Richter",
  "MariaDB communication IO plugin for Windows SSL/SChannel communication",
  {1, 0, 0},
  "LGPL",
  cio_schannel_start,
  cio_schannel_end,
  NULL,
  &cio_schannel_methods,
  NULL
};

static void cio_schannel_set_error(MYSQL *mysql)
{
  ulong ssl_errno= GetLastError();
  char  ssl_error[MAX_SSL_ERR_LEN];
  char *ssl_error_reason= NULL;
  MARIADB_CIO *cio= mysql->net.cio;

  if (!ssl_errno)
  {
    cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Unknown SSL error");
    return;
  }
  /* todo: obtain error messge */
  FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, ssl_errno, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR) &ssl_error_reason, 0, NULL );
  cio->set_error(mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, ssl_error_reason);

  if (ssl_error_reason)
    LocalFree(ssl_error_reason);
  return;
}


static int ssl_thread_init()
{
  return 0;
}


/*
  Initializes SSL and allocate global
  context SSL_context

  SYNOPSIS
    cio_schannel_start

  RETURN VALUES
    0  success
    1  error
*/
int cio_schannel_start(char *errmsg, size_t errmsg_len, int count, va_list list)
{
  if (!my_schannel_initialized)
  {
    pthread_mutex_init(&LOCK_schannel_config,MY_MUTEX_INIT_FAST);
    pthread_mutex_lock(&LOCK_schannel_config);

 //   SecureZeroMemory(&SC_CTX, sizeof(struct st_schannel_global));

    my_schannel_initialized= TRUE;
  }
  pthread_mutex_unlock(&LOCK_schannel_config);
  return 0;
}

/*
   Release SSL and free resources
   Will be automatically executed by 
   mysql_server_end() function

   SYNOPSIS
     cio_schannel_end()
       void

   RETURN VALUES
     void
*/
int cio_schannel_end()
{
  pthread_mutex_lock(&LOCK_schannel_config);
  if (my_schannel_initialized)
  {

    my_schannel_initialized= FALSE;
  }
  pthread_mutex_unlock(&LOCK_schannel_config);
  pthread_mutex_destroy(&LOCK_schannel_config);
  return 0;
}

/* {{{ static int cio_schannel_set_client_certs(MARIADB_SSL *cssl) */
static int cio_schannel_set_client_certs(MARIADB_SSL *cssl)
{
  MYSQL *mysql= cssl->cio->mysql;
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key,
       *cafile= mysql->options.ssl_ca;
       
  SC_CTX *sctx= (SC_CTX *)cssl->ssl;

  if (cafile)
    if (!(sctx->client_ca_ctx = ma_schannel_create_cert_context(cafile)))
      goto end;

  if (certfile)
  {
    if (!(sctx->client_cert_ctx = ma_schannel_create_cert_context(certfile)))
      goto end;
    if (keyfile)
      if (!ma_schannel_load_private_key(sctx->client_cert_ctx, keyfile))
        goto end;
  }

  if (mysql->options.extension && mysql->options.extension->ssl_crl)
  {
    sctx->client_crl_ctx= ma_schannel_create_crl_context(mysql->options.extension->ssl_crl);

  }
  return 0;
  
end:
  if (sctx->client_ca_ctx)
    CertFreeCertificateContext(sctx->client_ca_ctx);
  if (sctx->client_cert_ctx)
    CertFreeCertificateContext(sctx->client_cert_ctx);
  if (sctx->client_crl_ctx)
    CertFreeCRLContext(sctx->client_crl_ctx);

  cio_schannel_set_error(mysql);
  return 1;
}
/* }}} */

/* {{{ void *cio_schannel_init(MARIADB_SSL *cssl, MYSQL *mysql) */
void *cio_schannel_init(MARIADB_SSL *cssl, MYSQL *mysql)
{
  int verify;
  SC_CTX *sctx;

  if (!(sctx= LocalAlloc(0, sizeof(SC_CTX))))
    return NULL;
  ZeroMemory(sctx, sizeof(SC_CTX));

  cssl->data= (void *)sctx;

  pthread_mutex_lock(&LOCK_schannel_config);
  return (void *)sctx;
error:
  pthread_mutex_unlock(&LOCK_schannel_config);
  return NULL;
}
/* }}} */




static my_bool VerifyServerCertificate(SC_CTX *sctx, PCCERT_CONTEXT pServerCert, PSTR pszServerName, DWORD dwCertFlags )
{
  SECURITY_STATUS sRet;
  DWORD flags;
  char *szName= NULL;
  int rc= 0;

  /* We perform a manually validation, as described at
     http://msdn.microsoft.com/en-us/library/windows/desktop/aa378740%28v=vs.85%29.aspx
  */

  /* Check if
    - The certificate chain is complete and the root is a certificate from a trusted certification authority (CA).
    - The current time is not beyond the begin and end dates for each of the certificates in the certificate chain.
  */
  flags= CERT_STORE_SIGNATURE_FLAG |
         CERT_STORE_TIME_VALIDITY_FLAG;
    
 	if (!(sRet= CertVerifySubjectCertificateContext(pServerCert,
                                                        sctx->client_ca_ctx,
                                                        &flags)))
  {
    /* todo: error handling */
    return 0;
  }

  /* Check if none of the certificates in the certificate chain have been revoked. */
  if (sctx->client_crl_ctx)
  {
    PCRL_INFO Info[1];

    Info[0]= sctx->client_crl_ctx->pCrlInfo;
    if (!(CertVerifyCRLRevocation(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                  pServerCert->pCertInfo,
                                  1, Info))                               )
    {
      /* todo: error handling */
      return 0;
    }
  }

  /* check server name */
  if (pszServerName)
  {
    DWORD NameSize= 0;
    char *p1, *p2;

    if (!(NameSize= CertNameToStr(pServerCert->dwCertEncodingType,
      &pServerCert->pCertInfo->Subject,
      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
      NULL, 0)))
    {
      /* todo: error handling */
      return 0;
    }

    if (!(szName= LocalAlloc(0, NameSize + 1)))
    {
      /* error handling */
      return 0;
    }

    if (!CertNameToStr(pServerCert->dwCertEncodingType,
      &pServerCert->pCertInfo->Subject,
      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
      szName, NameSize))
    {
      /* error handling */
      goto end;
    }
    if ((p1 = strstr(szName, "CN=")))
    {
      p1+= 3;
      if ((p2= strstr(p1, ", ")))
        *p2= 0;
      if (!strcmp(pszServerName, p1))
      {
        rc= 1;
        goto end;
      }

    }

  }

end:
    if (szName)
      LocalFree(szName);
    return rc;  

}

my_bool cio_schannel_connect(MARIADB_SSL *cssl)
{
  my_bool blocking;
  MYSQL *mysql;
  SCHANNEL_CRED Cred;
  MARIADB_CIO *cio;
  SC_CTX *sctx;
  SECURITY_STATUS sRet;
  PCCERT_CONTEXT pRemoteCertContext = NULL;

  if (!cssl || !cssl->cio || !cssl->data)
    return 1;;
  
  cio= cssl->cio;
  sctx= (SC_CTX *)cssl->data;

  /* Set socket to blocking if not already set */
  if (!(blocking= cio->methods->is_blocking(cio)))
    cio->methods->blocking(cio, TRUE, 0);

  mysql= cio->mysql;

  if (cio_schannel_set_client_certs(cssl))
  {
    cio_schannel_set_error(mysql);
    goto end;
  }

  ZeroMemory(&Cred, sizeof(SCHANNEL_CRED));
  Cred.dwVersion= SCHANNEL_CRED_VERSION;
  Cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK |
			SCH_CRED_NO_DEFAULT_CREDS |
			SCH_CRED_MANUAL_CRED_VALIDATION;
	if (sctx->client_cert_ctx)
	{
    Cred.cCreds = 1;
    Cred.paCred = &sctx->client_cert_ctx;
  }
  Cred.grbitEnabledProtocols= SP_PROT_TLS1;

  /*  We allocate 2 x net_buffer_length */
  if (!(sctx->IoBuffer= (PUCHAR)LocalAlloc(0, 0x4000)))
    goto end;

  if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
 									            NULL, &Cred, NULL, NULL, &sctx->CredHdl, NULL) != SEC_E_OK)
    goto end;

  if (ma_schannel_client_handshake(cssl))
    goto end;

  sRet= QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext);
  if (sRet != SEC_E_OK)
    goto end;

  if (!VerifyServerCertificate(sctx, 
                               pRemoteCertContext,
                               mysql->host,
                               0 ))
    goto end;


  return 0;
end:
  /* todo: cleanup */
  if (sctx->IoBuffer)
    LocalFree(sctx->IoBuffer);
  if (sctx->client_ca_ctx)
    CertFreeCertificateContext(sctx->client_ca_ctx);
  if (sctx->client_cert_ctx)
    CertFreeCertificateContext(sctx->client_cert_ctx);
  return 1;
}

size_t cio_schannel_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
}

size_t cio_schannel_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{ 
}

my_bool cio_schannel_close(MARIADB_SSL *cssl)
{
  int i, rc;

  return rc;
}

int cio_schannel_verify_server_cert(MARIADB_SSL *cssl)
{
}

const char *cio_schannel_cipher(MARIADB_SSL *cssl)
{
  if (!cssl || !cssl->ssl)
    return NULL;
}
