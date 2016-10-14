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

//#define VOID void

extern my_bool ma_tls_initialized;

struct st_cipher_suite {
  DWORD aid;
  CHAR *cipher;
};

const struct st_cipher_suite valid_ciphers[] =
{
  { CALG_3DES, "CALG_3DES" },
  { CALG_3DES_112, "CALG_3DES_112" },
  { CALG_AES, "CALG_AES" },
  { CALG_AES_128, "CALG_AES_128" },
  { CALG_AES_192, "CALG_AES_192" },
  { CALG_AES_256, "CALG_AES_256" },
  { CALG_AGREEDKEY_ANY, "CALG_AGREEDKEY_ANY" },
  { CALG_CYLINK_MEK, "CALG_CYLINK_MEK" },
  { CALG_DES, "CALG_DES" },
  { CALG_DESX, "CALG_DESX" },
  { CALG_DH_EPHEM, "CALG_DH_EPHEM" },
  { CALG_DH_SF, "CALG_DH_SF" },
  { CALG_DSS_SIGN, "CALG_DSS_SIGN" },
  { CALG_ECDH, "CALG_ECDH" },
  { CALG_ECDSA, "CALG_ECDSA" },
  { CALG_ECMQV, "CALG_ECMQV" },
  { CALG_HASH_REPLACE_OWF, "CALG_HASH_REPLACE_OWF" },
  { CALG_HUGHES_MD5, "CALG_HUGHES_MD5" },
  { CALG_HMAC, "CALG_HMAC" },
  { CALG_KEA_KEYX, "CALG_KEA_KEYX" },
  { CALG_MAC, "CALG_MAC" },
  { CALG_MD2, "CALG_MD2" },
  { CALG_MD4, "CALG_MD4" },
  { CALG_MD4, "CALG_MD5" },
  { CALG_NO_SIGN, "CALG_NO_SIGN" },
  { CALG_OID_INFO_CNG_ONLY, "CALG_OID_INFO_CNG_ONLY" },
  { CALG_OID_INFO_PARAMETERS, "CALG_OID_INFO_PARAMETERS" },
  { CALG_RC2, "CALG_RC2" },
  { CALG_RC4, "CALG_RC4" },
  { CALG_RC5, "CALG_RC5" },
  { CALG_RSA_KEYX, "CALG_RSA_KEYX" },
  { CALG_RSA_SIGN, "CALG_RSA_SIGN" },
  { CALG_SHA, "CALG_SHA" },
  { CALG_SHA1, "CALG_SHA1" },
  { CALG_SHA_256, "CALG_SHA_256" },
  { CALG_SHA_384, "CALG_SHA_384" },
  { CALG_SHA_512, "CALG_SHA_512" },
  { 0, NULL }
};

#define MAX_ALG_ID 50

void ma_schannel_set_sec_error(MARIADB_PVIO *pvio, DWORD ErrorNo);
void ma_schannel_set_win_error(MYSQL *mysql);

/*
  Initializes SSL and allocate global
  context SSL_context

  SYNOPSIS
    ma_tls_start

  RETURN VALUES
    0  success
    1  error
*/
int ma_tls_start(char *errmsg, size_t errmsg_len)
{

  ma_tls_initialized = TRUE;
  return 0;
}

/*
   Release SSL and free resources
   Will be automatically executed by 
   mysql_server_end() function

   SYNOPSIS
     ma_tls_end()
       void

   RETURN VALUES
     void
*/
void ma_tls_end()
{
  return;
}

/* {{{ static int ma_tls_set_client_certs(MARIADB_TLS *ctls) */
static int ma_tls_set_client_certs(MARIADB_TLS *ctls)
{
  MYSQL *mysql= ctls->pvio->mysql;
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key;
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  MARIADB_PVIO *pvio= ctls->pvio;

  sctx->client_cert_ctx= NULL;

  if (!certfile && keyfile)
    certfile= keyfile;
  if (!keyfile && certfile)
    keyfile= certfile;

  if (!certfile)
    return 0;

  if (!(sctx->client_cert_ctx = ma_schannel_create_cert_context(ctls->pvio, certfile)))
    return 1;

  if (!ma_schannel_load_private_key(pvio, sctx->client_cert_ctx, keyfile))
  {
    CertFreeCertificateContext(sctx->client_cert_ctx);
    sctx->client_cert_ctx= NULL;
    return 1;
  }
  return 0;
}
/* }}} */

/* {{{ void *ma_tls_init(MARIADB_TLS *ctls, MYSQL *mysql) */
void *ma_tls_init(MYSQL *mysql)
{
  SC_CTX *sctx= NULL;
  if ((sctx= (SC_CTX *)LocalAlloc(0, sizeof(SC_CTX))))
  {
    ZeroMemory(sctx, sizeof(SC_CTX));
    sctx->mysql= mysql;
  }
  return sctx;
}
/* }}} */


/* 
  Maps between openssl suite names and schannel alg_ids.
  Every suite has 3 algorithms (for exchange, encryption, hash).
  
  The input string is a set of suite names (openssl),  separated 
  by ':'
  
  The output is written into the array 'arr' of size 'arr_size'
  The function returns number of elements written to the 'arr'.
*/

static size_t set_cipher(char * cipher_str, ALG_ID *arr , size_t arr_size)
{
  /* TODO : extend this mapping table */
  struct 
  {
    ALG_ID algs[3]; /* exchange, encryption, hash */
    const char *openssl_name;
  }
  map[] = 
  {
    {{CALG_RSA_KEYX,CALG_AES_256,CALG_SHA}, "AES256-SHA"}, 
    {{CALG_RSA_KEYX,CALG_AES_128,CALG_SHA}, "AES128-SHA"},
    {{CALG_RSA_KEYX,CALG_RC4,CALG_SHA}, "RC4-SHA"},
    {{CALG_RSA_KEYX,CALG_3DES,CALG_SHA}, "DES-CBC3-SHA"},
    {{CALG_RSA_KEYX, CALG_AES_128, CALG_SHA_256 }, "AES128-SHA256" },
  };
  
  char *token = strtok(cipher_str, ":");
  size_t pos = 0;
  while (token)
  {
    size_t i;
    for(i = 0; i < sizeof(map)/sizeof(map[0]) ; i++)
    {
      if(pos + 3 < arr_size && strcmp(map[i].openssl_name, token) == 0)
      {
        memcpy(arr + pos, map[i].algs, sizeof(map[i].algs));
        pos += 3;
        break;
      }
    }
    token = strtok(NULL, ":");
  }
  return pos;
}

my_bool ma_tls_connect(MARIADB_TLS *ctls)
{
  my_bool blocking;
  MYSQL *mysql;
  SCHANNEL_CRED Cred;
  MARIADB_PVIO *pvio;
  my_bool rc= 1;
  SC_CTX *sctx;
  SECURITY_STATUS sRet;
  ALG_ID AlgId[MAX_ALG_ID];
  WORD validTokens = 0;

  if (!ctls || !ctls->pvio)
    return 1;;
  
  pvio= ctls->pvio;
  sctx= (SC_CTX *)ctls->ssl;

  /* Set socket to blocking if not already set */
  if (!(blocking= pvio->methods->is_blocking(pvio)))
    pvio->methods->blocking(pvio, TRUE, 0);

  mysql= pvio->mysql;
 
  if (ma_tls_set_client_certs(ctls))
    goto end;

  ZeroMemory(&Cred, sizeof(SCHANNEL_CRED));

  /* Set cipher */
  if (mysql->options.ssl_cipher)
  {
    Cred.cSupportedAlgs = (DWORD)set_cipher(mysql->options.ssl_cipher, AlgId, MAX_ALG_ID);
    if (Cred.cSupportedAlgs)
    {
      Cred.palgSupportedAlgs = AlgId;
    }
    else
    {
      ma_schannel_set_sec_error(pvio, SEC_E_ALGORITHM_MISMATCH);
      goto end;
    }
  }
  Cred.dwVersion= SCHANNEL_CRED_VERSION;
  if (mysql->options.extension)
  {
    Cred.dwMinimumCipherStrength = mysql->options.extension->tls_cipher_strength;
  }

  Cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK | SCH_SEND_ROOT_CERT |
    SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
  if (sctx->client_cert_ctx)
  {
    Cred.cCreds = 1;
    Cred.paCred = &sctx->client_cert_ctx;
  }
  Cred.grbitEnabledProtocols= SP_PROT_TLS1_0|SP_PROT_TLS1_1;
  if (mysql->options.extension && mysql->options.extension->tls_version)
  {
    if (strstr("TLSv1.0", mysql->options.extension->tls_version))
      Cred.grbitEnabledProtocols|= SP_PROT_TLS1_0;
    if (strstr("TLSv1.1", mysql->options.extension->tls_version))
      Cred.grbitEnabledProtocols|= SP_PROT_TLS1_1;
    if (strstr("TLSv1.2", mysql->options.extension->tls_version))
      Cred.grbitEnabledProtocols|= SP_PROT_TLS1_2;
  }

  if ((sRet= AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
                                       NULL, &Cred, NULL, NULL, &sctx->CredHdl, NULL)) != SEC_E_OK)
  {
    ma_schannel_set_sec_error(pvio, sRet);
    goto end;
  }
  sctx->FreeCredHdl= 1;

  if (ma_schannel_client_handshake(ctls) != SEC_E_OK)
    goto end;

  
  if (!ma_schannel_verify_certs(sctx))
    goto end;
 
  return 0;

end:

  if (rc && sctx->IoBufferSize)
    LocalFree(sctx->IoBuffer);
  sctx->IoBufferSize= 0;
  if (sctx->client_cert_ctx)
    CertFreeCertificateContext(sctx->client_cert_ctx);
  sctx->client_cert_ctx= 0;
  return 1;
}

ssize_t ma_tls_read(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  MARIADB_PVIO *pvio= sctx->mysql->net.pvio;
  DWORD dlength= 0;
  SECURITY_STATUS status = ma_schannel_read_decrypt(pvio, &sctx->CredHdl, &sctx->ctxt, &dlength, (uchar *)buffer, (DWORD)length);
  if (status == SEC_I_CONTEXT_EXPIRED)
    return 0; /* other side shut down the connection. */
  if (status == SEC_I_RENEGOTIATE)
    return -1; /* Do not handle renegotiate yet */

  return (status == SEC_E_OK)? (ssize_t)dlength : -1;
}

ssize_t ma_tls_write(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{ 
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  MARIADB_PVIO *pvio= sctx->mysql->net.pvio;
  ssize_t rc, wlength= 0;
  ssize_t remain= length;

  while (remain > 0)
  {
    if ((rc= ma_schannel_write_encrypt(pvio, (uchar *)buffer + wlength, remain)) <= 0)
      return rc;
    wlength+= rc;
    remain-= rc;
  }
  return length;
}

/* {{{ my_bool ma_tls_close(MARIADB_PVIO *pvio) */
my_bool ma_tls_close(MARIADB_TLS *ctls)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl; 
  
  if (sctx)
  {
    if (sctx->IoBufferSize)
      LocalFree(sctx->IoBuffer);
    if (sctx->client_cert_ctx)
      CertFreeCertificateContext(sctx->client_cert_ctx);
    FreeCredentialHandle(&sctx->CredHdl);
    DeleteSecurityContext(&sctx->ctxt);
  }
  LocalFree(sctx);
  return 0;
}
/* }}} */

int ma_tls_verify_server_cert(MARIADB_TLS *ctls)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  MARIADB_PVIO *pvio= ctls->pvio;
  int rc= 1;
  char *szName= NULL;
  char *pszServerName= pvio->mysql->host;
  PCCERT_CONTEXT pServerCert= NULL;

  /* check server name */
  if (pszServerName && (sctx->mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT))
  {
    DWORD NameSize= 0;
    char *p1, *p2;
    SECURITY_STATUS sRet;

    if ((sRet= QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pServerCert)) != SEC_E_OK)
    {
      ma_schannel_set_sec_error(pvio, sRet);
      goto end;
    }

    if (!(NameSize= CertNameToStr(pServerCert->dwCertEncodingType,
      &pServerCert->pCertInfo->Subject,
      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
      NULL, 0)))
    {
      pvio->set_error(sctx->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "SSL connection error:  Can't retrieve name of server certificate");
      goto end;
    }

    if (!(szName= (char *)LocalAlloc(0, NameSize + 1)))
    {
      pvio->set_error(sctx->mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, NULL);
      goto end;
    }

    if (!CertNameToStr(pServerCert->dwCertEncodingType,
      &pServerCert->pCertInfo->Subject,
      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
      szName, NameSize))
    {
      pvio->set_error(sctx->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "SSL connection error: Can't retrieve name of server certificate");
      goto end;
    }
    if ((p1 = strstr(szName, "CN=")))
    {
      p1+= 3;
      if ((p2= strstr(p1, ", ")))
        *p2= 0;
      if (!strcmp(pszServerName, p1))
      {
        rc= 0;
        goto end;
      }
      pvio->set_error(pvio->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN,
                     "SSL connection error: Name of server certificate didn't match");
    }
  }
end:
  if (szName)
    LocalFree(szName);
  if (pServerCert)
    CertFreeCertificateContext(pServerCert);
  return rc;
}

const char *ma_tls_get_cipher(MARIADB_TLS *ctls)
{
  SecPkgContext_ConnectionInfo cinfo;
  SECURITY_STATUS sRet;
  SC_CTX *sctx;
  DWORD i= 0;

  if (!ctls || !ctls->ssl)
    return NULL;

  sctx= (SC_CTX *)ctls->ssl;

  sRet= QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&cinfo);
  if (sRet != SEC_E_OK)
    return NULL;

  while (valid_ciphers[i].cipher)
  {
    if (valid_ciphers[i].aid == cinfo.aiCipher)
      return valid_ciphers[i].cipher;
    i++;
  }
  return NULL;
}

unsigned int ma_tls_get_finger_print(MARIADB_TLS *ctls, char *fp, unsigned int len)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  PCCERT_CONTEXT pRemoteCertContext = NULL;
  if (QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext) != SEC_E_OK)
    return 0;
  CertGetCertificateContextProperty(pRemoteCertContext, CERT_HASH_PROP_ID, fp, (DWORD *)&len);
  CertFreeCertificateContext(pRemoteCertContext);
  return len;
}
