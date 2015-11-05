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

extern my_bool ma_ssl_initialized;

static pthread_mutex_t LOCK_schannel_config;
static pthread_mutex_t *LOCK_crypto= NULL;

struct st_cipher_suite {
  DWORD aid;
  CHAR *cipher;
};

void ma_schannel_set_sec_error(MARIADB_PVIO *pvio, DWORD ErrorNo);
void ma_schannel_set_win_error(MYSQL *mysql);

const struct st_cipher_suite sc_ciphers[]=
{
  {CALG_3DES, "CALG_3DES"},
  {CALG_3DES_112, "CALG_3DES_112"},
  {CALG_AES, "CALG_AES"},
  {CALG_AES_128, "CALG_AES_128"},
  {CALG_AES_192, "CALG_AES_192"},
  {CALG_AES_256, "CALG_AES_256"},
  {CALG_AGREEDKEY_ANY, "CALG_AGREEDKEY_ANY"},
  {CALG_CYLINK_MEK, "CALG_CYLINK_MEK"},
  {CALG_DES, "CALG_DES"},
  {CALG_DESX, "CALG_DESX"},
  {CALG_DH_EPHEM, "CALG_DH_EPHEM"},
  {CALG_DH_SF, "CALG_DH_SF"},
  {CALG_DSS_SIGN, "CALG_DSS_SIGN"},
  {CALG_ECDH, "CALG_ECDH"},
  {CALG_ECDSA, "CALG_ECDSA"},
  {CALG_ECMQV, "CALG_ECMQV"},
  {CALG_HASH_REPLACE_OWF, "CALG_HASH_REPLACE_OWF"},
  {CALG_HUGHES_MD5, "CALG_HUGHES_MD5"},
  {CALG_HMAC, "CALG_HMAC"},
  {CALG_KEA_KEYX, "CALG_KEA_KEYX"},
  {CALG_MAC, "CALG_MAC"},
  {CALG_MD2, "CALG_MD2"},
  {CALG_MD4, "CALG_MD4"},
  {CALG_MD4, "CALG_MD5"},
  {CALG_NO_SIGN, "CALG_NO_SIGN"},
  {CALG_OID_INFO_CNG_ONLY, "CALG_OID_INFO_CNG_ONLY"},
  {CALG_OID_INFO_PARAMETERS, "CALG_OID_INFO_PARAMETERS"},
  {CALG_PCT1_MASTER, "CALG_PCT1_MASTER"},
  {CALG_RC2, "CALG_RC2"},
  {CALG_RC4, "CALG_RC4"},
  {CALG_RC5, "CALG_RC5"},
  {CALG_RSA_KEYX, "CALG_RSA_KEYX"},
  {CALG_RSA_SIGN, "CALG_RSA_SIGN"},
  {CALG_SCHANNEL_MAC_KEY, "CALG_SCHANNEL_MAC_KEY"},
  {CALG_SCHANNEL_MASTER_HASH, "CALG_SCHANNEL_MASTER_HASH"},
  {CALG_SEAL, "CALG_SEAL"},
  {CALG_SHA, "CALG_SHA"},
  {CALG_SHA1, "CALG_SHA1"},
  {CALG_SHA_256, "CALG_SHA_256"},
  {CALG_SHA_384, "CALG_SHA_384"},
  {CALG_SHA_512, "CALG_SHA_512"},
  {CALG_SKIPJACK, "CALG_SKIPJACK"},
  {CALG_SSL2_MASTER, "CALG_SSL2_MASTER"},
  {CALG_SSL3_MASTER, "CALG_SSL3_MASTER"},
  {CALG_SSL3_SHAMD5, "CALG_SSL3_SHAMD5"},
  {CALG_TEK, "CALG_TEK"},
  {CALG_TLS1_MASTER, "CALG_TLS1_MASTER"},
  {CALG_TLS1PRF, "CALG_TLS1PRF"},
  {0, NULL}
};

static int ssl_thread_init()
{
  return 0;
}


/*
  Initializes SSL and allocate global
  context SSL_context

  SYNOPSIS
    ma_ssl_start

  RETURN VALUES
    0  success
    1  error
*/
int ma_ssl_start(char *errmsg, size_t errmsg_len)
{
  if (!ma_ssl_initialized)
  {
    pthread_mutex_init(&LOCK_schannel_config,MY_MUTEX_INIT_FAST);
    pthread_mutex_lock(&LOCK_schannel_config);
    ma_ssl_initialized= TRUE;
    pthread_mutex_unlock(&LOCK_schannel_config);
  }
  return 0;
}

/*
   Release SSL and free resources
   Will be automatically executed by 
   mysql_server_end() function

   SYNOPSIS
     ma_ssl_end()
       void

   RETURN VALUES
     void
*/
void ma_ssl_end()
{
  pthread_mutex_lock(&LOCK_schannel_config);
  if (ma_ssl_initialized)
  {

    ma_ssl_initialized= FALSE;
  }
  pthread_mutex_unlock(&LOCK_schannel_config);
  pthread_mutex_destroy(&LOCK_schannel_config);
  return;
}

/* {{{ static int ma_ssl_set_client_certs(MARIADB_SSL *cssl) */
static int ma_ssl_set_client_certs(MARIADB_SSL *cssl)
{
  MYSQL *mysql= cssl->pvio->mysql;
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key,
       *cafile= mysql->options.ssl_ca;
       
  SC_CTX *sctx= (SC_CTX *)cssl->ssl;
  MARIADB_PVIO *pvio= cssl->pvio;

  if (cafile)
  {
    HCERTSTORE myCS= NULL;

    if (!(sctx->client_ca_ctx = ma_schannel_create_cert_context(pvio, cafile)))
      goto end;

    /* For X509 authentication we need to add ca certificate to local MY store.
       Schannel doesn't provide a callback to send ca to server during handshake */
    if ((myCS= CertOpenStore(CERT_STORE_PROV_SYSTEM,
                             0, //X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                             0,
                             CERT_SYSTEM_STORE_CURRENT_USER,
                             L"CA")))
    {
      CertAddCertificateContextToStore(myCS, sctx->client_ca_ctx, CERT_STORE_ADD_NEWER, NULL);
      CertCloseStore(myCS, 0);
    }
    else {
      ma_schannel_set_win_error(sctx->mysql);
      goto end;
    }
  }

  if (!certfile && keyfile)
    certfile= keyfile;
  if (!keyfile && certfile)
    keyfile= certfile;

  if (certfile && certfile[0])
    if (!(sctx->client_cert_ctx = ma_schannel_create_cert_context(cssl->pvio, certfile)))
      goto end;

  if (sctx->client_cert_ctx && keyfile[0])
    if (!ma_schannel_load_private_key(pvio, sctx->client_cert_ctx, keyfile))
      goto end;
 
  if (mysql->options.extension && mysql->options.extension->ssl_crl)
  {
    if (!(sctx->client_crl_ctx= (CRL_CONTEXT *)ma_schannel_create_crl_context(pvio, mysql->options.extension->ssl_crl)))
      goto end;
  }
  return 0;
  
end:
  if (sctx->client_ca_ctx)
    CertFreeCertificateContext(sctx->client_ca_ctx);
  if (sctx->client_cert_ctx)
    CertFreeCertificateContext(sctx->client_cert_ctx);
  if (sctx->client_crl_ctx)
    CertFreeCRLContext(sctx->client_crl_ctx);
  sctx->client_ca_ctx= sctx->client_cert_ctx= NULL;
  sctx->client_crl_ctx= NULL;
  return 1;
}
/* }}} */

/* {{{ void *ma_ssl_init(MARIADB_SSL *cssl, MYSQL *mysql) */
void *ma_ssl_init(MYSQL *mysql)
{
  SC_CTX *sctx= NULL;

  pthread_mutex_lock(&LOCK_schannel_config);

  if ((sctx= (SC_CTX *)LocalAlloc(0, sizeof(SC_CTX))))
  {
    ZeroMemory(sctx, sizeof(SC_CTX));
    sctx->mysql= mysql;
  }

  pthread_mutex_unlock(&LOCK_schannel_config);
  return sctx;
}
/* }}} */



my_bool ma_ssl_connect(MARIADB_SSL *cssl)
{
  my_bool blocking;
  MYSQL *mysql;
  SCHANNEL_CRED Cred;
  MARIADB_PVIO *pvio;
  my_bool rc= 1;
  SC_CTX *sctx;
  SECURITY_STATUS sRet;
  PCCERT_CONTEXT pRemoteCertContext = NULL,
                 pLocalCertContext= NULL;
  ALG_ID AlgId[2]= {0, 0};
  
  if (!cssl || !cssl->pvio)
    return 1;;
  
  pvio= cssl->pvio;
  sctx= (SC_CTX *)cssl->ssl;

  /* Set socket to blocking if not already set */
  if (!(blocking= pvio->methods->is_blocking(pvio)))
    pvio->methods->blocking(pvio, TRUE, 0);

  mysql= pvio->mysql;
 
  if (ma_ssl_set_client_certs(cssl))
    goto end;

  /* Set cipher */
  if (mysql->options.ssl_cipher)
  {
    DWORD i= 0;
    while (sc_ciphers[i].cipher) {
      if (!strcmp(sc_ciphers[i].cipher, mysql->options.ssl_cipher))
      {
        AlgId[0]= sc_ciphers[i].aid;
        break;
      }
    }
    Cred.palgSupportedAlgs= (ALG_ID *)&AlgId;
  }


  ZeroMemory(&Cred, sizeof(SCHANNEL_CRED));
  Cred.dwVersion= SCHANNEL_CRED_VERSION;
  Cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK | SCH_SEND_ROOT_CERT | 
			SCH_CRED_NO_DEFAULT_CREDS |	SCH_CRED_MANUAL_CRED_VALIDATION;
	if (sctx->client_cert_ctx)
	{
    Cred.cCreds = 1;
    Cred.paCred = &sctx->client_cert_ctx;
  }
  Cred.grbitEnabledProtocols= SP_PROT_TLS1;

  if ((sRet= AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
 									            NULL, &Cred, NULL, NULL, &sctx->CredHdl, NULL)) != SEC_E_OK)
  {
    ma_schannel_set_sec_error(pvio, sRet);
    goto end;
  }
  sctx->FreeCredHdl= 1;

  if (ma_schannel_client_handshake(cssl) != SEC_E_OK)
    goto end;

  sRet= QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext);
  if (sRet != SEC_E_OK)
  {
    ma_schannel_set_sec_error(pvio, sRet);
    goto end;
  }
  
  if (!ma_schannel_verify_certs(sctx, 0))
    goto end;
 
  return 0;

end:
  /* todo: cleanup */
  if (pRemoteCertContext)
    CertFreeCertificateContext(pRemoteCertContext);
  if (rc && sctx->IoBufferSize)
    LocalFree(sctx->IoBuffer);
  sctx->IoBufferSize= 0;
  if (sctx->client_ca_ctx)
    CertFreeCertificateContext(sctx->client_ca_ctx);
  if (sctx->client_cert_ctx)
    CertFreeCertificateContext(sctx->client_cert_ctx);
  if (sctx->client_crl_ctx)
    CertFreeCRLContext(sctx->client_crl_ctx);
  return 1;
}

size_t ma_ssl_read(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{
  SC_CTX *sctx= (SC_CTX *)cssl->ssl;
  MARIADB_PVIO *pvio= sctx->mysql->net.pvio;
  DWORD dlength= -1;

  ma_schannel_read_decrypt(pvio, &sctx->CredHdl, &sctx->ctxt, &dlength, (uchar *)buffer, (DWORD)length);
  return dlength;
}

size_t ma_ssl_write(MARIADB_SSL *cssl, const uchar* buffer, size_t length)
{ 
  SC_CTX *sctx= (SC_CTX *)cssl->ssl;
  MARIADB_PVIO *pvio= sctx->mysql->net.pvio;
  size_t rc, wlength= 0;
  size_t remain= length;

  while (remain)
  {
    if ((rc= ma_schannel_write_encrypt(pvio, (uchar *)buffer + wlength, remain)) <= 0)
      return rc;
    wlength+= rc;
    remain-= rc;
  }
  return length;
}

/* {{{ my_bool ma_ssl_close(MARIADB_PVIO *pvio) */
my_bool ma_ssl_close(MARIADB_SSL *cssl)
{
  SC_CTX *sctx= (SC_CTX *)cssl->ssl; 
  
  if (sctx)
  {
    if (sctx->IoBufferSize)
      LocalFree(sctx->IoBuffer);
    if (sctx->client_ca_ctx)
      CertFreeCertificateContext(sctx->client_ca_ctx);
    if (sctx->client_cert_ctx)
      CertFreeCertificateContext(sctx->client_cert_ctx);
    if (sctx->client_crl_ctx)
      CertFreeCRLContext(sctx->client_crl_ctx);
    FreeCredentialHandle(&sctx->CredHdl);
    DeleteSecurityContext(&sctx->ctxt);
  }
  LocalFree(sctx);
  return 0;
}
/* }}} */

int ma_ssl_verify_server_cert(MARIADB_SSL *cssl)
{
  SC_CTX *sctx= (SC_CTX *)cssl->ssl;
  MARIADB_PVIO *pvio= cssl->pvio;
  int rc= 1;
  char *szName= NULL;
  char *pszServerName= pvio->mysql->host;

  /* check server name */
  if (pszServerName && (sctx->mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT))
  {
    PCCERT_CONTEXT pServerCert;
    DWORD NameSize= 0;
    char *p1, *p2;
    SECURITY_STATUS sRet;

    if ((sRet= QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pServerCert)) != SEC_E_OK)
    {
      ma_schannel_set_sec_error(pvio, sRet);
      return 1;
    }

    if (!(NameSize= CertNameToStr(pServerCert->dwCertEncodingType,
      &pServerCert->pCertInfo->Subject,
      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
      NULL, 0)))
    {
      pvio->set_error(sctx->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Can't retrieve name of server certificate");
      return 1;
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
      pvio->set_error(sctx->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "Can't retrieve name of server certificate");
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
                     "Name of server certificate didn't match");
    }
  }
end:
  if (szName)
    LocalFree(szName);
  return rc;
}

const char *ma_ssl_get_cipher(MARIADB_SSL *cssl)
{
  SecPkgContext_ConnectionInfo cinfo;
  SECURITY_STATUS sRet;
  SC_CTX *sctx;
  DWORD i= 0;

  if (!cssl || !cssl->ssl)
    return NULL;

  sctx= (SC_CTX *)cssl->ssl;

  sRet= QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_CONNECTION_INFO, (PVOID)&cinfo);
  if (sRet != SEC_E_OK)
    return NULL;

  while (sc_ciphers[i].cipher)
  {
    if (sc_ciphers[i].aid == cinfo.aiCipher)
      return sc_ciphers[i].cipher;
    i++;
  }
  return NULL;
}

unsigned int ma_ssl_get_finger_print(MARIADB_SSL *cssl, unsigned char *fp, unsigned int len)
{
  SC_CTX *sctx= (SC_CTX *)cssl->ssl;
  PCCERT_CONTEXT pRemoteCertContext = NULL;
  if (QueryContextAttributes(&sctx->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext) != SEC_E_OK)
    return 0;
  CertGetCertificateContextProperty(pRemoteCertContext, CERT_HASH_PROP_ID, fp, (DWORD *)&len);
  return len;
}
