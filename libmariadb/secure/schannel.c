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
#define SCHANNEL_USE_BLACKLISTS 1
#include "ma_schannel.h"
#include "ma_helper.h"
#include "schannel_certs.h"
#include <string.h>

extern my_bool ma_tls_initialized;
char tls_library_version[] = "Schannel";

#define PROT_SSL3 1
#define PROT_TLS1_0 2
#define PROT_TLS1_2 4
#define PROT_TLS1_3 8

ALG_ID all_algorithms[] = {CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA, CALG_SHA1, CALG_MAC,
                           CALG_RSA_SIGN, CALG_DSS_SIGN, CALG_NO_SIGN, CALG_RSA_KEYX,
                           CALG_DES, CALG_3DES_112, CALG_3DES, CALG_DESX, CALG_RC2,
                           CALG_RC4, CALG_SEAL, CALG_DH_SF, CALG_DH_EPHEM, CALG_AGREEDKEY_ANY,
                           CALG_KEA_KEYX, CALG_HUGHES_MD5, CALG_SKIPJACK, CALG_TEK, CALG_CYLINK_MEK,
                           CALG_SSL3_SHAMD5, CALG_SSL3_MASTER, CALG_SCHANNEL_MASTER_HASH,
                           CALG_SCHANNEL_MAC_KEY, CALG_SCHANNEL_ENC_KEY, CALG_PCT1_MASTER,
                           CALG_SSL2_MASTER, CALG_TLS1_MASTER, CALG_RC5, CALG_HMAC, CALG_TLS1PRF,
                           CALG_HASH_REPLACE_OWF, CALG_AES_128, CALG_AES_192, CALG_AES_256, CALG_AES,
                           CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, CALG_ECDH, CALG_ECDH_EPHEM, CALG_ECMQV,
                           CALG_NULLCIPHER, CALG_THIRDPARTY_KEY_EXCHANGE, CALG_THIRDPARTY_SIGNATURE,
                           CALG_THIRDPARTY_CIPHER, CALG_THIRDPARTY_HASH };

typedef enum {
  TLS_AES_128_GCM_SHA256 = 0,
  TLS_AES_256_GCM_SHA384,
  TLS_CHACHA20_POLY1305_SHA256,
#ifdef ENABLE_TLSV13_CCM
  TLS_AES_128_CCM_SHA256,
  TLS_AES_128_CCM_8_SHA256
#endif
  MAX_TLSV13_CIPHERSUITES
} enum_tlsv13_ciphers;

typedef struct {
  enum_tlsv13_ciphers id;
  char* name;
} TLSV13_CIPHERSUITE;

TLSV13_CIPHERSUITE tlsv13_ciphersuites[] = {
  {TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
  {TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
  {TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
#ifdef ENABLE_TLSV13_CCM
  {TLS_AES_128_CCM_SHA256, "TLS_AES_128_CCM_SHA256"},
  {TLS_AES_128_CCM_8_SHA256, "TLS_AES_128_CCM_8_SHA256"}
#endif
};

static struct
{
  DWORD cipher_id;
  DWORD protocol;
  const char *iana_name;
  const char *openssl_name;
  ALG_ID algs[4]; /* exchange, encryption, hash, signature */
}
cipher_map[] =
{
  {
    0x0002,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_RSA_WITH_NULL_SHA", "NULL-SHA",
    { CALG_RSA_KEYX, 0, CALG_SHA1, CALG_RSA_SIGN },
   },
  {
    0x0004,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_RSA_WITH_RC4_128_MD5", "RC4-MD5",
    { CALG_RSA_KEYX, CALG_RC4, CALG_MD5, CALG_RSA_SIGN }
  },
  {
    0x0005,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA",
    { CALG_RSA_KEYX, CALG_RC4, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x000A,
    PROT_SSL3,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA",
    {CALG_RSA_KEYX, CALG_3DES, CALG_SHA1, CALG_DSS_SIGN}
  },
  {
    0x0013,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "EDH-DSS-DES-CBC3-SHA",
    { CALG_DH_EPHEM, CALG_3DES, CALG_SHA1, CALG_DSS_SIGN }
  },
  {
    0x002F,
    PROT_SSL3 | PROT_TLS1_0 | PROT_TLS1_2,
    "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA",
    { CALG_RSA_KEYX, CALG_AES_128, CALG_SHA, CALG_RSA_SIGN}
  },
  {
    0x0032,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE-DSS-AES128-SHA",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0033,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0035,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA",
    { CALG_RSA_KEYX, CALG_AES_256, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0038,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE-DSS-AES256-SHA",
    { CALG_DH_EPHEM, CALG_AES_256, CALG_SHA1, CALG_DSS_SIGN }
  },
  {
    0x0039,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA",
    { CALG_DH_EPHEM, CALG_AES_256, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x003B,
    PROT_TLS1_2,
    "TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256",
    { CALG_RSA_KEYX, 0, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x003C,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256",
    { CALG_RSA_KEYX, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x003D,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256",
    { CALG_RSA_KEYX, CALG_AES_256, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x0040,
    PROT_TLS1_2,
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS-AES128-SHA256",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA_256, CALG_DSS_SIGN }
  },
  {
    0x009C,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256",
    { CALG_RSA_KEYX, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x009D,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384",
    { CALG_RSA_KEYX, CALG_AES_256, CALG_SHA_384, CALG_RSA_SIGN }
  },
  {
    0x009E,
    PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x009F,
    PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384",
    { CALG_DH_EPHEM, CALG_AES_256, CALG_SHA_384, CALG_RSA_SIGN }
  },
  {
    0xC027,
    PROT_TLS1_2,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256",
    { CALG_ECDH, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0xC028,
    PROT_TLS1_2,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384",
    { CALG_ECDH, CALG_AES_256, CALG_SHA_384, CALG_RSA_SIGN }
  }
};

#define MAX_ALG_ID 50

extern void ma_schannel_set_sec_error(MARIADB_PVIO *pvio, DWORD ErrorNo);

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
static int ma_tls_set_client_certs(MARIADB_TLS *ctls,const CERT_CONTEXT **cert_ctx)
{
  MYSQL *mysql= ctls->pvio->mysql;
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key;
  MARIADB_PVIO *pvio= ctls->pvio;
  char errmsg[256];

  if (!certfile && keyfile)
    certfile= keyfile;
  if (!keyfile && certfile)
    keyfile= certfile;

  if (!certfile)
    return 0;

  *cert_ctx = schannel_create_cert_context(certfile, keyfile, errmsg, sizeof(errmsg));
  if (!*cert_ctx)
  {
    pvio->set_error(pvio->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0, errmsg);
    return 1;
  }

  return 0;
}
/* }}} */

/* {{{ void *ma_tls_init(MARIADB_TLS *ctls, MYSQL *mysql) */
void *ma_tls_init(MYSQL *mysql)
{
  SC_CTX *sctx = (SC_CTX *)LocalAlloc(LMEM_ZEROINIT, sizeof(SC_CTX));
  if (sctx)
  {
    SecInvalidateHandle(&sctx->CredHdl);
    SecInvalidateHandle(&sctx->hCtxt);
  }
  return sctx;
}
/* }}} */


/* 
  Maps between openssl suite names and schannel alg_ids.
  Every suite has 4 algorithms (for exchange, encryption, hash and signing).
  
  The input string is a set of suite names (openssl),  separated 
  by ':'
  
  The output is written into the array 'arr' of size 'arr_size'
  The function returns number of elements written to the 'arr'.
*/

static struct _tls_version {
  const char *tls_version;
  DWORD protocol;
} tls_version[]= {
    {"TLSv1.0", PROT_TLS1_0},
    {"TLSv1.2", PROT_TLS1_2},
    {"TLSv1.3", PROT_TLS1_3},
    {"SSLv3",   PROT_SSL3}
};

/* The following list was produced with OpenSSL 1.1.1j
   by executing `openssl ciphers -V`.  */
static struct {
  DWORD dwCipherSuite;
  const char *openssl_name;
} openssl_ciphers[] = {
  {0x002F, "AES128-SHA"},
  {0x0033, "DHE-RSA-AES128-SHA"},
  {0x0035, "AES256-SHA"},
  {0x0039, "DHE-RSA-AES256-SHA"},
  {0x003C, "AES128-SHA256"},
  {0x003D, "AES256-SHA256"},
  {0x0067, "DHE-RSA-AES128-SHA256"},
  {0x006B, "DHE-RSA-AES256-SHA256"},
  {0x008C, "PSK-AES128-CBC-SHA"},
  {0x008D, "PSK-AES256-CBC-SHA"},
  {0x0090, "DHE-PSK-AES128-CBC-SHA"},
  {0x0091, "DHE-PSK-AES256-CBC-SHA"},
  {0x0094, "RSA-PSK-AES128-CBC-SHA"},
  {0x0095, "RSA-PSK-AES256-CBC-SHA"},
  {0x009C, "AES128-GCM-SHA256"},
  {0x009D, "AES256-GCM-SHA384"},
  {0x009E, "DHE-RSA-AES128-GCM-SHA256"},
  {0x009F, "DHE-RSA-AES256-GCM-SHA384"},
  {0x00A8, "PSK-AES128-GCM-SHA256"},
  {0x00A9, "PSK-AES256-GCM-SHA384"},
  {0x00AA, "DHE-PSK-AES128-GCM-SHA256"},
  {0x00AB, "DHE-PSK-AES256-GCM-SHA384"},
  {0x00AC, "RSA-PSK-AES128-GCM-SHA256"},
  {0x00AD, "RSA-PSK-AES256-GCM-SHA384"},
  {0x00AE, "PSK-AES128-CBC-SHA256"},
  {0x00AF, "PSK-AES256-CBC-SHA384"},
  {0x00B2, "DHE-PSK-AES128-CBC-SHA256"},
  {0x00B3, "DHE-PSK-AES256-CBC-SHA384"},
  {0x00B6, "RSA-PSK-AES128-CBC-SHA256"},
  {0x00B7, "RSA-PSK-AES256-CBC-SHA384"},
  {0x1301, "TLS_AES_128_GCM_SHA256"},
  {0x1302, "TLS_AES_256_GCM_SHA384"},
  {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
  {0xC009, "ECDHE-ECDSA-AES128-SHA"},
  {0xC00A, "ECDHE-ECDSA-AES256-SHA"},
  {0xC013, "ECDHE-RSA-AES128-SHA"},
  {0xC014, "ECDHE-RSA-AES256-SHA"},
  {0xC01D, "SRP-AES-128-CBC-SHA"},
  {0xC01E, "SRP-RSA-AES-128-CBC-SHA"},
  {0xC020, "SRP-AES-256-CBC-SHA"},
  {0xC021, "SRP-RSA-AES-256-CBC-SHA"},
  {0xC023, "ECDHE-ECDSA-AES128-SHA256"},
  {0xC024, "ECDHE-ECDSA-AES256-SHA384"},
  {0xC027, "ECDHE-RSA-AES128-SHA256"},
  {0xC028, "ECDHE-RSA-AES256-SHA384"},
  {0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
  {0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"},
  {0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
  {0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
  {0xC035, "ECDHE-PSK-AES128-CBC-SHA"},
  {0xC036, "ECDHE-PSK-AES256-CBC-SHA"},
  {0xC037, "ECDHE-PSK-AES128-CBC-SHA256"},
  {0xC038, "ECDHE-PSK-AES256-CBC-SHA384"},
  {0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305"},
  {0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305"},
  {0xCCAA, "DHE-RSA-CHACHA20-POLY1305"},
  {0xCCAB, "PSK-CHACHA20-POLY1305"},
  {0xCCAC, "ECDHE-PSK-CHACHA20-POLY1305"},
  {0xCCAD, "DHE-PSK-CHACHA20-POLY1305"},
  {0xCCAE, "RSA-PSK-CHACHA20-POLY1305"}
};

static size_t set_cipher(char * cipher_str, DWORD protocol, ALG_ID *arr , size_t arr_size)
{
  char *token = strtok(cipher_str, ":");
  size_t pos = 0;

  while (token)
  {
    size_t i;

    for(i = 0; i < sizeof(cipher_map)/sizeof(cipher_map[0]) ; i++)
    {
      if((pos + 4 < arr_size && strcmp(cipher_map[i].openssl_name, token) == 0) ||
        (cipher_map[i].protocol <= protocol))
      {
        memcpy(arr + pos, cipher_map[i].algs, sizeof(ALG_ID)* 4);
        pos += 4;
        break;
      }
    }
    token = strtok(NULL, ":");
  }
  return pos;
}

#define DISABLE_BLOCK_CIPHER(a,cipher)\
{\
  (a).Length = (a).MaximumLength= sizeof((cipher));\
  (a).Buffer = (PWSTR)(cipher);\
}

#define DISABLE_ALGORITHM(a, usage, cipher)\
{\
  (a).eAlgorithmUsage = (usage);\
  (a).strCngAlgId.Length = (a).strCngAlgId.MaximumLength = sizeof((cipher));\
  (a).strCngAlgId.Buffer = (PWSTR)(cipher);\
}

my_bool ma_tls_connect(MARIADB_TLS* ctls)
{
  MYSQL* mysql;
  MARIADB_PVIO* pvio;
  my_bool rc = 1;
  SC_CTX* sctx;
  SECURITY_STATUS sRet;
  ALG_ID AlgId[MAX_ALG_ID];
  size_t i;
  DWORD protocol = 0;
  DWORD flags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
  DWORD Enabled_Protocols = 0;
  int verify_certs;
  const CERT_CONTEXT* cert_context = NULL;
  SCHANNEL_CRED Cred = { 0 };

  SCH_CREDENTIALS Sch_Cred = { 0 };

  if (!ctls)
    return 1;

  pvio = ctls->pvio;
  sctx = (SC_CTX*)ctls->ssl;
  if (!pvio || !sctx)
    return 1;

  mysql = pvio->mysql;
  if (!mysql)
    return 1;

  if (ma_tls_set_client_certs(ctls, &cert_context))
    goto end;

  if (mysql->options.extension && mysql->options.extension->tls_version)
  {
    if (strstr(mysql->options.extension->tls_version, "TLSv1.0"))
      Enabled_Protocols |= SP_PROT_TLS1_0_CLIENT;
    if (strstr(mysql->options.extension->tls_version, "TLSv1.1"))
      Enabled_Protocols |= SP_PROT_TLS1_1_CLIENT;
    if (strstr(mysql->options.extension->tls_version, "TLSv1.2"))
      Enabled_Protocols |= SP_PROT_TLS1_2_CLIENT;

    /* TLS v1.3 available since build 20348 */
    if (ma_check_windows_version(VERSION_GREATER_OR_EQUAL, 10, 0, 20348))
      if (strstr(mysql->options.extension->tls_version, "TLSv1.3"))
        Enabled_Protocols |= SP_PROT_TLS1_3_CLIENT;
  }
  if (!Enabled_Protocols)
  {
    Enabled_Protocols = SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT |
      SP_PROT_TLS1_2_CLIENT;
    if (ma_check_windows_version(VERSION_GREATER_OR_EQUAL, 10, 0, 20348))
      Enabled_Protocols |= SP_PROT_TLS1_3_CLIENT;
  }

  /* Since Version 10.1809 SCHANNEL_CRED became deprecated, we have
     to use SCH_CREDENTIALS instead.
     1809 is build number 17763 */

  if (ma_check_windows_version(VERSION_LESS, 10, 0, 17763))
  {

    /* Set cipher */
    if (mysql->options.ssl_cipher)
    {

      /* check if a protocol was specified as a cipher:
        * In this case don't allow cipher suites which belong to newer protocols
        * Please note: There are no cipher suites for TLS1.1
        */
      for (i = 0; i < sizeof(tls_version) / sizeof(tls_version[0]); i++)
      {
        if (!_stricmp(mysql->options.ssl_cipher, tls_version[i].tls_version))
          protocol |= tls_version[i].protocol;
      }
      memset(AlgId, 0, sizeof(AlgId));
      Cred.cSupportedAlgs = (DWORD)set_cipher(mysql->options.ssl_cipher, protocol, AlgId, MAX_ALG_ID);
      if (Cred.cSupportedAlgs)
      {
        Cred.palgSupportedAlgs = AlgId;
      }
      else if (!protocol)
      {
        ma_schannel_set_sec_error(pvio, SEC_E_ALGORITHM_MISMATCH);
        goto end;
      }
    }

    Cred.dwVersion = SCHANNEL_CRED_VERSION;

    Cred.dwFlags = flags;

    Cred.grbitEnabledProtocols = Enabled_Protocols;


    if (cert_context)
    {
      Cred.cCreds = 1;
      Cred.paCred = &cert_context;
    }
    sRet = AcquireCredentialsHandleA(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
      NULL, &Cred, NULL, NULL, &sctx->CredHdl, NULL);
  }
  else {
    TLS_PARAMETERS tls_params = { 0 };
    CRYPTO_SETTINGS c_settings[3] = { 0 };
    uint8 c_cnt = 0;
    UNICODE_STRING blockcipher_disable[2];
    uint8 bcd_cnt = 0;
    my_bool disabled_algs[MAX_TLSV13_CIPHERSUITES];

    tls_params.grbitDisabledProtocols =  (DWORD)~Enabled_Protocols;
    Sch_Cred.cTlsParameters = 1;
    Sch_Cred.pTlsParameters = &tls_params;
    tls_params.pDisabledCrypto = c_settings;
    tls_params.cDisabledCrypto = 0;

    memset(&disabled_algs, 0, sizeof(my_bool) * MAX_TLSV13_CIPHERSUITES);

    if (mysql->options.ssl_cipher)
    {
      for (i = 0; i < MAX_TLSV13_CIPHERSUITES; i++)
      {
        if (!strcmp(tlsv13_ciphersuites[i].name, mysql->options.ssl_cipher))
        {
          memset(&disabled_algs, 1, sizeof(my_bool) * MAX_TLSV13_CIPHERSUITES);
          disabled_algs[tlsv13_ciphersuites[i].id] = 0;
          break;
        }
      }
    }

    /* GCM block cipher */
    if (disabled_algs[TLS_AES_128_GCM_SHA256] || disabled_algs[TLS_AES_256_GCM_SHA384])
    {
      if (disabled_algs[TLS_AES_128_GCM_SHA256] && disabled_algs[TLS_AES_256_GCM_SHA384])
      {
        DISABLE_BLOCK_CIPHER(blockcipher_disable[bcd_cnt], BCRYPT_CHAIN_MODE_GCM);
        c_settings[c_cnt].rgstrChainingModes = &blockcipher_disable[bcd_cnt];
        c_settings[c_cnt].cChainingModes = 1;
        bcd_cnt++;
        DISABLE_ALGORITHM(c_settings[c_cnt], TlsParametersCngAlgUsageCipher, BCRYPT_AES_ALGORITHM);
      }
      else {
        PWSTR alg = disabled_algs[TLS_AES_128_GCM_SHA256] ? (PWSTR)BCRYPT_SHA256_ALGORITHM : (PWSTR)BCRYPT_SHA384_ALGORITHM;
        DISABLE_ALGORITHM(c_settings[c_cnt], TlsParametersCngAlgUsageCipher, alg);
      }
      c_cnt++;
    }

#ifdef ENABLE_TLSV13_CCM
    /* CCM block cipher */
    if (disabled_algs[TLS_AES_128_CCM_SHA256] || disabled_algs[TLS_AES_128_CCM_8_SHA256])
    {
      DISABLE_BLOCK_CIPHER(blockcipher_disable[bcd_cnt], BCRYPT_CHAIN_MODE_CCM);
      c_settings[c_cnt].rgstrChainingModes = &blockcipher_disable[bcd_cnt];
      c_settings[c_cnt].cChainingModes = 1;
      bcd_cnt++;
      DISABLE_ALGORITHM(c_settings[c_cnt], TlsParametersCngAlgUsageCipher, BCRYPT_AES_ALGORITHM);
      /* if (disabled_algs[TLS_AES_128_CCM_SHA256] != disabled_algs[TLS_AES_128_CCM_8_SHA256])
      {
        if (disabled_algs[TLS_AES_128_CCM_SHA256])
          c_settings[c_cnt].dwMaxBitLength = 64;
        else
          c_settings[c_cnt].dwMinBitLength = 128;
      } */
      c_cnt++;
    }
#endif

    /* CHACHA20 */
    if (disabled_algs[TLS_CHACHA20_POLY1305_SHA256])
    {
      DISABLE_ALGORITHM(c_settings[c_cnt], TlsParametersCngAlgUsageCipher, BCRYPT_CHACHA20_POLY1305_ALGORITHM);
      c_cnt++;
    }
    
    if (c_cnt)
    {
      tls_params.cDisabledCrypto = c_cnt;
    }

    Sch_Cred.dwVersion = SCH_CREDENTIALS_VERSION;
    Sch_Cred.dwFlags = flags | SCH_USE_STRONG_CRYPTO;
        

    if (cert_context)
    {
      Sch_Cred.cCreds= 1;
      Sch_Cred.paCred= &cert_context;
    }

    sRet = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
      NULL, &Sch_Cred, NULL, NULL, &sctx->CredHdl, NULL);
  }
  if (sRet)
  {
    ma_schannel_set_sec_error(pvio, sRet);
    goto end;
  }
  if (ma_schannel_client_handshake(ctls) != SEC_E_OK)
    goto end;

   verify_certs =  mysql->options.ssl_ca || mysql->options.ssl_capath ||
     (mysql->options.extension->tls_verify_server_cert);

  if (verify_certs)
  {
    if (!ma_schannel_verify_certs(ctls, mysql->options.extension->tls_verify_server_cert))
      goto end;
  }

  rc = 0;

end:
  if (cert_context)
    schannel_free_cert_context(cert_context);
  return rc;
}

ssize_t ma_tls_read(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  MARIADB_PVIO *pvio= ctls->pvio;
  DWORD dlength= 0;
  SECURITY_STATUS status = ma_schannel_read_decrypt(pvio, &sctx->hCtxt, &dlength, (uchar *)buffer, (DWORD)length);
  if (status == SEC_I_CONTEXT_EXPIRED)
    return 0; /* other side shut down the connection. */
  if (status == SEC_I_RENEGOTIATE)
    return -1; /* Do not handle renegotiate yet */

  return (status == SEC_E_OK)? (ssize_t)dlength : -1;
}

ssize_t ma_tls_write(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{ 
  MARIADB_PVIO *pvio= ctls->pvio;
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
    LocalFree(sctx->IoBuffer);

    if (SecIsValidHandle(&sctx->CredHdl))
      FreeCredentialHandle(&sctx->CredHdl);

    if (SecIsValidHandle(&sctx->hCtxt))
      DeleteSecurityContext(&sctx->hCtxt);
  }
  LocalFree(sctx);
  return 0;
}
/* }}} */

int ma_tls_verify_server_cert(MARIADB_TLS *ctls)
{
  /* Done elsewhere */
  return 0;
}

static const char *cipher_name(const SecPkgContext_CipherInfo *CipherInfo)
{
  size_t i;

  for(i = 0; i < sizeof(openssl_ciphers)/sizeof(openssl_ciphers[0]) ; i++)
  {
    if (CipherInfo->dwCipherSuite == openssl_ciphers[i].dwCipherSuite)
      return openssl_ciphers[i].openssl_name;
  }
  return "";
};

const char *ma_tls_get_cipher(MARIADB_TLS *ctls)
{
  SecPkgContext_CipherInfo CipherInfo = { SECPKGCONTEXT_CIPHERINFO_V1 };
  SECURITY_STATUS sRet;
  SC_CTX *sctx;

  if (!ctls || !ctls->ssl)
    return NULL;

  sctx= (SC_CTX *)ctls->ssl;
  sRet= QueryContextAttributesA(&sctx->hCtxt, SECPKG_ATTR_CIPHER_INFO, (PVOID)&CipherInfo);

  if (sRet != SEC_E_OK)
    return NULL;

  return cipher_name(&CipherInfo);
}

unsigned int ma_tls_get_finger_print(MARIADB_TLS *ctls, char *fp, unsigned int len)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  PCCERT_CONTEXT pRemoteCertContext = NULL;
  if (QueryContextAttributesA(&sctx->hCtxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext) != SEC_E_OK)
    return 0;
  CertGetCertificateContextProperty(pRemoteCertContext, CERT_HASH_PROP_ID, fp, (DWORD *)&len);
  CertFreeCertificateContext(pRemoteCertContext);
  return len;
}

void ma_tls_set_connection(MYSQL *mysql __attribute__((unused)))
{
  return;
}
