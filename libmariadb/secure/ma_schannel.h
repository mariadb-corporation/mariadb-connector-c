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

  Author: Georg Richter

 *************************************************************************************/
#ifndef _ma_schannel_h_
#define _ma_schannel_h_

#define SECURITY_WIN32
#include <my_global.h>
#include <my_sys.h>
#include <ma_common.h>
#include <ma_cio.h>
#include <errmsg.h>


typedef void VOID;

#include <wincrypt.h>
#include <wintrust.h>


#include <security.h>

#include <schnlsp.h>
#undef SECURITY_WIN32
#include <Windows.h>
#include <sspi.h>

#define SC_IO_BUFFER_SIZE 0x4000


#ifndef HAVE_SCHANNEL_DEFAULT
#define my_snprintf snprintf
#define my_vsnprintf vsnprintf
#undef SAFE_MUTEX
#endif
#include <my_pthread.h>

struct st_schannel {
  HCERTSTORE cert_store;
  CERT_CONTEXT *client_cert_ctx;
  CERT_CONTEXT *client_ca_ctx;
  CRL_CONTEXT *client_crl_ctx;
  CredHandle CredHdl;
  PUCHAR IoBuffer;
  DWORD IoBufferSize;
/*  PUCHAR EncryptBuffer;
  DWORD EncryptBufferSize;
  DWORD EncryptBufferLength;
  PUCHAR DecryptBuffer;
  DWORD DecryptBufferSize;
  DWORD DecryptBufferLength;
    uchar thumbprint[21]; */
  SecPkgContext_StreamSizes Sizes;

  CtxtHandle ctxt;
  MYSQL *mysql;
};

typedef struct st_schannel SC_CTX;

CERT_CONTEXT *ma_schannel_create_cert_context(MARIADB_CIO *cio, const char *pem_file);
SECURITY_STATUS ma_schannel_handshake_loop(MARIADB_CIO *cio, my_bool InitialRead, SecBuffer *pExtraData);
my_bool ma_schannel_load_private_key(MARIADB_CIO *cio, CERT_CONTEXT *ctx, char *key_file);
PCCRL_CONTEXT ma_schannel_create_crl_context(MARIADB_CIO *cio, const char *pem_file);
my_bool ma_schannel_verify_certs(SC_CTX *sctx, DWORD dwCertFlags);
size_t ma_schannel_write_encrypt(MARIADB_CIO *cio,
                                 uchar *WriteBuffer,
                                 size_t WriteBufferSize);
 size_t ma_schannel_read_decrypt(MARIADB_CIO *cio,
                                 PCredHandle phCreds,
                                 CtxtHandle * phContext,
                                 DWORD *DecryptLength,
                                 uchar *ReadBuffer,
                                 DWORD ReadBufferSize);


#endif /* _ma_schannel_h_ */
