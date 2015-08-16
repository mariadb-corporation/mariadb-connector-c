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
#include "ma_schannel.h"

#define SC_IO_BUFFER_SIZE 0x4000

/* {{{ LPBYTE ma_schannel_load_pem(const char *PemFileName, DWORD *buffer_len) */
/*
   Load a pem or clr file and convert it to a binary DER object

   SYNOPSIS
     ma_schannel_load_pem()
     PemFileName           name of the pem file (in)
     buffer_len            length of the converted DER binary

   DESCRIPTION
     Loads a X509 file (ca, certification, key or clr) into memory and converts
     it to a DER binary object. This object can be decoded and loaded into
     a schannel crypto context.
     If the function failed, error can be retrieved by GetLastError()
     The returned binary object must be freed by caller.

   RETURN VALUE
     NULL                  if the conversion failed or file was not found
     LPBYTE *              a pointer to a binary der object
                           buffer_len will contain the length of binary der object
*/
static LPBYTE ma_schannel_load_pem(const char *PemFileName, DWORD *buffer_len)
{
  HANDLE hfile;
  char   *buffer= NULL;
  DWORD dwBytesRead= 0;
  LPBYTE der_buffer= NULL;
  DWORD der_buffer_length;
  DWORD x;

  if (buffer_len == NULL)
    return NULL;

  
  if ((hfile= CreateFile(PemFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 
                          FILE_ATTRIBUTE_NORMAL, NULL )) == INVALID_HANDLE_VALUE)
    return NULL;

  if (!(*buffer_len = GetFileSize(hfile, NULL)))
     goto end;

  if (!(buffer= LocalAlloc(0, *buffer_len + 1)))
    goto end;

  if (!ReadFile(hfile, buffer, *buffer_len, &dwBytesRead, NULL))
    goto end;

  CloseHandle(hfile);

  /* calculate the length of DER binary */
  if (!CryptStringToBinaryA(buffer, *buffer_len, CRYPT_STRING_BASE64HEADER,
                            NULL, &der_buffer_length, NULL, NULL))
    goto end;
  /* allocate DER binary buffer */
  if (!(der_buffer= (LPBYTE)LocalAlloc(0, der_buffer_length)))
    goto end;
  /* convert to DER binary */
  if (!CryptStringToBinaryA(buffer, *buffer_len, CRYPT_STRING_BASE64HEADER,
                            der_buffer, &der_buffer_length, NULL, NULL))
    goto end;

  *buffer_len= der_buffer_length;
  LocalFree(buffer);
  
  return der_buffer;

end:
  if (hfile != INVALID_HANDLE_VALUE)
    CloseHandle(hfile);
  if (buffer)
    LocalFree(buffer);
  if (der_buffer)
    LocalFree(der_buffer);
  *buffer_len= 0;
  return NULL;
}
/* }}} */

/* {{{ CERT_CONTEXT *ma_schannel_create_cert_context(const char *pem_file) */
/*
  Create a certification context from ca or cert file

  SYNOPSIS
    ma_schannel_create_cert_context()
    pem_file               name of certificate or ca file

  DESCRIPTION
    Loads a PEM file (certificate authority or certificate) creates a certification
    context and loads the binary representation into context.
    The returned context must be freed by caller.
    If the function failed, error can be retrieved by GetLastError().

  RETURNS
    NULL                   If loading of the file or creating context failed
    CERT_CONTEXT *         A pointer to a certification context structure
*/
CERT_CONTEXT *ma_schannel_create_cert_context(const char *pem_file)
{
  DWORD der_buffer_length;
  LPBYTE der_buffer= NULL;

  CERT_CONTEXT *ctx= NULL;

  /* create DER binary object from ca/certification file */
  if (!(der_buffer= ma_schannel_load_pem(pem_file, (DWORD *)&der_buffer_length)))
    goto end;
  ctx= CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    der_buffer, der_buffer_length);
end:
  if (der_buffer)
    LocalFree(der_buffer);
  return ctx;
}
/* }}} */

/* {{{ PCCRL_CONTEXT ma_schannel_create_crl_context(const char *pem_file) */
/*
  Create a crl context from crlfile

  SYNOPSIS
    ma_schannel_create_crl_context()
    pem_file               name of certificate or ca file

  DESCRIPTION
    Loads a certification revocation list file, creates a certification
    context and loads the binary representation into crl context.
    The returned context must be freed by caller.
    If the function failed, error can be retrieved by GetLastError().

  RETURNS
    NULL                   If loading of the file or creating context failed
    PCCRL_CONTEXT          A pointer to a certification context structure
*/
PCCRL_CONTEXT ma_schannel_create_crl_context(const char *pem_file)
{
  DWORD der_buffer_length;
  LPBYTE der_buffer= NULL;

  PCCRL_CONTEXT ctx= NULL;

  /* load ca pem file into memory */
  if (!(der_buffer= ma_schannel_load_pem(pem_file, (DWORD *)&der_buffer_length)))
    goto end;
  ctx= CertCreateCRLContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    der_buffer, der_buffer_length);
end:
  if (der_buffer)
    LocalFree(der_buffer);
  return ctx;
}
/* }}} */

/* {{{ my_bool ma_schannel_load_private_key(CERT_CONTEXT *ctx, char *key_file) */
/*
  Load privte key into context

  SYNOPSIS
    ma_schannel_load_private_key()
    ctx                    pointer to a certification context
    pem_file               name of certificate or ca file

  DESCRIPTION
    Loads a certification revocation list file, creates a certification
    context and loads the binary representation into crl context.
    The returned context must be freed by caller.
    If the function failed, error can be retrieved by GetLastError().

  RETURNS
    NULL                   If loading of the file or creating context failed
    PCCRL_CONTEXT          A pointer to a certification context structure
*/

my_bool ma_schannel_load_private_key(CERT_CONTEXT *ctx, char *key_file)
{
   DWORD der_buffer_len= 0;
   LPBYTE der_buffer= NULL;
   DWORD priv_key_len= 0;
   LPBYTE priv_key= NULL;
   HCRYPTPROV  crypt_prov= NULL;
   HCRYPTKEY  crypt_key= NULL;
   CRYPT_KEY_PROV_INFO kpi;
   my_bool rc= 0;

   /* load private key into der binary object */
   if (!(der_buffer= ma_schannel_load_pem(key_file, &der_buffer_len)))
     return 0;

   /* determine required buffer size for decoded private key */
   if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS_RSA_PRIVATE_KEY,
                            der_buffer, der_buffer_len,
                            0, NULL,
                            NULL, &priv_key_len))
     goto end;

   /* allocate buffer for decoded private key */
   if (!(priv_key= LocalAlloc(0, priv_key_len)))
     goto end;

   /* decode */
   if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                            PKCS_RSA_PRIVATE_KEY,
                            der_buffer, der_buffer_len,
                            0, NULL,
                            priv_key, &priv_key_len))
     goto end;

   /* Acquire context */
   if (!CryptAcquireContext(&crypt_prov, "cio_schannel", MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
     goto end;

   /* ... and import the private key */
   if (!CryptImportKey(crypt_prov, priv_key, priv_key_len, NULL, 0, &crypt_key))
     goto end;

   SecureZeroMemory(&kpi, sizeof(kpi));
   kpi.pwszContainerName = "cio-schanel";
   kpi.dwKeySpec = AT_KEYEXCHANGE;
   kpi.dwFlags = CRYPT_MACHINE_KEYSET;

   /* assign private key to certificate context */
   if (CertSetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi))
     rc= 1;
end:
  if (der_buffer)
    LocalFree(der_buffer);
  if (priv_key)
  {
    if (crypt_key)
      CryptDestroyKey(crypt_key);
    LocalFree(priv_key);
  if (!rc)
    if (crypt_prov)
      CryptReleaseContext(crypt_prov, 0);
  }
  return rc;
}
/* }}} */

/* {{{ SECURITY_STATUS ma_schannel_handshake_loop(MARIADB_CIO *cio, my_bool InitialRead, SecBuffer *pExtraData) */
/*
  perform handshake loop

  SYNOPSIS
    ma_schannel_handshake_loop()
    cio            Pointer to an Communication/IO structure
    InitialRead    TRUE if it's the very first read
    ExtraData      Pointer to an SecBuffer which contains extra data (sent by application)

    
*/

SECURITY_STATUS ma_schannel_handshake_loop(MARIADB_CIO *cio, my_bool InitialRead, SecBuffer *pExtraData)
{
  SecBufferDesc   OutBuffer, InBuffer;
  SecBuffer       InBuffers[2], OutBuffers[1];
  DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData, cbIoBuffer;
  TimeStamp       tsExpiry;
  SECURITY_STATUS rc;
  PUCHAR          IoBuffer;
  BOOL            fDoRead;
  MARIADB_SSL     *cssl= cio->cssl;
  SC_CTX          *sctx= (SC_CTX *)cssl->data;


  dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
                ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY |
                ISC_RET_EXTENDED_ERROR |
                ISC_REQ_ALLOCATE_MEMORY | 
                ISC_REQ_STREAM;


  /* Allocate data buffer */
  if (!(IoBuffer = LocalAlloc(LMEM_FIXED, SC_IO_BUFFER_SIZE)))
    return SEC_E_INSUFFICIENT_MEMORY;

  cbIoBuffer = 0;
  fDoRead = InitialRead;

  /* handshake loop: We will leave a handshake is finished
     or an error occurs */

  rc = SEC_I_CONTINUE_NEEDED;

  while (rc == SEC_I_CONTINUE_NEEDED ||
         rc == SEC_E_INCOMPLETE_MESSAGE ||
         rc == SEC_I_INCOMPLETE_CREDENTIALS )
  {
    /* Read data */
    if (rc == SEC_E_INCOMPLETE_MESSAGE ||
        !cbIoBuffer)
    {
      if(fDoRead)
      {
        cbData = cio->methods->read(cio, IoBuffer + cbIoBuffer, SC_IO_BUFFER_SIZE - cbIoBuffer, 0);
        if (cbData == SOCKET_ERROR || cbData == 0)
        {
          rc = SEC_E_INTERNAL_ERROR;
          break;
        }
        cbIoBuffer += cbData;
      }
      else
        fDoRead = TRUE;
    }

    /* input buffers
       First buffer stores data received from server. leftover data
       will be stored in second buffer with BufferType SECBUFFER_EXTRA */

    InBuffers[0].pvBuffer   = IoBuffer;
    InBuffers[0].cbBuffer   = cbIoBuffer;
    InBuffers[0].BufferType = SECBUFFER_TOKEN;

    InBuffers[1].pvBuffer   = NULL;
    InBuffers[1].cbBuffer   = 0;
    InBuffers[1].BufferType = SECBUFFER_EMPTY;

    InBuffer.cBuffers       = 2;
    InBuffer.pBuffers       = InBuffers;
    InBuffer.ulVersion      = SECBUFFER_VERSION;


    /* output buffer */
    OutBuffers[0].pvBuffer  = NULL;
    OutBuffers[0].BufferType= SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer  = 0;

    OutBuffer.cBuffers      = 1;
    OutBuffer.pBuffers      = OutBuffers;
    OutBuffer.ulVersion     = SECBUFFER_VERSION;


    rc = InitializeSecurityContextA(&sctx->CredHdl,
                                    &sctx->ctxt,
                                    NULL,
                                    dwSSPIFlags,
                                    0,
                                    SECURITY_NATIVE_DREP,
                                    &InBuffer,
                                    0,
                                    NULL,
                                    &OutBuffer,
                                    &dwSSPIOutFlags,
                                    &tsExpiry );


    if (rc == SEC_E_OK  ||
        rc == SEC_I_CONTINUE_NEEDED ||
        FAILED(rc) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
    {
      if(OutBuffers[0].cbBuffer && OutBuffers[0].pvBuffer)
      {
        cbData= cio->methods->write(cio, (uchar *)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
          FreeContextBuffer(OutBuffers[0].pvBuffer);
          DeleteSecurityContext(&sctx->ctxt);
          return SEC_E_INTERNAL_ERROR;
        }

        /* Free output context buffer */
        FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
      }
    }

    /* check if we need to read more data */
    switch (rc) {
    case SEC_E_INCOMPLETE_MESSAGE:
      /* we didn't receive all data, so just continue loop */
      continue;
      break;
    case SEC_E_OK:
      /* handshake completed, but we need to check if extra
         data was sent (which contains encrypted application data) */
      if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
      {
        if (!(pExtraData->pvBuffer= LocalAlloc(0, InBuffers[1].cbBuffer)))
          return SEC_E_INSUFFICIENT_MEMORY;
        
        MoveMemory(pExtraData->pvBuffer, IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer );
        pExtraData->BufferType = SECBUFFER_TOKEN;
        pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
      }
      else
      {
        pExtraData->BufferType= SECBUFFER_EMPTY;
        pExtraData->pvBuffer= NULL;
        pExtraData->cbBuffer= 0;
      }
    break;
    case SEC_I_INCOMPLETE_CREDENTIALS:
      /* Provided credentials didn't contain a valid client certificate.
         We will try to connect anonymously, using current credentials */
      fDoRead= FALSE;
      rc= SEC_I_CONTINUE_NEEDED;
      continue;
      break;
    default:
      if (FAILED(rc))
        goto loopend;
      break;
    }

    if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
    {
      MoveMemory( IoBuffer, IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer );
      cbIoBuffer = InBuffers[1].cbBuffer;
    }

    cbIoBuffer = 0;
  }
loopend:
  if (FAILED(rc)) 
    DeleteSecurityContext(&sctx->ctxt);
  LocalFree(IoBuffer);

  return rc;
}
/* }}} */

/* {{{ SECURITY_STATUS ma_schannel_client_handshake(MARIADB_SSL *cssl) */
/*
   performs client side handshake 

   SYNOPSIS
     ma_schannel_client_handshake()
     cssl             Pointer to a MARIADB_SSL structure

   DESCRIPTION
     initiates a client/server handshake. This function can be used
     by clients only

   RETURN
     SEC_E_OK         on success
*/

SECURITY_STATUS ma_schannel_client_handshake(MARIADB_SSL *cssl)
{
  MARIADB_CIO *cio;
  SECURITY_STATUS sRet;
  DWORD OutFlags;
  DWORD r;
  SC_CTX *sctx;
  SecBuffer ExtraData;
  DWORD SFlags= ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | 
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
  
  SecBufferDesc	BufferIn, BufferOut;
  SecBuffer  BuffersOut[1], BuffersIn[2];

  if (!cssl || !cssl->cio || !cssl->data)
    return 1;

  cio= cssl->cio;
  sctx= (SC_CTX *)cssl->data;

  /* Initialie securifty context */
  BuffersOut[0].BufferType= SECBUFFER_TOKEN;
  BuffersOut[0].cbBuffer= 0;
  BuffersOut[0].pvBuffer= NULL;

  BufferOut.cBuffers= 1;
  BufferOut.pBuffers= BuffersOut;
  BufferOut.ulVersion= SECBUFFER_VERSION;

  sRet = InitializeSecurityContext(&sctx->CredHdl,
                                    NULL,
                                    cio->mysql->host,
                                    SFlags,
                                    0,
                                    SECURITY_NATIVE_DREP,
                                    NULL,
                                    0,
                                    &sctx->ctxt,
                                    &BufferOut,
                                    &OutFlags,
                                    NULL);

  if(sRet != SEC_I_CONTINUE_NEEDED)
    return sRet;
  
  /* send client hello packaet */
  if(BuffersOut[0].cbBuffer != 0 && BuffersOut[0].pvBuffer != NULL)
  {  
    r= cio->methods->write(cio, (uchar *)BuffersOut[0].pvBuffer, BuffersOut[0].cbBuffer);
    if (r <= 0)
    {
      sRet= SEC_E_INTERNAL_ERROR;
      goto end;
    }
  }
  return ma_schannel_handshake_loop(cio, TRUE, &ExtraData);

end:
  FreeContextBuffer(BuffersOut[0].pvBuffer);
  DeleteSecurityContext(&sctx->ctxt);
  return sRet;
}
/* }}} */

/* {{{ static PUCHAR ma_schannel_alloc_iobuffer(CtxtHandle *Context, DWORD *BufferLength) */
/* 
   alloates an IO Buffer for ssl communication

   SYNOPSUS
     ma_schannel_alloc_iobuffer()
     Context             SChannel context handle
     BufferLength        a pointer for the buffer length

   DESCRIPTION
     calculates the required buffer length and allocates a memory buffer for en- and
     decryption. The calculated buffer length will be returned in BufferLength pointer.
     The allocated buffer needs to be freed at end of the connection.

   RETURN
     NULL                if an error occured
     PUCHAR              an IO Buffer
*/ 
static PUCHAR ma_schannel_alloc_iobuffer(CtxtHandle *Context, DWORD *BufferLength)
{
  SecPkgContext_StreamSizes StreamSizes;

  PUCHAR Buffer= NULL;

  if (!BufferLength || QueryContextAttributes(Context, SECPKG_ATTR_STREAM_SIZES, &StreamSizes) != SEC_E_OK)
    return NULL;

  /* Calculate BufferLength */
  *BufferLength= StreamSizes.cbHeader + StreamSizes.cbTrailer + StreamSizes.cbMaximumMessage;

  Buffer= LocalAlloc(LMEM_FIXED, *BufferLength);
  return Buffer;
}
/* }}} */

/* {{{ SECURITY_STATUS ma_schannel_read(MARIADB_CIO *cio, PCredHandle phCreds, CtxtHandle * phContext) */
/*
  Reads encrypted data from a SSL stream and decrypts it.

  SYNOPSIS
    ma_schannel_read
    cio              pointer to Communication IO structure
    phContext        a context handle
    DecryptLength    size of decrypted buffer
    ReadBuffer       Buffer for decrypted data
    ReadBufferSize   size of ReadBuffer


  DESCRIPTION
    Reads decrypted data from a SSL stream and encrypts it.

  RETURN
    SEC_E_OK         on success
    SEC_E_*          if an error occured
*/  

SECURITY_STATUS ma_schannel_read(MARIADB_CIO *cio,
                                 PCredHandle phCreds,
                                 CtxtHandle * phContext,
                                 DWORD *DecryptLength,
                                 uchar *ReadBuffer,
                                 DWORD ReadBufferSize)
{
  DWORD dwBytesRead= 0;
  DWORD dwOffset= 0;
  SC_CTX *sctx;
  SECURITY_STATUS sRet= 0;
  SecBuffersDesc Msg;
  SecBuffer Buffers[4],
            ExtraBuffer,
            *pData, *pExtra;
  int i;

  if (!cio || !cio->methods || !cio->methods->read || !cio->cssl || !cio->cssl->data | !DecryptLength)
    return SEC_E_INTERNAL_ERROR;

  sctx= (SC_CTX *)cio->cssl->data;
  *DecryptLength= 0;

  /* Allocate IoBuffer */
  if (!sctx->IoBuffer)
  {
    if (!(sctx->IoBuffer= ma_schannel_alloc_iobuffer(&sctx->ctxt, &sctx->IoBufferSize)))
    {
      /* todo: error */
      return NULL;
    }
  }

  while (1)
  {
    if (!dwOffset || sRet == SEC_E_INCOMPLETE_MESSAGE)
    {
      dwBytesRead= cio->methods->read(cio, sctx->IoBuffer + dwOffset, cbIoBufferLength - dwOffset);
      if (dwBytesRead == 0)
      {
        /* server closed connection */
        // todo: error 
        printf("Server closed connection\n");
        return NULL;
      }
      if (dwBytesRead < 0)
      {
        printf("Socket error\n");
        return NULL;
      }
    }
    ZeroMem(Buffers, sizeof(SecBuffer) * 4);
    Buffers[0].pvBuffer= sctx->IoBuffer;
    Buffers[0].cbBuffer= dwOffset;

    Buffers[0].BufferType= SECBUFFER_DATA; 
    Buffers[1].BufferType=
    Buffers[2].BufferType=
    Buffers[3].BufferType= SECBUFFER_EMPTY;

    Msg.ulVersion= SECBUFFER_VERSION;    // Version number
    Msg.cBuffers= 4;
    Msg.pBuffers= Buffers;

    sRet = DecryptMessage(phContext, &Msg, 0, NULL);

    /* Check for possible errors: we continue in case context has 
       expired or renogitiation is required */
    if (sRet != SEC_E_OK && sRet != SEC_I_CONTEXT_EXPIRED &&
        sRet != SEC_I_RENEGOTIARE)
    {
      // set error
      return sRet;
    }

    pData= pExtra= NULL;
    for (i=0; i < 4; i++)
    {
      if (!pData && Buffers[i].BufferType == SECBUFFER_DATA)
        pData= &Buffers[i];
      if (!pExtra && Buffers[i].BufferType == SECBUFFER_EXTRA)
        pExtra= &Buffers[i];
      if (pData && pExtra)
        break;
    }

    if (pData && pData->cbBuffer)
    {
      memcpy(ReadBuffer + *DecrypthLength, pData->pvBuffer, pData->cbBuffer);
      *DecryptLength+= pData->cbBuffer;
    }

    if (pExtra)
    {
      MoveMemory(sctx->IoBuffer, pExtra->pvBuffer, pExtra->cbBuffer);
      dwOffset= pExtra->cbBuffer;
    }
    else
      dwOffset= 0;
  }    
}
/* }}} */
