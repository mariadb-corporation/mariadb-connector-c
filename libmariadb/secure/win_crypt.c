/*
    Copyright (C) 2018 MariaDB Corporation AB

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
*/
#include <windows.h>
#include <bcrypt.h>
#include <ma_crypt.h>
#include <malloc.h>

static LPCWSTR ma_hash_get_algorithm(unsigned int alg)
{
  switch(alg)
  {
  case MA_HASH_SHA1:
    return BCRYPT_SHA1_ALGORITHM;
  case MA_HASH_SHA256:
    return BCRYPT_SHA256_ALGORITHM;
  case MA_HASH_SHA384:
    return BCRYPT_SHA384_ALGORITHM;
  case MA_HASH_SHA512:
    return BCRYPT_SHA512_ALGORITHM;
  default:
    return NULL;
  }
}

MA_HASH_CTX *ma_hash_new(unsigned int algorithm, MA_HASH_CTX *ctx)
{
  MA_HASH_CTX *newctx= ctx;
  DWORD cbObjSize, cbData;
  LPCWSTR alg;
  BCRYPT_ALG_HANDLE algHdl= 0;

  alg= ma_hash_get_algorithm(algorithm);

  if (!alg)
    return NULL;

  if (!newctx)
  {
    newctx= (MA_HASH_CTX *)calloc(1, sizeof(MA_HASH_CTX));
    newctx->free_me= 1;
  } else {
    char tmp_freeme= newctx->free_me;
    BCRYPT_ALG_HANDLE tmp_alg= newctx->hAlg;

    newctx->free_me= 0;
    newctx->hAlg = 0;
 
    ma_hash_free(newctx); 

    newctx->free_me= tmp_freeme;
    newctx->hAlg= tmp_alg;
  }

  if (!newctx->hAlg)
    if (BCryptOpenAlgorithmProvider(&newctx->hAlg, alg, NULL, 0))
      goto error;

  if (BCryptGetProperty(newctx->hAlg, BCRYPT_OBJECT_LENGTH,
                      (PBYTE)&cbObjSize, sizeof(DWORD),
                      &cbData, 0) < 0)
    goto error;

  newctx->hashObject= (PBYTE)malloc(cbObjSize);
  newctx->digest_len= (DWORD)ma_hash_digest_size(algorithm);
  BCryptCreateHash(newctx->hAlg, &newctx->hHash, newctx->hashObject, cbObjSize, NULL, 0, 0);

  return newctx;
error:
  if (newctx && !ctx)
    free(newctx);
  return NULL;
}

void ma_hash_free(MA_HASH_CTX *ctx)
{
  if (ctx)
  {
    if (ctx->hHash)
      BCryptDestroyHash(ctx->hHash);
    if (ctx->hashObject)
      free(ctx->hashObject);
    if (ctx->hAlg)
      BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
	if (ctx->free_me)
      free(ctx);
  }
}

void ma_hash_input(MA_HASH_CTX *ctx,
                   const unsigned char *buffer,
                   size_t len)
{
  BCryptHashData(ctx->hHash, (PUCHAR)buffer, (LONG)len, 0);
}

void ma_hash_result(MA_HASH_CTX *ctx, unsigned char *digest)
{
  BCryptFinishHash(ctx->hHash, digest, ctx->digest_len, 0);
}
