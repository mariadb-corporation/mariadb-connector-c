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

#ifndef _ma_hash_h_
#define _ma_hash_h_

#include <stddef.h>
#include <stdarg.h>

/*! Hash algorithms */
#define MA_HASH_MD5       1
#define MA_HASH_SHA1      2
#define MA_HASH_SHA224    3
#define MA_HASH_SHA256    4
#define MA_HASH_SHA384    5
#define MA_HASH_SHA512    6
#define MA_HASH_RIPEMD160 7

/*! Hash digest sizes */
#define MA_MD5_HASH_SIZE 16
#define MA_SHA1_HASH_SIZE 20
#define MA_SHA224_HASH_SIZE 28
#define MA_SHA256_HASH_SIZE 32
#define MA_SHA384_HASH_SIZE 48
#define MA_SHA512_HASH_SIZE 64
#define MA_RIPEMD160_HASH_SIZE 20

#define MA_MAX_HASH_SIZE 64
/** \typedef MRL hash context */

#if defined(HAVE_OPENSSL)
typedef void MA_HASH_CTX;
#elif defined(HAVE_SCHANNEL)
typedef struct {
  char free_me;
  BCRYPT_ALG_HANDLE hAlg;
  BCRYPT_HASH_HANDLE hHash;
  PBYTE hashObject;
  DWORD digest_len;
} MA_HASH_CTX;
#endif

/**
  @brief acquire and initialize new hash context

  @param[in] algorithm   hash algorithm
  @param[in] ctx         pointer to a crypto context

  @return    hash context on success, NULL on error
*/
MA_HASH_CTX *ma_hash_new(unsigned int algorithm, MA_HASH_CTX *ctx);

/**
  @brief release and deinitializes a hash context

  @param[in] hash context

  @return    void
*/
void ma_hash_free(MA_HASH_CTX *ctx);

/**
  @brief hashes len bytes of data into the hash context.
  This function can be called several times on same context to
  hash additional data.

  @param[in] ctx        hash context
  @param[in] buffer     data buffer
  @param[in] len        size of buffer

  @return               void
*/
void ma_hash_input(MA_HASH_CTX *ctx,
                   const unsigned char *buffer,
                   size_t len);

/**
  @brief retrieves the hash value from hash context 

  @param[in] ctx        hash context
  @param[out] digest    digest containing hash value

  @return               void
 */
void ma_hash_result(MA_HASH_CTX *ctx, unsigned char *digest);

/**
  @brief wrapper function to compute hash from one or more
  buffers.

  @param[in] hash_alg ]   hash algorithm
  @param[out] digest]     computed hash digest
  @param[in] ...          variable argument list containg touples of
                          message and message lengths. Last parameter
                          must be always NULL.

  @return                 void
*/

/**
  @brief  returns digest size for a given hash algorithm

  @param[in] hash algorithm

  @retuns digest size or 0 on error
*/
static inline size_t ma_hash_digest_size(unsigned int hash_alg)
{
  switch(hash_alg) {
  case MA_HASH_MD5:
    return MA_MD5_HASH_SIZE;
  case MA_HASH_SHA1:
    return MA_SHA1_HASH_SIZE;
  case MA_HASH_SHA224:
    return MA_SHA224_HASH_SIZE;
  case MA_HASH_SHA256:
    return MA_SHA256_HASH_SIZE;
  case MA_HASH_SHA384:
    return MA_SHA384_HASH_SIZE;
  case MA_HASH_SHA512:
    return MA_SHA512_HASH_SIZE;
  case MA_HASH_RIPEMD160:
    return MA_RIPEMD160_HASH_SIZE;
  default:
    return 0;
  }
}

#endif /* _ma_hash_h_ */
