/*
  Copyright (c) 2024, 2026, MariaDB plc

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1335  USA */

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#define random_bytes(B,L) RAND_bytes(B,L)
#elif defined(HAVE_GNUTLS)
#include <nettle/eddsa.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha2.h>
#include <nettle/nettle-meta.h>
#include <nettle/hmac.h>
#include <gnutls/crypto.h>
#define random_bytes(B,L) gnutls_rnd(GNUTLS_RND_NONCE, B, L)
#elif defined(HAVE_SCHANNEL)
#include <windows.h>
#include <ma_crypt.h>
#include <bcrypt.h>
#include <crypto_sign.h>
#define random_bytes(B,L) BCryptGenRandom(NULL ,(PUCHAR)(B),(L), BCRYPT_USE_SYSTEM_PREFERRED_RNG)
#endif

#include <errmsg.h>
#include <ma_global.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>

#define CHALLENGE_SCRAMBLE_LENGTH 32
#define CHALLENGE_SALT_LENGTH     18
#define ED25519_SIG_LENGTH        64
#define ED25519_KEY_LENGTH        32
#define PBKDF2_HASH_LENGTH        ED25519_KEY_LENGTH
#define CLIENT_RESPONSE_LENGTH    (CHALLENGE_SCRAMBLE_LENGTH + ED25519_SIG_LENGTH)
#define PARSEC_ITER_FACTOR_MAX    20

/* Conservative constant proposed in CONC-838 */
#define PBKDF2_ROUNDS_PER_MS (262144.0 / 225.0)
#define SERVER_CONNECT_TIMEOUT_DEFAULT 10

struct Passwd_in_memory
{
  char algorithm;
  uchar iterations;
  uchar salt[CHALLENGE_SALT_LENGTH];
  uchar pub_key[ED25519_KEY_LENGTH];
};

#ifdef _MSC_VER
# define _Static_assert static_assert
#endif

_Static_assert(sizeof(struct Passwd_in_memory) == 2 + CHALLENGE_SALT_LENGTH
                                                   + ED25519_KEY_LENGTH,
              "Passwd_in_memory should be packed.");

struct Client_signed_response
{
  union {
    struct {
      uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      uchar signature[ED25519_SIG_LENGTH];
    };
    uchar start[1];
  };
};

_Static_assert(sizeof(struct Client_signed_response) == CLIENT_RESPONSE_LENGTH,
              "Client_signed_response should be packed.");

static int get_max_iter_factor(MYSQL *mysql)
{
  unsigned int timeout= mysql->options.connect_timeout ?
                        mysql->options.connect_timeout : SERVER_CONNECT_TIMEOUT_DEFAULT;
  int max_factor = 0;

  unsigned long long max_rounds= (unsigned long long)(PBKDF2_ROUNDS_PER_MS * (timeout * 1000.0));

  if (max_rounds > 1024.0) {
    unsigned long long val = max_rounds / 1024;
    /* use bitshifting to avoid libm dependency */
    while (val >>= 1) {
      max_factor++;
    }
  }

  if (max_factor > PARSEC_ITER_FACTOR_MAX)
    max_factor= PARSEC_ITER_FACTOR_MAX;

  return max_factor;
}

int compute_derived_key(const char* password, size_t pass_len,
                        const struct Passwd_in_memory *params,
                        uchar *derived_key)
{
#if defined(HAVE_OPENSSL)
  return !PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                            CHALLENGE_SALT_LENGTH,
                            1 << (params->iterations + 10),
                            EVP_sha512(), PBKDF2_HASH_LENGTH, derived_key);
#elif defined(HAVE_GNUTLS) /* HAVE_GNUTLS */
  struct hmac_sha512_ctx ctx;
  hmac_sha512_set_key(&ctx, pass_len, (const uint8_t *)password);

  /*
    pbkdf2/nettle functions are third party, so ignore the bad function casts
  */
# if defined __clang_major__ && __clang_major__ >= 16
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wcast-function-type-strict"
# endif
  pbkdf2(&ctx, (nettle_hash_update_func *)hmac_sha512_update,
         (nettle_hash_digest_func *)hmac_sha512_digest, SHA512_DIGEST_SIZE,
         1024 << params->iterations, CHALLENGE_SALT_LENGTH, params->salt,
         PBKDF2_HASH_LENGTH, derived_key);
# if defined __clang_major__ && __clang_major__ >= 16
#  pragma clang diagnostic pop
# endif
#elif defined(HAVE_SCHANNEL)
  BCRYPT_ALG_HANDLE algHdl;
  NTSTATUS status;

  if ((status = BCryptOpenAlgorithmProvider(&algHdl, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) != 0)
    goto end;

  if ((status = BCryptDeriveKeyPBKDF2(algHdl, (BYTE*)password, (ULONG)pass_len, (BYTE*)params->salt, CHALLENGE_SALT_LENGTH, 1024 << params->iterations, derived_key, PBKDF2_HASH_LENGTH, 0)) != 0)
    goto end;

end:
  BCryptCloseAlgorithmProvider(algHdl, 0);
  return (int)status;
#endif
  return 0;
}

int ed25519_sign(const uchar *response, size_t response_len,
                 const uchar *private_key, uchar *signature,
                 uchar *public_key)
{

#if defined(HAVE_OPENSSL)
  int res= 1;
  size_t sig_len= ED25519_SIG_LENGTH, pklen= ED25519_KEY_LENGTH;
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                private_key,
                                                ED25519_KEY_LENGTH);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx || !pkey)
    goto cleanup;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1 ||
      EVP_DigestSign(ctx, signature, &sig_len, response, response_len) != 1)
    goto cleanup;

  EVP_PKEY_get_raw_public_key(pkey, public_key, &pklen);

  res= 0;
cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return res;
#elif defined(HAVE_GNUTLS) /* HAVE_GNUTLS */
  ed25519_sha512_public_key((uint8_t*)public_key, (uint8_t*)private_key);
  ed25519_sha512_sign((uint8_t*)public_key, (uint8_t*)private_key,
                      response_len, (uint8_t*)response, (uint8_t*)signature);
#elif defined(HAVE_SCHANNEL)
  unsigned char sig[ED25519_SIG_LENGTH + CHALLENGE_SCRAMBLE_LENGTH * 2];

  if (ma_crypto_sign((unsigned char *)sig, public_key,
                     response, response_len,
                     private_key, ED25519_KEY_LENGTH))
    return 1;
  memcpy(signature, sig, ED25519_SIG_LENGTH);
#endif
  return 0;
}

/*
  We cache between sessions: the private and public keys (very
  expensive to calculate, pbkdf2 with many rounds) and the ext-salt (to
  avoid re-requesting it)
*/
struct Cached_key
{
  MA_PLUGIN_DATA header;
  struct Passwd_in_memory params;
  uchar priv_key[ED25519_KEY_LENGTH];
};

static int auth(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  uchar *serv_scramble;
  union
  {
    struct
    {
      uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      struct Client_signed_response response;
    };
    uchar start[1];
  } signed_msg;
  _Static_assert(sizeof signed_msg == CHALLENGE_SCRAMBLE_LENGTH
                                     + sizeof(struct Client_signed_response),
                "signed_msg should be packed.");

  struct Passwd_in_memory *params;
  struct Cached_key *cached= (struct Cached_key *)mysql->plugin_data;
  int pkt_len;
  size_t pwlen= strlen(mysql->passwd);
  unsigned int max_iter_factor;

  pkt_len= vio->read_packet(vio, (uchar**)(&serv_scramble));
  if (pkt_len != CHALLENGE_SCRAMBLE_LENGTH)
    return CR_SERVER_HANDSHAKE_ERR;

  memcpy(signed_msg.server_scramble, serv_scramble, CHALLENGE_SCRAMBLE_LENGTH);
  random_bytes(signed_msg.response.client_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  if (cached)
  {
    /* Sign straight away to save a round-trip. */
    if (ed25519_sign(signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH * 2,
                     cached->priv_key, signed_msg.response.signature,
                     cached->params.pub_key))
      return CR_AUTH_PLUGIN_ERR;

    if (vio->write_packet(vio, signed_msg.response.start,
                          sizeof signed_msg.response) != 0)
      return CR_ERROR;
  }
  else if (vio->write_packet(vio, 0, 0) != 0) // Request salt
    return CR_ERROR;

  pkt_len= vio->read_packet(vio, (uchar**)&params);
  if (pkt_len < 0)
    return CR_ERROR;

  /* if it's not the salt - let the caller read the ok packet or fail */
  if (pkt_len != 2 + CHALLENGE_SALT_LENGTH || params->algorithm != 'P')
    return CR_OK_HANDSHAKE_COMPLETE;

  max_iter_factor= get_max_iter_factor(mysql);

  if (params->iterations > max_iter_factor)
    return CR_AUTH_PLUGIN_ERR;

  if (!cached && !(cached= (struct Cached_key *)malloc(sizeof(*cached))))
    return CR_OUT_OF_MEMORY;
  cached->header.length= sizeof(*cached);
  mysql->plugin_data= &cached->header;

  if (compute_derived_key(mysql->passwd, pwlen, params, cached->priv_key))
    return CR_AUTH_PLUGIN_ERR;

  if (ed25519_sign(signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH * 2,
                   cached->priv_key, signed_msg.response.signature,
                   params->pub_key))
    return CR_AUTH_PLUGIN_ERR;

  cached->params= *params;

  if (vio->write_packet(vio, signed_msg.response.start,
                        sizeof signed_msg.response) != 0)
    return CR_ERROR;

  return CR_OK;
}

static int hash_password(MYSQL *mysql, unsigned char *out, size_t *outlen)
{
  struct Cached_key *cached= (struct Cached_key *)mysql->plugin_data;

  if (*outlen < sizeof(struct Passwd_in_memory) || !cached)
    return 1;
  *outlen= sizeof(struct Passwd_in_memory);

  /* what auth() has just derived, or read out of the cache */
  memcpy(out, &cached->params, sizeof(struct Passwd_in_memory));
  return 0;
}

#ifndef PLUGIN_DYNAMIC
struct st_mysql_client_plugin_AUTHENTICATION parsec_client_plugin=
#else
MARIADB_CLIENT_PLUGIN_EXPORT struct st_mysql_client_plugin_AUTHENTICATION
  _mysql_client_plugin_declaration_=
#endif
{
  .type   = MYSQL_CLIENT_AUTHENTICATION_PLUGIN,
  .interface_version = MYSQL_CLIENT_AUTHENTICATION_PLUGIN_INTERFACE_VERSION,
  .name   = "parsec",
  .author = "Nikita Maliavin",
  .desc   = "Password Authentication using Response Signed with Elliptic Curve",
  .version= {0,1,1},
  .license= "LGPL",
  .authenticate_user= auth,
  .hash_password_bin= hash_password
};
