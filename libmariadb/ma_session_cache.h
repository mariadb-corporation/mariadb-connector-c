/************************************************************************************
  Copyright (C) 2026 MariaDB plc

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

#ifndef _ma_session_cache_h_
#define _ma_session_cache_h_

#include <ma_hash.h>
#include <ma_tls.h>
#include <time.h>

/*
  Session cache.

  Whatever a new connection can reuse from an earlier connection to the same
  server, made with the same configuration and as the same user.

  ma_session_cache_init/deinit are called once per process from
  mysql_server_init()/mysql_server_end().
*/

void ma_session_cache_init(void);
void ma_session_cache_deinit(void);

/* Build the cache key of a connection, MA_SHA256_HASH_SIZE bytes. */
my_bool ma_session_cache_key(MYSQL *mysql, uchar *key);

/* Removes from the cache and returns the oldest not expired TLS session of
   this connection identity. */
SSL_SESSION *ma_tls_session_take(const uchar *key);

/* Cache a TLS session of this connection identity, valid until not_after. */
void ma_tls_session_add(const uchar *key, SSL_SESSION *tls_session,
                        time_t not_after);

/* Drop every TLS session of this connection identity. Used when a server
   rejected one of them - it means that others won't work either. */
void ma_tls_session_clear(const uchar *key);

#endif /* _ma_session_cache_h_ */
