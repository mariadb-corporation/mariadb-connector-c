/****************************************************************************
  Copyright (C) 2020 MariaDB Corporation

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

  Part of this code includes code from the PHP project which
  is freely available from http://www.php.net
 *****************************************************************************/
#ifndef MA_PRIV_H
#define MA_PRIV_H

void free_rows(MYSQL_DATA *cur);
int ma_multi_command(MYSQL *mysql, enum enum_multi_status status);
MYSQL_FIELD *ma_read_fields(MYSQL *mysql, MA_MEM_ROOT *alloc,
                            uint *field_count, my_bool default_value);
int ma_unpack_field(MA_MEM_ROOT *alloc, uchar *pos, ulong pkt_len,
                    MYSQL_FIELD *field, my_bool ext_info,
                    my_bool default_value);

static inline my_bool ma_has_extended_type_info(const MYSQL *mysql)
{
  return ((mysql->extension->mariadb_server_capabilities) &
          (MARIADB_CLIENT_EXTENDED_METADATA >> 32)) != 0;
}

static inline uint ma_extended_type_info_rows(const MYSQL *mysql)
{
  return ma_has_extended_type_info(mysql) ? 1 : 0;
}

static inline my_bool ma_supports_cache_metadata(const MYSQL *mysql)
{
  return (mysql->extension->mariadb_server_capabilities &
          (MARIADB_CLIENT_CACHE_METADATA >> 32)) != 0 ;
}


static inline uint ma_result_set_rows(const MYSQL *mysql)
{
  return ma_has_extended_type_info(mysql) ? 9 : 8;
}

MA_FIELD_EXTENSION *ma_field_extension_deep_dup(MA_MEM_ROOT *memroot,
                                                const MA_FIELD_EXTENSION *from);

MYSQL_FIELD *ma_duplicate_resultset_metadata(MYSQL_FIELD *fields, size_t count,
                                             MA_MEM_ROOT *memroot);

static inline int net_field_length_ll_safe(uchar **pos, const uchar *end,
                                           unsigned long long *len)
{
  uchar *p= *pos;
  size_t avail;

  if (p >= end)
    return MARIADB_LENENC_ERROR;

  /* 0..250: the byte is the value, by far the most common case */
  if (*p < 251)
  {
    *len= (unsigned long long)*p;
    *pos= p + 1;
    return MARIADB_LENENC_OK;
  }

  avail= (size_t)(end - p);       /* >= 1, includes the marker byte */

  if (*p == 251)
  {
    *len= 0;
    *pos= p + 1;
    return MARIADB_LENENC_NULL;
  }
  if (*p == 252)
  {
    if (avail < 3)
      return MARIADB_LENENC_ERROR;
    *len= (unsigned long long)uint2korr(p + 1);
    *pos= p + 3;
    return MARIADB_LENENC_OK;
  }
  if (*p == 253)
  {
    if (avail < 4)
      return MARIADB_LENENC_ERROR;
    *len= (unsigned long long)uint3korr(p + 1);
    *pos= p + 4;
    return MARIADB_LENENC_OK;
  }
  if (*p == 254)
  {
    if (avail < 9)
      return MARIADB_LENENC_ERROR;
    *len= (unsigned long long)uint8korr(p + 1);
    *pos= p + 9;
    return MARIADB_LENENC_OK;
  }
  return MARIADB_LENENC_ERROR;    /* 255: never a valid length marker */
}

static inline int net_field_length_safe(uchar **pos, const uchar *end, ulong *len)
{
  uchar *p= *pos;
  size_t avail;

  if (p >= end)
    return MARIADB_LENENC_ERROR;

  /* 0..250: the byte is the value, by far the most common case */
  if (*p < 251)
  {
    *len= (ulong)*p;
    *pos= p + 1;
    return MARIADB_LENENC_OK;
  }

  avail= (size_t)(end - p);       /* >= 1, includes the marker byte */

  if (*p == 251)
  {
    *len= 0;
    *pos= p + 1;
    return MARIADB_LENENC_NULL;
  }
  if (*p == 252)
  {
    if (avail < 3)
      return MARIADB_LENENC_ERROR;
    *len= (ulong)uint2korr(p + 1);
    *pos= p + 3;
    return MARIADB_LENENC_OK;
  }
  if (*p == 253)
  {
    if (avail < 4)
      return MARIADB_LENENC_ERROR;
    *len= (ulong)uint3korr(p + 1);
    *pos= p + 4;
    return MARIADB_LENENC_OK;
  }
  if (*p == 254)
  {
    unsigned long long v;

    if (avail < 9)
      return MARIADB_LENENC_ERROR;
    v= (unsigned long long)uint8korr(p + 1);
    if (v > 0xFFFFFFFFULL)
      return MARIADB_LENENC_ERROR;
    *len= (ulong)v;
    *pos= p + 9;
    return MARIADB_LENENC_OK;
  }
  return MARIADB_LENENC_ERROR;    /* 255: never a valid length marker */
}


extern void ma_save_session_track_info(void *ptr, enum enum_mariadb_status_info type, ...);

#define ma_status_callback(mysql, last_status)\
  if ((mysql)->server_status != last_status && \
      (mysql)->options.extension->status_callback != ma_save_session_track_info)\
  {\
    (mysql)->options.extension->status_callback((mysql)->options.extension->status_data,\
                                                STATUS_TYPE, (mysql)->server_status);\
  }

#endif
