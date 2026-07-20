/************************************************************************************
    Copyright (C) 2018,2022 MariaDB Corporation AB

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

#include <ma_global.h>
#include <ma_sys.h>
#include <ma_common.h>
#include <mysql.h>
#include <errmsg.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <zlib.h>
#include <ma_decimal.h>
#include <mariadb_rpl.h>


#ifdef WIN32
#include <malloc.h>
#undef alloca
#define alloca _malloca
#endif

#define RPL_EVENT_HEADER_SIZE 19
#define RPL_ERR_POS(r) (r)->filename ? (size_t)(r)->filename_length : (size_t)0, \
                       (r)->filename ? (r)->filename : (const char *)"", \
                       (long)(r)->start_position
#define RPL_CHECK_NULL_POS(position, end)\
{\
  uchar *tmp= (position);\
  while (*tmp && tmp < (end))\
    tmp++;\
  if (tmp > (end))\
    goto malformed_packet;\
}

#define RPL_CALC_SAFE_LEN(ev, ev_end, use_checksum, out_len, error_target) \
do {                                                                              \
  size_t _avail, _pad;                                                            \
  /* 1. Ensure pointers haven't crossed or overshot before doing any math */      \
  if ((ev_end) < (ev)) {                                                          \
    goto error_target;                                                            \
  }                                                                               \
                                                                                  \
  _avail = (size_t)((ev_end) - (ev));                                             \
  _pad = (use_checksum) ? 4 : 0;                                                  \
                                                                                  \
  /* 2. Validate that available bytes can accommodate the checksum trailer */    \
  if (_avail >= _pad) {                                                           \
    (out_len) = _avail - _pad;                                                    \
  } else {                                                                        \
    goto error_target;                                                            \
  }                                                                               \
} while (0)

#define RPL_CALC_SAFE_HDR_LEN(hdr_len, consumed, pad, out_len, error_target)  \
do {                                                                          \
  size_t _hdr    = (size_t)(hdr_len);                                         \
  size_t _cons   = (size_t)(consumed);                                        \
  size_t _pad    = (size_t)(pad);                                             \
  size_t _remain;                                                             \
                                                                              \
  /* 1. Ensure the header size can comfortably accommodate what we consumed */ \
  if (_hdr < _cons) {                                                         \
    goto error_target;                                                        \
  }                                                                           \
                                                                              \
  _remain = _hdr - _cons;                                                     \
                                                                              \
  /* 2. Ensure remaining space can accommodate the checksum/crypto pad */     \
  if (_remain >= _pad) {                                                      \
    (out_len) = _remain - _pad;                                               \
  } else {                                                                    \
    goto error_target;                                                        \
  }                                                                           \
} while (0)

#define RPL_CHECK_POS(position, end, bytes) \
do { \
    size_t _req_bytes = (size_t)(bytes); \
    if ((end) < (position) || (size_t)((end) - (position)) < _req_bytes) \
        goto malformed_packet; \
} while(0)

#define RPL_CHECK_FIELD_LENGTH(position, end)\
{\
  RPL_CHECK_POS((position), (end), 1);\
  RPL_CHECK_POS((position), (end), net_field_size((position)));\
}

RPL_SUPPORTED_POST_HEADER_LEN post_header_lengths[] = {
  {1,   {0, 56}},   /* START_EVENT_V3 */
  {2,   {13, 13}},  /* QUERY_EVENT */
  {3,   {0, 0}},    /* STOP_EVENT */
  {4,   {8, 8}},    /* ROTATE_EVENT */
  {5,   {0, 0}},    /* INTVAR_EVENT */
  {6,   {0, 18}},   /* LOAD_EVENT */
  {7,   {0, 0}},    /* SLAVE_EVENT */
  {8,   {0, 4}},    /* CREATE_FILE_EVENT */
  {9,   {4, 4}},    /* APPEND_BLOCK_EVENT */
  {10,  {0, 4}},    /* EXEC_LOAD_EVENT */
  {11,  {4, 4}},    /* DELETE_FILE_EVENT */
  {12,  {0, 18}},   /* NEW_LOAD_EVENT */
  {13,  {0, 0}},    /* RAND_EVENT */
  {14,  {0, 0}},    /* USER_VAR_EVENT */
  {15,  {98, 228}}, /* FORMAT_DESCRIPTION_EVENT */
  {16,  {0, 0}},    /* XID_EVENT */
  {17,  {4, 4}},    /* BEGIN_LOAD_QUERY_EVENT */
  {18,  {26, 26}},  /* EXECUTE_LOAD_QUERY_EVENT */
  {19,  {8, 8}},    /* TABLE_MAP_EVENT */
  {20,  {0, 0}},    /* PRE_GA_WRITE_ROWS_EVENT */
  {21,  {0, 0}},    /* PRE_GA_UPDATE_ROWS_EVENT */
  {22,  {0, 0}},    /* PRE_GA_DELETE_ROWS_EVENT */
  {23,  {8, 8}},    /* WRITE_ROWS_EVENT_V1 */
  {24,  {8, 8}},    /* UPDATE_ROWS_EVENT_V1 */
  {25,  {8, 8}},    /* DELETE_ROWS_EVENT_V1 */
  {26,  {2, 2}},    /* INCIDENT_EVENT */
  {27,  {0, 0}},    /* HEARTBEAT_LOG_EVENT */
  {28,  {0, 0}},    /* IGNORABLE_LOG_EVENT */
  {29,  {0, 0}},    /* ROWS_QUERY_LOG_EVENT */
  {30,  {10, 10}},  /* WRITE_ROWS_EVENT */
  {31,  {10, 10}},  /* UPDATE_ROWS_EVENT */
  {32,  {10, 10}},  /* DELETE_ROWS_EVENT */
  {33,  {42, 0}},   /* GTID_LOG_EVENT */
  {34,  {42, 0}},   /* ANONYMOUS_GTID_LOG_EVENT */
  {35,  {0, 0}},    /* PREVIOUS_GTIDS_LOG_EVENT */
  {36,  {18, 0}},   /* TRANSACTION_CONTEXT_EVENT */
  {37,  {52, 0}},   /* VIEW_CHANGE_EVENT */
  {38,  {0, 0}},    /* XA_PREPARE_LOG_EVENT */
  {39,  {10, 10}},  /* PARTIAL_UPDATE_ROWS_EVENT */

  /* MariaDB Specific Extensions Block (MySQL handles as unknown/0) */
  {160, {0, 0}},    /* ANNOTATE_ROWS_EVENT */
  {161, {0, 4}},    /* BINLOG_CHECKPOINT_EVENT */
  {162, {0, 19}},   /* GTID_EVENT */
  {163, {0, 4}},    /* GTID_LIST_EVENT */
  {164, {0, 0}},    /* START_ENCRYPTION_EVENT */
  {165, {0, 13}},   /* QUERY_COMPRESSED_EVENT */
  {166, {0, 8}},    /* WRITE_ROWS_COMPRESSED_EVENT_V1 */
  {167, {0, 8}},    /* UPDATE_ROWS_COMPRESSED_EVENT_V1 */
  {168, {0, 8}},    /* DELETE_ROWS_COMPRESSED_EVENT_V1 */
  {169, {0, 10}},   /* WRITE_ROWS_COMPRESSED_EVENT */
  {170, {0, 10}},   /* UPDATE_ROWS_COMPRESSED_EVENT */
  {171, {0, 10}},   /* DELETE_ROWS_COMPRESSED_EVENT */
  {0,   {0, 0}}     /* Sentinel */
};

static ssize_t get_post_header_length(MARIADB_RPL *rpl, enum mariadb_rpl_event event)
{
  if (!rpl || event <= 0)
    return -1;
  if (event == 0 || event > rpl->num_post_header_lengths)
    return -1;
  return (size_t)rpl->post_header_len[event - 1];
}

static uint32_t get_min_expected_header_len(uint8_t event_type, RPL_SERVER_TYPE server_type)
{
  size_t i = 0;

  if (server_type < 0 || server_type >= RPL_SERVER_COUNT)
    server_type = RPL_SERVER_MYSQL;

  while (post_header_lengths[i].event != 0)
  {
    if (post_header_lengths[i].event == event_type)
    {
      /* Maps directly to the length matrix array bucket */
      return (uint32_t)post_header_lengths[i].length[server_type];
    }
    i++;
  }

  return 0;
}

static inline uint64_t uintNkorr(uint8_t len, u_char *p)
{
  switch (len) {
    case 1:
      return *p;
    case 2:
      return uint2korr(p);
    case 3:
      return uint3korr(p);
    case 4:
      return uint4korr(p);
    case 8:
      return uint8korr(p);
    default:
      return 0;
  }
}

static inline int net_field_size(uchar *p)
{
  if (*p <= 251)
    return 1;
  if (*p == 252)
    return 3;
  if (*p == 253)
    return 4;
  return 9;
}

static inline int rpl_bit_size(uint32_t x)
{
  int bits= 1;

  while (x >>= 1)
    bits++;

  return bits;
}

static inline int rpl_byte_size(uint32_t x)
{
  int bits= rpl_bit_size(x);

  return (bits + 7) / 8;
}

void rpl_set_error(MARIADB_RPL *rpl,
                   unsigned int error_nr,
                   const char *format,
                    ...)
{
  va_list ap;

  const char *errmsg= NULL;

  if (!format)
  {
    if (error_nr >= CR_MIN_ERROR && error_nr <= CR_MYSQL_LAST_ERROR)
      errmsg= ER(error_nr);
    else if (error_nr >= CER_MIN_ERROR && error_nr <= CR_MARIADB_LAST_ERROR)
      errmsg= CER(error_nr);
    else
      errmsg= ER(CR_UNKNOWN_ERROR);
  }

  if (error_nr == CR_BINLOG_ERROR && (!rpl || !rpl->filename))
  {
    errmsg = "Binary log error: (No file context available). Details: %s";
  }

  rpl->error_no= error_nr;
  va_start(ap, format);
  vsnprintf(rpl->error_msg, MYSQL_ERRMSG_SIZE - 1,
            format ? format : errmsg, ap);
  va_end(ap);

  /* For backward compatibility we also need to set a connection
     error, if we read from primary instead of file */
  if (rpl->mysql)
  {
    my_set_error(rpl->mysql, error_nr, SQLSTATE_UNKNOWN, rpl->error_msg);
  }
}

const char * STDCALL mariadb_rpl_error(MARIADB_RPL *rpl)
{
  return rpl->error_msg;
}

uint32_t STDCALL mariadb_rpl_errno(MARIADB_RPL *rpl)
{
  return rpl->error_no;
}

uint8_t rpl_parse_opt_metadata(MARIADB_RPL_EVENT *event, const uchar *buffer, size_t length)
{
  const uchar *pos= buffer, *end= buffer + length;
  struct st_mariadb_rpl_table_map_event *tm_event= (struct st_mariadb_rpl_table_map_event *)&event->event;

  if (event->event_type != TABLE_MAP_EVENT)
    return 1;

  while (pos < end)
  {
    uint8_t meta_type= *pos++;
    uint32_t len;

    RPL_CHECK_FIELD_LENGTH((uchar *)pos, end);
    len= net_field_length((uchar **)&pos);
    RPL_CHECK_POS(pos, end,len);

    switch(meta_type)
    {
      case SIGNEDNESS:
        tm_event->signed_indicator= (uchar *)pos;
        pos+= len;
        break;
      case DEFAULT_CHARSET:
        tm_event->default_charset= *pos;
        pos+= len;
        break;
      case COLUMN_CHARSET:
        tm_event->column_charsets.data= pos;
        tm_event->column_charsets.length= len;
        pos+= len;
        break;
      case COLUMN_NAME:
        tm_event->column_names.data= pos;
        tm_event->column_names.length= len;
        pos+= len;
        break;
      case SIMPLE_PRIMARY_KEY:
        tm_event->simple_primary_keys.data= pos;
        tm_event->simple_primary_keys.length= len;
        pos+= len;
        break;
      case PRIMARY_KEY_WITH_PREFIX:
        tm_event->prefixed_primary_keys.data= pos;
        tm_event->prefixed_primary_keys.length= len;
        pos+= len;
        break;
      case GEOMETRY_TYPE:
      {
        tm_event->geometry_types.data= pos;
        tm_event->geometry_types.length= len;
        pos+= len;
        break;
      }
      /* Default character set used by all columns */
      case ENUM_AND_SET_DEFAULT_CHARSET:
        tm_event->enum_set_default_charset= *pos;
        pos+= len;
        break;
      case ENUM_AND_SET_COLUMN_CHARSET:
        tm_event->enum_set_column_charsets.data= pos;
        tm_event->enum_set_column_charsets.length= len;
        pos+= len;
        break;
      case SET_STR_VALUE:
        tm_event->set_values.data= pos;
        tm_event->set_values.length= len;
        pos+= len;
        break;
      case ENUM_STR_VALUE:
        tm_event->enum_values.data= pos;
        tm_event->enum_values.length= len;
        pos+= len;
        break;
      default:
        rpl_set_error(event->rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(event->rpl), "Unknown/unsupported event type");
        pos+= len;
        break;
    }
  }
  return 0;
malformed_packet:
  return 1;
}

static void *ma_calloc_root(void *memroot, size_t len)
{
  void *p;

  if ((p= ma_alloc_root(memroot, len)))
    memset(p, 0, len);
  return p;
}

static void rpl_set_string_and_len(MARIADB_STRING *s,
                            unsigned char *buffer,
                            size_t len)
{
  if (!buffer || !len)
  {
    s->length= 0;
    return;
  }
  s->str= (char *)buffer;
  s->length= len;
}

static uint8_t rpl_alloc_set_string_and_len(MARIADB_RPL_EVENT *event,
                                            MARIADB_STRING *s,
                                            void *buffer,
                                            size_t len)
{
  if (!s)
    return 0;

  if (!buffer || !len)
  {
    s->length= 0;
    return 0;
  }

  if (!(s->str = (char *)ma_alloc_root(&event->memroot, len)))
    return 1;

  memcpy(s->str, buffer, len);
  s->length= len;
  return 0;
}

static uint8_t rpl_metadata_size(enum enum_field_types field_type)
{
  switch (field_type) {
    case MYSQL_TYPE_DOUBLE:
    case MYSQL_TYPE_FLOAT:
    case MYSQL_TYPE_BLOB:
    case MYSQL_TYPE_DATETIME2:
    case MYSQL_TYPE_TIMESTAMP2:
    case MYSQL_TYPE_TIME2:
    case MYSQL_TYPE_TINY_BLOB:
    case MYSQL_TYPE_MEDIUM_BLOB:
    case MYSQL_TYPE_LONG_BLOB:
      return 1;
    case MYSQL_TYPE_STRING:
    case MYSQL_TYPE_ENUM:
    case MYSQL_TYPE_SET:
    case MYSQL_TYPE_NEWDECIMAL:
    case MYSQL_TYPE_VARCHAR:
    case MYSQL_TYPE_VAR_STRING:
    case MYSQL_TYPE_BIT:
      return 2;
    default:
      return 0;
  }
}

static uint8_t ma_rpl_get_second_part(MYSQL_TIME *tm, uchar *ptr, uchar *metadata)
{
  switch(metadata[0])
  {
    case 0:
      tm->second_part= 0;
      return 0;
    case 1:
    case 2:
      tm->second_part= (uint32_t)ptr[0] * 10000;
      return 1;
    case 3:
    case 4:
      tm->second_part= myisam_sint2korr(ptr) * 100;
      return 2;
    case 5:
    case 6:
      tm->second_part= myisam_sint3korr(ptr);
      return 3;
    default:
      tm->second_part= 0;
      return 0;
  }
}

MARIADB_RPL_ROW * STDCALL
mariadb_rpl_extract_rows(MARIADB_RPL *rpl,
                         MARIADB_RPL_EVENT *tm_event,
                         MARIADB_RPL_EVENT *row_event)
{
  uchar *start, *pos, *end;
  MARIADB_RPL_ROW *f_row= NULL, *p_row= NULL, *c_row= NULL;
  uint32_t column_count;
  uchar *metadata_end;

  if (!rpl || !tm_event || !row_event)
    return NULL;

  if (tm_event->event_type != TABLE_MAP_EVENT || !(IS_ROW_EVENT(row_event)))
  {
    rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Event with wrong event type passed.");
    return NULL;
  }

  if (row_event->event.rows.table_id != tm_event->event.table_map.table_id)
  {
    rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "table_id in table_map event differs.");
    return NULL;
  }

  if (!row_event->event.rows.row_data_size ||
      !row_event->event.rows.row_data)
  {
    rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Row event has no data.");
    return NULL;
  }

  column_count= tm_event->event.table_map.column_count;

  /* Protect against integer multiplication overflow and OOM loops */
  if (column_count == 0 || column_count > 0x80000) {
    rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Sanity check failed: Invalid column count");
    return NULL;
  }

  if (!tm_event->event.table_map.metadata.str || tm_event->event.table_map.metadata.length == 0)
  {
    rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Sanity check failed: Missing table map metadata");
    return NULL;
  }

  start= pos = row_event->event.rows.row_data;
  end= start + row_event->event.rows.row_data_size;

  if (!start || pos > end)
  {
    rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Invalid pointer");
    return NULL;
  }

  /* Create a strict ceiling boundary for metadata array parsing */
  metadata_end = (uchar *)tm_event->event.table_map.metadata.str + tm_event->event.table_map.metadata.length;

  while (pos < end)
  {
    uchar *n_bitmap;
    uint32_t i;
    size_t bitmap_size;

    uchar *metadata= (uchar *)tm_event->event.table_map.metadata.str;

    if (!(c_row = (MARIADB_RPL_ROW *)ma_calloc_root(&row_event->memroot, sizeof(MARIADB_RPL_ROW))) ||
        !(c_row->columns= (MARIADB_RPL_VALUE *)ma_calloc_root(&row_event->memroot,
                                                             sizeof(MARIADB_RPL_VALUE) * column_count)))
    {
      rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
      return NULL;
    }

    if (!f_row)
      f_row= c_row;
    if (p_row)
      p_row->next= c_row;

    c_row->column_count= column_count;
    n_bitmap= pos;

    /* Ensure null-bitmap footprint doesn't overshoot the row payload buffer */
     bitmap_size = (column_count + 7) / 8;
    if (pos + bitmap_size > end)
      goto malformed_packet;
    pos+= bitmap_size;

    for (i= 0; i < column_count; i++)
    {
      MARIADB_RPL_VALUE *column;
      /* Prevent table_map column_types string read overflows */
      if (!tm_event->event.table_map.column_types.str || i >= tm_event->event.table_map.column_types.length)
        goto malformed_packet;

      column= &c_row->columns[i];
      column->field_type= (uchar)tm_event->event.table_map.column_types.str[i];

      /* enum, set and string types are stored as string - first metadata
         byte contains real_type, second byte contains the length */
      if (column->field_type == MYSQL_TYPE_STRING)
      {
        if (metadata < metadata_end && (metadata[0] == MYSQL_TYPE_ENUM || metadata[0] == MYSQL_TYPE_SET))
          column->field_type = metadata[0];
      }

      if ((n_bitmap[i / 8] >> (i % 8)) & 1)
      {
        column->is_null= 1;
        metadata+= rpl_metadata_size(column->field_type);
        continue;
      }

      if (column->field_type == MYSQL_TYPE_BLOB)
      {
        if (metadata >= metadata_end)
          goto malformed_packet;
        switch(metadata[0])
        {
          case 1:
            column->field_type= MYSQL_TYPE_TINY_BLOB;
            break;
          case 3:
            column->field_type= MYSQL_TYPE_MEDIUM_BLOB;
            break;
          case 4:
            column->field_type= MYSQL_TYPE_LONG_BLOB;
            break;
          default:
            break;
        }
      }

      switch (column->field_type) {
        case MYSQL_TYPE_NULL:
          column->is_null = 1;
          break;

        case MYSQL_TYPE_TINY:
          if (pos + 1 > end)
            goto malformed_packet;
          column->val.ll= sint1korr(pos);
          column->val.ull= uint1korr(pos);
          pos++;
          break;

        case MYSQL_TYPE_YEAR:
          if (pos + 1 > end)
            goto malformed_packet;
          column->val.ull= uint1korr(pos++) + 1900;
          break;

        case MYSQL_TYPE_SHORT:
          if (pos + 2 > end)
            goto malformed_packet;
          column->val.ll= sint2korr(pos);
          column->val.ull= uint2korr(pos);
          pos+= 2;
          break;

        case MYSQL_TYPE_INT24:
          if (pos + 3 > end)
            goto malformed_packet;
          column->val.ll= sint3korr(pos);
          column->val.ull= uint3korr(pos);
          pos+= 3;
          break;

        case MYSQL_TYPE_LONG:
          if (pos + 4 > end)
            goto malformed_packet;
          column->val.ll= sint4korr(pos);
          column->val.ull= uint4korr(pos);
          pos+= 4;
          break;

        case MYSQL_TYPE_LONGLONG:
          if (pos + 8 > end)
            goto malformed_packet;
          column->val.ll= sint8korr(pos);
          column->val.ull= uint8korr(pos);
          pos+= 8;
          break;

        case MYSQL_TYPE_DECIMAL:
        {
          uint16_t s_len;
          if (metadata + 2 > metadata_end)
            goto malformed_packet;
          s_len = uint2korr(metadata);
          metadata += 2;
          if (pos + s_len > end)
            goto malformed_packet;
          if (rpl_alloc_set_string_and_len(row_event, &column->val.str, pos, s_len))
            goto mem_error;
          pos += s_len;
          break;
        }

        case MYSQL_TYPE_NEWDECIMAL:
        {
          uint8_t precision;
          uint8_t scale;
          uint32_t bin_size;
          decimal dec;
          char str[200];
          char buf[100];
          int s_len= sizeof(str) - 1;

          if (metadata + 2 > metadata_end)
            goto malformed_packet;

          precision= *metadata++;
          scale= *metadata++;

          if (precision < 1 || precision > 65 || scale > 30 || scale > precision)
            goto malformed_packet;

          dec.buf= (void *)buf;
          dec.len= sizeof(buf) / sizeof(decimal_digit);

          bin_size= decimal_bin_size(precision, scale);
          if (pos + bin_size > end)
            goto malformed_packet;

          bin2decimal((char *)pos, &dec, precision, scale);
          decimal2string(&dec, str, &s_len);
          pos+= bin_size;

          if (rpl_alloc_set_string_and_len(row_event, &column->val.str, str, s_len))
            goto mem_error;
          break;
        }

        case MYSQL_TYPE_FLOAT:
        case MYSQL_TYPE_DOUBLE:
        {
          uint8_t flen;

          if (metadata + 1 > metadata_end)
            goto malformed_packet;

          flen= *metadata++;

          if (pos + flen > end)
            goto malformed_packet;

          if (flen == 4)
          {
            float4get(column->val.f, pos);
          }
          else if (flen == 8)
          {
            float8get(column->val.d, pos);
          }
          else
          {
            goto malformed_packet;
          }
          pos+= flen;
          break;
        }

        case MYSQL_TYPE_BIT:
        {
          uint8_t num_bits, b_len;

          if (metadata + 2 > metadata_end)
            goto malformed_packet;

          num_bits= (metadata[0] & 0xFF) + metadata[1] * 8;
          b_len= (num_bits + 7) / 8;
          metadata+= 2;

          if (pos + b_len > end)
            goto malformed_packet;
          if (rpl_alloc_set_string_and_len(row_event, &column->val.str, pos, b_len))
            goto mem_error;
          pos+= b_len;
          break;
        }

        case MYSQL_TYPE_TIMESTAMP:
        {
          if (pos + 4 > end)
            goto malformed_packet;
          column->val.ts.second= uint4korr(pos);
          column->val.ts.second_part= 0;
          pos+= 4;
          break;
        }

        case MYSQL_TYPE_TIMESTAMP2:
        {
          MYSQL_TIME tm= {0};
          size_t sp_len;

          if (pos + 4 > end)
            goto malformed_packet;

          column->val.ts.second= myisam_uint4korr(pos);
          pos+= 4;

          if (metadata >= metadata_end)
            goto malformed_packet;

          sp_len = ma_rpl_get_second_part(&tm, pos, metadata);
          if (pos + sp_len > end)
            goto malformed_packet;
          pos+= sp_len;
          metadata++;
          column->val.ts.second_part= tm.second_part;
          break;
        }

        case MYSQL_TYPE_NEWDATE:
        {
          MYSQL_TIME *tm = &column->val.tm;
          uint32_t d_val;

          if (pos + 3 > end)
            goto malformed_packet;

          d_val = uint3korr(pos);
          pos += 3;
          tm->day = d_val & 31;
          tm->month = (d_val >> 5) & 15;
          tm->year = d_val >> 9;
          tm->time_type = MYSQL_TIMESTAMP_DATE;
          break;
        }

        case MYSQL_TYPE_DATE:
        {
          MYSQL_TIME *tm= &column->val.tm;
          uint32_t d_val;

          if (pos + 3 > end)
            goto malformed_packet;

          d_val= uint3korr(pos);
          pos+= 3;
          tm->year= (int)(d_val / (16 * 32));
          tm->month= (int)(d_val / 32 % 16);
          tm->day= d_val % 32;
          tm->time_type= MYSQL_TIMESTAMP_DATE;
          break;
        }

        case MYSQL_TYPE_TIME:
        {
          MYSQL_TIME *tm = &column->val.tm;
          uint32_t t_val;

          if (pos + 3 > end)
            goto malformed_packet;

          t_val = uint3korr(pos);
          pos += 3;
          tm->hour = t_val / 10000;
          tm->minute = (t_val / 100) % 100;
          tm->second = t_val % 100;
          tm->time_type = MYSQL_TIMESTAMP_TIME;
          break;
        }

        case MYSQL_TYPE_TIME2:
        {
          MYSQL_TIME *tm= &column->val.tm;
          int64_t t_val;
          size_t sp_len;

          if (pos + 3 > end)
            goto malformed_packet;

          t_val= myisam_uint3korr(pos) - 0x800000LL;

          if ((tm->neg = t_val < 0))
            t_val= -t_val;

          pos+= 3;
          tm->hour= (t_val >> 12) % (1 << 10);
          tm->minute= (t_val >> 6) % (1 << 6);
          tm->second= t_val % (1 << 6);

          if (metadata >= metadata_end)
             goto malformed_packet;
          sp_len = ma_rpl_get_second_part(tm, pos, metadata);
          if (pos + sp_len > end)
            goto malformed_packet;
          pos+= sp_len;
          metadata++;
          tm->time_type= MYSQL_TIMESTAMP_TIME;
          column->field_type= MYSQL_TYPE_TIME;
          break;
        }

        case MYSQL_TYPE_DATETIME:
        {
          MYSQL_TIME *tm = &column->val.tm;
          uint64_t t;
          uint32_t d_val, t_val;

          if (pos + 8 > end)
            goto malformed_packet;
          t = uint8korr(pos);
          pos += 8;
          d_val = (uint32_t)(t / 1000000);
          t_val = (uint32_t)(t % 1000000);
          tm->year = d_val / 10000;
          tm->month = (d_val / 100) % 100;
          tm->day = d_val % 100;
          tm->hour = t_val / 10000;
          tm->minute = (t_val / 100) % 100;
          tm->second = t_val % 100;
          tm->time_type = MYSQL_TIMESTAMP_DATETIME;
          break;
        }

        case MYSQL_TYPE_DATETIME2:
        {
          MYSQL_TIME *tm= &column->val.tm;
          uint64_t dt_val, date_part, time_part;
          size_t sp_len;

          if (pos + 5 > end)
            goto malformed_packet;
          dt_val= mi_uint5korr(pos) - 0x8000000000LL;
          pos+= 5;

          date_part= dt_val >> 17;
          time_part= dt_val % (1 << 17);

          tm->day= (unsigned int)date_part % (1 << 5);
          tm->month= (unsigned int)(date_part >> 5) % 13;
          tm->year= (unsigned int)(date_part >> 5) / 13;

          tm->second= time_part % (1 << 6);
          tm->minute= (time_part >> 6) % (1 << 6);
          tm->hour= (uint32_t)(time_part >> 12);

          tm->time_type= MYSQL_TIMESTAMP_DATETIME;
          column->field_type= MYSQL_TYPE_DATETIME;

          if (metadata >= metadata_end)
            goto malformed_packet;
          sp_len = ma_rpl_get_second_part(tm, pos, metadata);
          if (pos + sp_len > end)
            goto malformed_packet;
          pos+= sp_len;
          metadata++;
          break;
        }

        case MYSQL_TYPE_STRING:
        {
          uint8_t s_len;

          if (metadata + 3 > metadata_end)
            goto malformed_packet;

          s_len= metadata[2];
          metadata+= 2;

          if (pos + s_len > end)
            goto malformed_packet;

          if (rpl_alloc_set_string_and_len(row_event, &column->val.str, pos, s_len))
            goto mem_error;
          pos+= s_len;
          break;
        }

        case MYSQL_TYPE_ENUM:
        case MYSQL_TYPE_SET:
        {
          uint8_t e_len;

          if (metadata + 3 > metadata_end)
            goto malformed_packet;
          e_len= metadata[2];
          metadata+= 2;

          if (e_len > 8 || pos + e_len > end)
            goto malformed_packet;
          column->val.ull= uintNkorr(e_len, pos);
          pos+= e_len;
          break;
        }

        case MYSQL_TYPE_JSON:
        case MYSQL_TYPE_GEOMETRY:
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB:
        case MYSQL_TYPE_BLOB:
        {
          uint8_t h_len;
          uint64_t b_len;

          if (metadata + 1 > metadata_end)
            goto malformed_packet;

          h_len= *metadata++;

          if (pos + h_len > end)
            goto malformed_packet;
          b_len= uintNkorr(h_len, pos);
          pos+= h_len;

          if (pos + b_len > end)
            goto malformed_packet;
          if (rpl_alloc_set_string_and_len(row_event, &column->val.str, pos, (size_t)b_len))
            goto mem_error;
          pos+= b_len;
          break;
        }

        case MYSQL_TYPE_VARCHAR:
        case MYSQL_TYPE_VAR_STRING:
        {
          uint32_t s_len;
          uint8_t byte_len;

          if (metadata + 2 > metadata_end)
            goto malformed_packet;

          s_len= uint2korr(metadata);
          byte_len= rpl_byte_size(s_len);
          metadata+= 2;

          if (pos + byte_len > end)
            goto malformed_packet;
          s_len= (uint32_t)uintNkorr(byte_len, pos);
          pos+= byte_len;

          if (pos + s_len > end)
            goto malformed_packet;
          if (rpl_alloc_set_string_and_len(row_event, &column->val.str, pos, s_len))
            goto mem_error;
          pos+= s_len;
          break;
        }

        default:
          goto malformed_packet;
      }
    }
    p_row= c_row;
  }
  return f_row;

malformed_packet:
  rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Malformed row data packet stream.");
  return NULL;

mem_error:
  rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
  return NULL;
}

MARIADB_RPL * STDCALL mariadb_rpl_init_ex(MYSQL *mysql, unsigned int version)
{
  MARIADB_RPL *rpl;

  if (version < MARIADB_RPL_REQUIRED_VERSION ||
      version > MARIADB_RPL_VERSION)
  {
    if (mysql)
      my_set_error(mysql, CR_VERSION_MISMATCH, SQLSTATE_UNKNOWN, 0, version,
                   MARIADB_RPL_VERSION, MARIADB_RPL_REQUIRED_VERSION);
    return 0;
  }

  if (!(rpl= (MARIADB_RPL *)calloc(1, sizeof(MARIADB_RPL))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    return 0;
  }
  rpl->version= version;

  if ((rpl->mysql= mysql))
  {
    MYSQL_RES *result;
    if (!mysql_query(mysql, "select @@binlog_checksum"))
    {
      if ((result= mysql_store_result(mysql)))
      {
        MYSQL_ROW row= mysql_fetch_row(result);
        if (!strcmp(row[0], "CRC32"))
        {
          rpl->artificial_checksum= 1;
        }
        mysql_free_result(result);
      }
    }
  }

  /* recommended way to set replica host and port is via rpl_optionsv(), however if
     hostname and port was set via mysql_optionsv, we set it here to rpl */
  if (rpl->mysql && rpl->mysql->options.extension && rpl->mysql->options.extension->rpl_host)
  {
    mariadb_rpl_optionsv(rpl, MARIADB_RPL_HOST, rpl->mysql->options.extension->rpl_host);
    mariadb_rpl_optionsv(rpl, MARIADB_RPL_PORT, rpl->mysql->options.extension->rpl_port);
  }
  return rpl;
}

void STDCALL mariadb_free_rpl_event(MARIADB_RPL_EVENT *event)
{
  if (event)
  {
    ma_free_root(&event->memroot, MYF(0));
    free(event);
  }
}

int STDCALL mariadb_rpl_open(MARIADB_RPL *rpl)
{
  unsigned char *ptr, *buf;

  if (!rpl)
    return 1;

  /* COM_BINLOG_DUMP:
     Ofs  Len Data
     0      1 COM_BINLOG_DUMP
     1      4 position
     5      2 flags
     7      4 server id
     11     * filename

     * = filename length

  */
  rpl_clear_error(rpl);

  /* if replica was specified, we will register replica via
     COM_REGISTER_SLAVE */
  if (rpl->host)
  {
     /* Protocol:
        Ofs  Len  Data
        0      1  COM_REGISTER_SLAVE
        1      4  server id
        5      1  replica host name length
        6     <n> replica host name
               1  user name length
              <n> user name
               1  password length
              <n> password
               2  replica port
               4  replication rank (unused)
               4  source server id (unused)
      */
     unsigned char *p, buffer[1024];
     size_t len= MIN(strlen(rpl->host), 255);

     p= buffer;
     int4store(p, rpl->server_id);
     p+= 4;
     *p++= (unsigned char)len;
     memcpy(p, rpl->host, len);
     p+= len;

     /* Don't send user, password, rank and server_id */
     *p++= 0;
     *p++= 0;
     int2store(p, rpl->port);
     p+= 2;

     int4store(p, 0);
     p+= 4;
     int4store(p, 0);
     p+= 4;

     if (ma_simple_command(rpl->mysql, COM_REGISTER_SLAVE, (const char *)buffer, p - buffer, 0, 0))
     {
       rpl_set_error(rpl, mysql_errno(rpl->mysql), 0, NULL, 0);
       return 1;
     }
  }

  if (rpl->mysql)
  {
    uint32_t replica_id= rpl->server_id;
    ptr= buf= (unsigned char *)alloca(rpl->filename_length + 11);

    if (!ptr)
    {
      rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
    }

    if (rpl->is_semi_sync)
    {
      if (mysql_query(rpl->mysql, "SET @rpl_semi_sync_slave=1"))
      {
        rpl_set_error(rpl, mysql_errno(rpl->mysql), 0, mysql_error(rpl->mysql));
        return 1;
      }
    }
    else {
      MYSQL_RES* result;
      MYSQL_ROW row;
      if (mysql_query(rpl->mysql, "SELECT @rpl_semi_sync_slave=1"))
      {
        rpl_set_error(rpl, mysql_errno(rpl->mysql), 0, mysql_error(rpl->mysql));
        return 1;
      }
      if ((result = mysql_store_result(rpl->mysql)))
      {
        if ((row = mysql_fetch_row(result)))
          rpl->is_semi_sync = (row[0] != NULL && row[0][0] == '1');
        mysql_free_result(result);
      }
    }

    int4store(ptr, (unsigned int)rpl->start_position);
    ptr+= 4;
    int2store(ptr, rpl->flags);
    ptr+= 2;
    if ((rpl->flags & MARIADB_RPL_BINLOG_DUMP_NON_BLOCK) && !replica_id)
      replica_id= 1;
    int4store(ptr, replica_id);
    ptr+= 4;
    memcpy(ptr, rpl->filename, rpl->filename_length);
    ptr+= rpl->filename_length;

    return (ma_simple_command(rpl->mysql, COM_BINLOG_DUMP, (const char *)buf, ptr - buf, 1, 0));
  } else
  {
    char *buf[RPL_BINLOG_MAGIC_SIZE];
    MYSQL mysql;

    /* Semi sync doesn't work when processing files */
    rpl->is_semi_sync = 0;

    if (rpl->fp)
      ma_close(rpl->fp);

    if (!(rpl->fp= ma_open((const char *)rpl->filename, "r", &mysql)))
    {
      rpl_set_error(rpl, CR_FILE_NOT_FOUND, 0, rpl->filename, errno);
      return errno;
    }

    if (ma_read(buf, 1, RPL_BINLOG_MAGIC_SIZE, rpl->fp) != 4)
    {
      rpl_set_error(rpl, CR_FILE_READ, 0, rpl->filename, errno);
      return errno;
    }

    /* check if it is a valid binlog file */
    if (memcmp(buf, RPL_BINLOG_MAGIC, RPL_BINLOG_MAGIC_SIZE) != 0)
    {
      rpl_set_error(rpl, CR_BINLOG_INVALID_FILE, 0, rpl->filename, errno);
      return errno;
    }

    return 0;
  }
}

static int ma_set_rpl_filename(MARIADB_RPL *rpl, const unsigned char *filename, size_t len)
{
  if (!rpl)
    return 1;
  free(rpl->filename);
  if (!(rpl->filename= (char *)malloc(len)))
    return 1;
  memcpy(rpl->filename, filename, len);
  rpl->filename_length= (uint32_t)len;
  return 0;
}

/*
 * Returns compression info:
 *    Ofs  Len
 *      0    1          header:
 *                        ofs & 0x07 >> 4: algorithm, always 0=zlib
 *                        ofs & 0x07: header size
 *      1  header size  uncompressed length in MyISAM format.
 */
static uint32_t get_compression_info(const unsigned char *buf,
                                     uint8_t *algorithm,
                                     uint8_t *header_size)
{
  uint8_t alg, header;
  uint32 len= 0;

  if (!algorithm)
    algorithm= &alg;
  if (!header_size)
    header_size= &header;

  *header_size= 0;
  *algorithm= 0;

  if (!buf)
    return len;

  if ((buf[0] & 0xe0) != 0x80)
    return len;

  *header_size= buf[0] & 0x07;
  *algorithm = (buf[0] & 0x07) >> 4;

  buf++;

  /* Attention: we can't use uint*korr, here, we need myisam macros since
     length is stored in high byte first order
   */
  switch(*header_size) {
  case 1:
    len= *buf;
    break;
  case 2:
    len= myisam_uint2korr(buf);
    break;
  case 3:
    len= myisam_uint3korr(buf);
    break;
  case 4:
    len= myisam_uint4korr(buf);
    break;
  default:
    len= 0;
    break;
  }

  *header_size += 1;
  return len;
}

static uint8_t mariadb_rpl_send_semisync_ack(MARIADB_RPL* rpl, MARIADB_RPL_EVENT* event)
{
  size_t buf_size = 0;
  uchar* buf = NULL;
  uchar stack_buf[512]; /* Safe, bounded stack-allocated workspace buffer */
  uint8_t error_code = 0;

  if (!rpl)
    return 1;

  if (!event)
  {
    rpl_set_error(rpl, CR_BINLOG_SEMI_SYNC_ERROR, 0, "Invalid event");
    return 1;
  }

  /* Structural network pointer health validation */
  if (!rpl->mysql)
  {
    rpl_set_error(rpl, CR_CONNECTION_ERROR, 0, "Database connection handle is invalid");
    return 1;
  }

  if (!rpl->is_semi_sync)
  {
    rpl_set_error(rpl, CR_BINLOG_SEMI_SYNC_ERROR, 0, "semi synchronous replication is not enabled");
    return 1;
  }
  if (!event->is_semi_sync || (event->semi_sync_flags != SEMI_SYNC_ACK_REQ))
  {
    rpl_set_error(rpl, CR_BINLOG_SEMI_SYNC_ERROR, 0, "This event doesn't require to send semi synchronous acknowledgement");
    return 1;
  }

  /* Enforce a hard threshold sanity constraint check on the tracked file length size */
  if (rpl->filename_length > 1024 || rpl->filename == NULL)
  {
    rpl_set_error(rpl, CR_BINLOG_SEMI_SYNC_ERROR, 0, "Tracked binlog filename size is corrupted or excessively long");
    return 1;
  }

  buf_size = rpl->filename_length + 9;

  /* Dynamically route memory target safely: stack for tiny runs, heap for exceptional configurations */
  if (buf_size <= sizeof(stack_buf))
  {
    buf = stack_buf;
  }
  else
  {
    buf = (uchar*)malloc(buf_size);
    if (!buf)
    {
      rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
      return 1;
    }
  }

  buf[0] = SEMI_SYNC_INDICATOR;
  int8store(buf + 1, (uint64_t)event->next_event_pos);
  memcpy(buf + 9, rpl->filename, rpl->filename_length);

  ma_net_clear(&rpl->mysql->net);

  if (ma_net_write(&rpl->mysql->net, buf, buf_size) ||
      (ma_net_flush(&rpl->mysql->net)))
  {
    rpl_set_error(rpl, CR_CONNECTION_ERROR, 0);
    error_code = 1;
  }

  /* Cleanup memory if we fallback mapped onto the heap array */
  if (buf != stack_buf)
  {
    free(buf);
  }

  return error_code;
}

MARIADB_RPL_EVENT * STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl, MARIADB_RPL_EVENT *event)
{
  unsigned char *ev= 0;
  unsigned char *checksum_start= 0;
  unsigned char *ev_start= 0;
  unsigned char *ev_end= 0;
  size_t len= 0;
  ssize_t post_header_len;
  MARIADB_RPL_EVENT *rpl_event= 0;

  if (!rpl || (!rpl->mysql && !rpl->fp))
    return 0;

  if (event)
  {
    MA_MEM_ROOT memroot= event->memroot;
    rpl_event= event;
    ma_free_root(&memroot, MYF(MY_KEEP_PREALLOC));
    memset(rpl_event, 0, sizeof(MARIADB_RPL_EVENT));
    rpl_event->memroot= memroot;
  } else {
    if (!(rpl_event = (MARIADB_RPL_EVENT *)malloc(sizeof(MARIADB_RPL_EVENT))))
      goto mem_error;
    memset(rpl_event, 0, sizeof(MARIADB_RPL_EVENT));
    ma_init_alloc_root(&rpl_event->memroot, 8192, 0);
  }

  rpl_event->rpl= rpl;

  while (1) {
    unsigned long pkt_len;

    if (rpl->mysql)
    {
      pkt_len= ma_net_safe_read(rpl->mysql);

      if (pkt_len == packet_error)
      {
        mariadb_free_rpl_event(rpl_event);
        return 0;
      }

      /* EOF packet:
         see https://mariadb.com/kb/en/library/eof_packet/
         Packet length must be less than 9 bytes, EOF header
         is 0xFE.
      */
      if (pkt_len < 9 && rpl->mysql->net.read_pos[0] == 0xFE)
      {
        mariadb_free_rpl_event(rpl_event);
        return 0;
      }

    /* if ignore heartbeat flag was set, we ignore this
       record and continue to fetch next record.
       The first byte is always status byte (0x00)
       For event header description see
       https://mariadb.com/kb/en/library/2-binlog-event-header/ */
      if (rpl->flags & MARIADB_RPL_IGNORE_HEARTBEAT)
      {
        if (rpl->mysql->net.read_pos[1 + 4] == HEARTBEAT_LOG_EVENT)
          continue;
      }

      if (!(rpl_event->raw_data= ma_alloc_root(&rpl_event->memroot, pkt_len)))
        goto mem_error;

      rpl_event->raw_data_size= pkt_len;
      memcpy(rpl_event->raw_data, rpl->mysql->net.read_pos, pkt_len);
      ev= rpl_event->raw_data;
    } else if (rpl->fp) {
      char buf[EVENT_HEADER_OFS]; /* header */
      size_t rc;
      uint32_t len= 0;
      char *p= buf;

      if (ma_feof(rpl->fp))
      {
        mariadb_free_rpl_event(rpl_event);
        return NULL;
      }

      memset(buf, 0, EVENT_HEADER_OFS);
      if ((rc= ma_read(buf, 1, EVENT_HEADER_OFS, rpl->fp)) != EVENT_HEADER_OFS)
      {
         rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Can't read event header");
         mariadb_free_rpl_event(rpl_event);
         return NULL;
      }
      len= uint4korr(p + 9);

      if (len < EVENT_HEADER_OFS ||
          len > MAX_PACKET_LENGTH)
      {
        rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Sanity check failed: Malformed event length");
        mariadb_free_rpl_event(rpl_event);
        return NULL;
      }

      if (!(rpl_event->raw_data= ma_alloc_root(&rpl_event->memroot, len)))
      {
        rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
        mariadb_free_rpl_event(rpl_event);
        return NULL;
      }

      rpl_event->raw_data_size= len;
      memcpy(rpl_event->raw_data, buf, EVENT_HEADER_OFS - 1);
      len-= (EVENT_HEADER_OFS - 1);
      rc= ma_read(rpl_event->raw_data + EVENT_HEADER_OFS - 1, 1, len, rpl->fp);
      if (rc != len)
      {
        rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl), "Error while reading post header");
        mariadb_free_rpl_event(rpl_event);
        return NULL;
      }
      ev= rpl_event->raw_data;

          /* We don't decrypt yet */
      if (rpl->encrypted) {
        return rpl_event;
      }
    }

    ev_end= rpl_event->raw_data + rpl_event->raw_data_size;


    if (rpl->mysql)
    {
      RPL_CHECK_POS(ev, ev_end, 1);
      rpl_event->ok= *ev++;

      /* CONC-470: add support for semi synchronous replication */
      if (rpl->is_semi_sync && (rpl_event->is_semi_sync= (*ev == SEMI_SYNC_INDICATOR)))
      {
        RPL_CHECK_POS(ev, ev_end, 1);
        ev++;
        rpl_event->semi_sync_flags= *ev++;
      }
    }
    rpl_event->raw_data_ofs= ev - rpl_event->raw_data;

    /* check sum verification:
       check sum will be calculated from begin of binlog header
     */
    checksum_start= ev;

    /******************************************************************
     Binlog event header:

     All binary log events have the same header:
      - uint32_t timestamp: creation time
      - uint8_t event_type: type code of the event
      - uint32_t server_id: server which created the event
      - uint32_t event_len: length of the event. If checksum is
                            enabled, the length also include 4 bytes
                            of checksum
      ------------- if START_ENCRYPTION_EVENT was sent, ---------------
                    encrypted part starts here:
      - uint32_t next_pos:  Position of next binary log event
      - uint16_t flags:     flags

     The size of binlog event header must match the header size returned
     by FORMAT_DESCIPTION_EVENT. In version 4 it is always 19.
    ********************************************************************/
    RPL_CHECK_POS(ev, ev_end, RPL_EVENT_HEADER_SIZE);
    rpl_event->timestamp= uint4korr(ev);
    ev+= 4;
    rpl_event->event_type= (unsigned char)*ev++;
    rpl_event->server_id= uint4korr(ev);
    ev+= 4;
    rpl_event->event_length= uint4korr(ev);
    ev+= 4;
    rpl_event->next_event_pos= uint4korr(ev);
    ev+= 4;
    rpl_event->flags= uint2korr(ev);
    ev+=2;
    rpl_event->checksum= 0;

    /* start of post_header */
    ev_start= ev;

    if (rpl_event->event_type >= ENUM_END_EVENT) {
      rpl_event->event_type= UNKNOWN_EVENT;
      return rpl_event;
    }

    /* Unless FORMAT_DESCRIPTION_EVENT was received,
       rpl->num_post_header_lengths will be zero  */
    if (rpl_event->event_type != UNKNOWN_EVENT &&
        rpl_event->event_type != SLAVE_EVENT &&
        rpl->num_post_header_lengths > 0)
    {
      post_header_len= get_post_header_length(rpl, rpl_event->event_type);
      if (post_header_len < 0)
        goto malformed_packet;
    } else
      post_header_len= 0; /* not known yet */

    switch(rpl_event->event_type) {
    case UNKNOWN_EVENT:
    case SLAVE_EVENT:
      return rpl_event;
    case HEARTBEAT_LOG_EVENT:
    {
      RPL_CHECK_POS(ev, ev_end, post_header_len);
      ev+= post_header_len;
      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);
      RPL_CHECK_POS(ev, ev_end, len);
      rpl_event->event.heartbeat.filename.length= len;
      rpl_event->event.heartbeat.filename.str= (char *)ev;
      ev+= len;
      break;
    }

    case BEGIN_LOAD_QUERY_EVENT:
    {
      size_t max_allowed_len= 0, slen;

      /* check post header size */
      if (post_header_len < 4)
        goto malformed_packet;

      RPL_CHECK_POS(ev, ev_end, post_header_len);

      rpl_event->event.begin_load_query.file_id= uint4korr(ev);
      ev= ev_start + post_header_len;

      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, max_allowed_len, malformed_packet);

      slen = strnlen((char *)ev, max_allowed_len);

      if (slen == max_allowed_len)
        goto malformed_packet;

      rpl_event->event.begin_load_query.data= ev;
      ev += slen;

      /* terminating zero */
      RPL_CHECK_POS(ev, ev_end, 1);
      ev++; // @infer-ignore DEAD_STORE
      break;
    }

    case START_ENCRYPTION_EVENT:
      /* No post header */
      RPL_CHECK_POS(ev, ev_end, 17);
      rpl_event->event.start_encryption.scheme= *ev++;
      rpl_event->event.start_encryption.key_version= uint4korr(ev);
      ev+= 4;
      memcpy(rpl_event->event.start_encryption.nonce, ev, 12);
      memcpy(rpl->nonce, ev, 12);
      ev+= 12; // @infer-ignore DEAD_STORE
      rpl->encrypted= 1;
      break;

    case EXECUTE_LOAD_QUERY_EVENT:
    {
      uint16_t status_len;
      uint8_t schema_len;
      size_t pad;

      /* Post header */
      if (post_header_len < 26)
        goto malformed_packet;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      rpl_event->event.execute_load_query.thread_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.execute_load_query.execution_time= uint4korr(ev);
      ev+= 4;
      schema_len= *ev++;
      rpl_event->event.execute_load_query.error_code= uint2korr(ev);
      ev+= 2;
      status_len= uint2korr(ev);
      ev+= 2;
      rpl_event->event.execute_load_query.file_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.execute_load_query.ofs1= uint4korr(ev);
      ev+= 4;
      rpl_event->event.execute_load_query.ofs2= uint4korr(ev);
      ev+= 4;
      rpl_event->event.execute_load_query.duplicate_flag= *ev++;

      ev= ev_start + post_header_len;

      /* Payload:
         - status variables
         - query schema
         - statement */
      RPL_CHECK_POS(ev, ev_end, status_len);
      rpl_set_string_and_len(&rpl_event->event.execute_load_query.status_vars, ev, status_len);
      ev+= status_len;

      RPL_CHECK_POS(ev, ev_end, schema_len);
      rpl_set_string_and_len(&rpl_event->event.execute_load_query.schema, ev, schema_len);
      ev+= schema_len;
      /* terminating zero */
      RPL_CHECK_POS(ev, ev_end, 1);
      ev++;

      pad = (rpl->use_checksum ? 4 : 0) + (EVENT_HEADER_OFS - 1);
      RPL_CALC_SAFE_HDR_LEN(rpl_event->event_length, (ev - ev_start), pad, len, malformed_packet);
      RPL_CHECK_POS(ev, ev_end, len);

      rpl_set_string_and_len(&rpl_event->event.execute_load_query.statement, ev, len);
      ev+= len; // @infer-ignore DEAD_STORE
      break;
    }
    case BINLOG_CHECKPOINT_EVENT:
    {
      size_t pad;
      uint32_t payload_len;

      if (post_header_len < 4)
        goto malformed_packet;

      /* Post header */
      RPL_CHECK_POS(ev, ev_end, post_header_len);
      payload_len= uint4korr(ev);
      ev= ev_start + post_header_len;

      /* payload: filename */
      pad = (rpl->use_checksum ? 4 : 0) + (EVENT_HEADER_OFS - 1);
      RPL_CALC_SAFE_HDR_LEN(rpl_event->event_length, (ev - ev_start), pad, len, malformed_packet);

      if ((size_t)payload_len > len)
        goto malformed_packet;

      len= payload_len;

      rpl_set_string_and_len(&rpl_event->event.checkpoint.filename, ev, len);
      if (ma_set_rpl_filename(rpl, ev, len))
        goto mem_error;
      ev+= len; // @infer-ignore DEAD_STORE
      break;
    }

    case FORMAT_DESCRIPTION_EVENT:
    {
      /*
         FORMAT_DESCRIPTION_EVENT:

         Header:
           uint<2>     binary log version
                       (we support only version 4)
           str<50>     server version, right padded with \0
           uint<4>     timestamp <redundant>
           uint<1>     header length
           byte<n>     post header lengths. Length can be calculated by
                       ev_end - end - 1 - 4
           uint<1>     check sum algorithm byte
           uint<4>     CRC32 checksum
       */


      /* We don't speak bing log protocol version < 4, in case it's an older
         protocol version an error will be returned. */
      ushort binlog_format;
      uint32_t mysql_fd_header_len, mariadb_fd_header_len;
      size_t total_payload= (size_t)(ev_end - ev);

      if (total_payload < 57)
        goto malformed_packet;

      mysql_fd_header_len = get_min_expected_header_len(FORMAT_DESCRIPTION_EVENT, RPL_SERVER_MYSQL);   /* 98 */
      mariadb_fd_header_len = get_min_expected_header_len(FORMAT_DESCRIPTION_EVENT, RPL_SERVER_MARIADB); /* 228 */

      if (ev[56] != 19)
        goto malformed_packet;

      if (total_payload < mysql_fd_header_len)
        goto malformed_packet;
      if (total_payload < mariadb_fd_header_len)
        rpl->server_type= RPL_SERVER_MYSQL;
      else
        rpl->server_type= RPL_SERVER_MARIADB;

      binlog_format= uint2korr(ev);
      if ((rpl_event->event.format_description.format = binlog_format) < 4)
      {
        mariadb_free_rpl_event(rpl_event);
        rpl_set_error(rpl, CR_ERR_UNSUPPORTED_BINLOG_FORMAT, SQLSTATE_UNKNOWN, 0,
                     RPL_ERR_POS(rpl), binlog_format);
        return 0;
      }

      ev+= 2;
      rpl_event->event.format_description.server_version = (char *)(ev);
      /* for safety, we append a '\0' */
      ev[49]= 0;
      ev+= 50;
      rpl_event->event.format_description.timestamp= uint4korr(ev);
      ev+= 4;
      rpl->fd_header_len= rpl_event->event.format_description.header_len= *ev;
      ev+= 1;
      /*Post header lengths: 1 byte for each event, non-used events/gaps in enum should
                             have a zero value */
      RPL_CHECK_POS(ev, ev_end, 5);
      len = ev_end - ev - 5;

      rpl_set_string_and_len(&rpl_event->event.format_description.post_header_lengths, ev, len);
      memset(rpl->post_header_len, 0, ENUM_END_EVENT);

      if (len > 0)
      {
        /* upper boundary */
        size_t max_allowed_events = (rpl->server_type == RPL_SERVER_MYSQL) ?
                                    MYSQL_EVENTS_END : ENUM_END_EVENT;
        size_t max_copy = MIN(len, max_allowed_events);

        rpl->num_post_header_lengths= (uint16_t)max_copy;

        /* check required minimum lengths */
        for (size_t idx = 0; idx < max_copy; idx++)
        {
          uint8_t current_event_id = (uint8_t)(idx + 1);
          uint8_t declared_len = ev[idx];
          uint32_t min_header_len = get_min_expected_header_len(current_event_id, rpl->server_type);

          if (declared_len > 0 && (uint32_t)declared_len < min_header_len)
            goto malformed_packet;
        }

        /* copy lengths */
        memcpy(rpl->post_header_len, rpl_event->event.format_description.post_header_lengths.str, max_copy);

        ev += len;
      }

      RPL_CHECK_POS(ev, ev_end, 5);
      if ((rpl->use_checksum= *ev++))
      {
        rpl_event->checksum= uint4korr(ev);
        ev+= 4; // @infer-ignore DEAD_STORE
      }
      break;
    }

    case QUERY_COMPRESSED_EVENT:
    case QUERY_EVENT:
    {
      size_t db_len, status_len, pad;
      uchar *post_header_start= ev;

      /***********
       post_header
       ***********/
      RPL_CHECK_POS(ev, ev_end, post_header_len);

      rpl_event->event.query.thread_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.query.seconds= uint4korr(ev);
      ev+= 4;
      db_len= *ev;
      ev++;
      rpl_event->event.query.errornr= uint2korr(ev);
      ev+= 2;
      status_len= uint2korr(ev);
      ev+= 2;

      ev= post_header_start + post_header_len;

      /*******
       payload
       ******/
      if (status_len > 0) {
        RPL_CHECK_POS(ev, ev_end, status_len);
        rpl_set_string_and_len(&rpl_event->event.query.status, ev, status_len);
        ev+= status_len;
      } else {
        rpl_set_string_and_len(&rpl_event->event.query.status, NULL, 0);
      }

      if (db_len > 0) {
        RPL_CHECK_POS(ev, ev_end, db_len);
        rpl_set_string_and_len(&rpl_event->event.query.database, ev, db_len);
        ev+= db_len;
      } else {
        rpl_set_string_and_len(&rpl_event->event.query.database, NULL, 0);
      }

      RPL_CHECK_POS(ev, ev_end, 1);
      ev++;

      pad = (rpl->use_checksum ? 4 : 0) + (EVENT_HEADER_OFS - 1);
      RPL_CALC_SAFE_HDR_LEN(rpl_event->event_length, (ev - ev_start), pad, len, malformed_packet);
      RPL_CHECK_POS(ev, ev_end, len);

      if (rpl_event->event_type == QUERY_EVENT || !rpl->uncompress) {
        rpl_set_string_and_len(&rpl_event->event.query.statement, ev, len);
      }
      else if (rpl_event->event_type == QUERY_COMPRESSED_EVENT)
      {
        uint8_t header_size= 0,
                algorithm= 0;
        uLongf source_len, dest_len;

        uint32_t uncompressed_len= get_compression_info(ev, &algorithm, &header_size);

        if (header_size >= len || len < header_size ||
            uncompressed_len == 0 ||
            uncompressed_len > MAX_PACKET_LENGTH)
        {
          mariadb_free_rpl_event(rpl_event);
          rpl_set_error(rpl, CR_ERR_BINLOG_UNCOMPRESS, SQLSTATE_UNKNOWN, RPL_ERR_POS(rpl));
          return 0;
        }
        source_len= (uLongf)(len - header_size);
        dest_len= (uLongf)uncompressed_len;

        if (!(rpl_event->event.query.statement.str = ma_calloc_root(&rpl_event->memroot, uncompressed_len)))
          goto mem_error;

        if ((uncompress((Bytef*)rpl_event->event.query.statement.str, &dest_len,
           (Bytef*)ev + header_size, source_len) != Z_OK))
        {
          mariadb_free_rpl_event(rpl_event);
          rpl_set_error(rpl, CR_ERR_BINLOG_UNCOMPRESS, SQLSTATE_UNKNOWN, RPL_ERR_POS(rpl));
          return 0;
        }
        rpl_event->event.query.statement.length= uncompressed_len;
      }
      break;
    }
    case TABLE_MAP_EVENT:
    {
      /*
         TABLE_MAP_EVENT:

         Header:
           uint<6>   table_id
           uint<2>   unused

         Payload:
           uint<1>   schema_name length
           str<NULL> schema_name (zero terminated)
           uint<1>   table_name length
           str<NULL> table_name (zero terminated)
           int<lenc> column_count
           byte<n>   column_types[column_count], 1 byte for
                     each column
           int<lenc> meta_data_size
           byte<n>   netadata[metadata_size]
           byte<n>   bit fields, indicating which column can be null
                     n= (column_count + 7) / 8;

           if (remaining_bytes)
               byte<n>  optional metadata
      */
      size_t db_len, table_len;
      size_t metadata_len;
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);

      /* Post header */
      rpl_event->event.table_map.table_id= uint6korr(ev);
      ev+= 8;  /* 2 byte in header ignored */

      ev= post_header_start + post_header_len;

      /* Payload: Database Name */
      RPL_CHECK_POS(ev, ev_end, 1);
      db_len= *ev++;
      RPL_CHECK_POS(ev, ev_end, db_len + 1);

      if (ev[db_len] != 0)
        goto malformed_packet;

      rpl_set_string_and_len(&rpl_event->event.table_map.database, ev, db_len);
      ev+= db_len + 1;

      /* Payload: Table Name */
      RPL_CHECK_POS(ev, ev_end, 1);
      table_len= *ev++;
      RPL_CHECK_POS(ev, ev_end, table_len + 1);

      if (ev[table_len] != 0)
        goto malformed_packet;

      rpl_set_string_and_len(&rpl_event->event.table_map.table, ev, table_len);
      ev+= table_len + 1;

      /* Column Count (Max 4096 columns) */
      RPL_CHECK_FIELD_LENGTH(ev, ev_end);
      len= mysql_net_field_length(&ev);
      if (len > 4096)
        goto malformed_packet;

      rpl_event->event.table_map.column_count= (uint32_t)len;
      RPL_CHECK_POS(ev, ev_end, len);
      rpl_set_string_and_len(&rpl_event->event.table_map.column_types, ev, len);
      ev+= len;

      /* Metadata Size */
      RPL_CHECK_FIELD_LENGTH(ev, ev_end);
      metadata_len= mysql_net_field_length(&ev);
      RPL_CHECK_POS(ev, ev_end, metadata_len);
      rpl_set_string_and_len(&rpl_event->event.table_map.metadata, ev, metadata_len);
      ev+= metadata_len;

      /* Null-Bitmap */
      len= (rpl_event->event.table_map.column_count + 7) / 8;
      RPL_CHECK_POS(ev, ev_end, len);
      rpl_event->event.table_map.null_indicator= ev;
      ev+= len;

      /* Optional Metadata */
      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);

      if (len > 0)
      {
        rpl_parse_opt_metadata(rpl_event, ev, len);
        ev+= len;
      }
      break;
    }

    case RAND_EVENT:
    {
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);

      /* no post header data processed */

      ev= post_header_start + post_header_len;

      RPL_CHECK_POS(ev, ev_end, 16);
      rpl_event->event.rand.first_seed= uint8korr(ev);
      ev+= 8;
      rpl_event->event.rand.second_seed= uint8korr(ev);
      ev+= 8; // @infer-ignore DEAD_STORE
      break;
    }

    case INTVAR_EVENT:
    {
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;

      RPL_CHECK_POS(ev, ev_end, 9);
      rpl_event->event.intvar.type= *ev;
      ev++;
      rpl_event->event.intvar.value= uint8korr(ev);
      ev+= 8; // @infer-ignore DEAD_STORE
      break;
    }

    case USER_VAR_EVENT:
    {
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;
      RPL_CHECK_POS(ev, ev_end, 4);
      len= uint4korr(ev);
      ev+= 4;
      RPL_CHECK_POS(ev, ev_end, len);
      rpl_set_string_and_len(&rpl_event->event.uservar.name, ev, len);
      ev+= len;

      RPL_CHECK_POS(ev, ev_end, 1);
      if (!(rpl_event->event.uservar.is_null= (uint8)*ev))
      {
        ev++;
        RPL_CHECK_POS(ev, ev_end, 9);
        rpl_event->event.uservar.type= *ev;
        ev++;
        rpl_event->event.uservar.charset_nr= uint4korr(ev);
        ev+= 4;
        len= uint4korr(ev);
        ev+= 4;

        RPL_CHECK_POS(ev, ev_end, len);

        if (rpl_event->event.uservar.type == DECIMAL_RESULT)
        {
          char str[200];
          int s_len= sizeof(str) - 1;
          int precision, scale;
          decimal d;
          decimal_digit buf[10];
          size_t bin_size;

          RPL_CHECK_POS(ev, ev_end, 2);

          precision= (int)ev[0];
          scale= (int)ev[1];

          if (precision < 1 || precision > 65 || scale < 0 || scale > 30 || scale > precision)
            goto malformed_packet;

          d.len= 10;
          d.buf= buf;

          bin_size = decimal_bin_size(precision, scale);

          RPL_CHECK_POS(ev, ev_end, 2 + bin_size);

          bin2decimal((char *)(ev+2), &d, precision, scale);
          decimal2string(&d, str, &s_len);
          if (!(rpl_event->event.uservar.value.str =
                (char *)ma_calloc_root(&rpl_event->memroot, s_len)))
            goto mem_error;
          memcpy(rpl_event->event.uservar.value.str, str, s_len);
          rpl_event->event.uservar.value.length= s_len;
        }
        else if (rpl_event->event.uservar.type == INT_RESULT)
        {
          uint64_t val64;
          RPL_CHECK_POS(ev, ev_end, 8);

          if (!(rpl_event->event.uservar.value.str =
                (char *)ma_calloc_root(&rpl_event->memroot, sizeof(longlong))))
            goto mem_error;
          val64= uint8korr(ev);
          memcpy(rpl_event->event.uservar.value.str, &val64, sizeof(uint64_t));
          rpl_event->event.uservar.value.length= sizeof(uint64_t);
        }
        else if (rpl_event->event.uservar.type == REAL_RESULT)
        {
          double d;
          RPL_CHECK_POS(ev, ev_end, 8);

          float8get(d, ev);
          if (!(rpl_event->event.uservar.value.str =
                (char *)ma_calloc_root(&rpl_event->memroot, 24)))
            goto mem_error;
          memset(rpl_event->event.uservar.value.str, 0, 24);
          snprintf(rpl_event->event.uservar.value.str, 24, "%.14g", d);
          rpl_event->event.uservar.value.length= strlen(rpl_event->event.uservar.value.str);
        }
        else
        {
          rpl_set_string_and_len(&rpl_event->event.uservar.value, ev, len);
        }

        ev+= len;

        if ((unsigned long)(ev - rpl_event->raw_data) < rpl_event->raw_data_size)
        {
          RPL_CHECK_POS(ev, ev_end, 1);
          rpl_event->event.uservar.flags= *ev;
          ev++; // @infer-ignore DEAD_STORE
        }
      }
      break;
    }

    case ANNOTATE_ROWS_EVENT:
    {
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;
      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);

      if (len > 0)
        rpl_set_string_and_len(&rpl_event->event.annotate_rows.statement, ev, len);
    }
    break;

    case ROTATE_EVENT:
    {
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;

      /* 1. Position (8 Bytes) */
      rpl_event->event.rotate.position= uint8korr(ev);
      ev+= 8;

      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);

      if (len == 0)
        goto malformed_packet;

      if (rpl_event->timestamp == 0 &&
          rpl_event->flags & LOG_EVENT_ARTIFICIAL_F)
      {
        if (rpl->artificial_checksum)
        {
          unsigned long crc= crc32(0L, Z_NULL, 0);
          rpl_event->checksum= (uint32_t) crc32(crc, checksum_start, (uint32_t)(ev_end - checksum_start));
          if (len < 4)
            goto malformed_packet;
          len-= 4;
        }
      }

      rpl_set_string_and_len(&rpl_event->event.rotate.filename, ev, len);
      if (ma_set_rpl_filename(rpl, ev, len)) /* this crashes */
        goto mem_error;

      ev+= len; // @infer-ignore DEAD_STORE
      break;
    }
    case XID_EVENT:
    {
      /*
         XID_EVENT was generated if a transaction which modified tables was
         committed.

         Header:
           - uint64_t  transaction number
      */
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;
      RPL_CHECK_POS(ev, ev_end, 8);

      rpl_event->event.xid.transaction_nr= uint8korr(ev);
      ev+= 8;
      break;
    }
    case XA_PREPARE_LOG_EVENT:
    {
      /*
         MySQL only!

         Header:
           uint8_t   one phase commit
           uint32_t  format_id
           uint32_t  length of gtrid
           uint32_t  length of bqual

         Payload:
           char<n>   xid, where n is sum of gtrid and bqual lengths
      */
      uint32_t gtrid_len, bqual_len;
      uchar *post_header_start= ev;
      size_t remain;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;

      RPL_CHECK_POS(ev, ev_end, 13);

      rpl_event->event.xa_prepare_log.one_phase= *ev;
      ev++;
      rpl_event->event.xa_prepare_log.format_id= uint4korr(ev);
      ev+= 4;
      gtrid_len= rpl_event->event.xa_prepare_log.gtrid_len= uint4korr(ev);
      ev+= 4;
      bqual_len= rpl_event->event.xa_prepare_log.bqual_len= uint4korr(ev);
      ev+= 4;

      remain= (size_t)(ev_end - ev);
      if (remain < gtrid_len || remain - gtrid_len < bqual_len)
        goto malformed_packet;

      len = (size_t)gtrid_len + (size_t)bqual_len;

      RPL_CHECK_POS(ev, ev_end, len);
      rpl_set_string_and_len(&rpl_event->event.xa_prepare_log.xid, ev, len);
      ev+= len;
      break;
    }

    case STOP_EVENT:
    {
      /*
         STOP_EVENT - server shutdown or crash. It's always the last written
         event after shutdown or after resuming from crash.

         After starting the server a new binary log file will be created, additionally
         a ROTATE_EVENT will be appended to the old log file.

         No data to process.
      */
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;
      break;
    }
    case PREVIOUS_GTIDS_LOG_EVENT:
    {
      /*
         PREVIOUS_GTID_LOG_EVENT (MySQL only):

         8-bytes, always zero ?!
      */
      uchar *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);
      /* no post header data processed */
      ev= post_header_start + post_header_len;

      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);

      if (len > 0)
      {
        rpl_event->event.previous_gtid.content.data= ev;
        rpl_event->event.previous_gtid.content.length= len;
        ev+= len; // @infer-ignore DEAD_STORE
      }
      break;
    }

    case ANONYMOUS_GTID_LOG_EVENT:
    case GTID_LOG_EVENT:
    {
      uchar *post_header_start = ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);

      /* ---------------------------------------------------------------------
       * MySQL Native 42-Byte Layout
       * --------------------------------------------------------------------- */
      if (post_header_len >= 42)
      {
        rpl_event->event.gtid_log.commit_flag = *post_header_start;
        memcpy(rpl_event->event.gtid_log.source_id, post_header_start + 1, 16);
        rpl_event->event.gtid_log.sequence_nr = uint8korr(post_header_start + 17);
      }
      /* ---------------------------------------------------------------------
       * MariaDB 19-Byte Compatibility Layout
       * --------------------------------------------------------------------- */
      else if (post_header_len >= 19)
      {
        /* Map the 19-byte MariaDB fields instead */
        rpl_event->event.gtid.sequence_nr = uint8korr(post_header_start);
        rpl_event->event.gtid.domain_id = uint4korr(post_header_start + 8);
        rpl_event->event.gtid.flags = *(post_header_start + 12);

        /* Bit 1 (0x02) indicates a group commit ID exists in the final bytes */
        if (rpl_event->event.gtid.flags & 2) {
          rpl_event->event.gtid.commit_id = uint8korr(post_header_start + 13);
        } else {
          rpl_event->event.gtid.commit_id = 0;
        }
      }
      else
      {
        goto malformed_packet;
      }

      /* Cleanly advance past whatever header size the server defined */
      ev = post_header_start + post_header_len;

      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);
      if (len > 0)
        ev += len;

      break;
    }

    case GTID_EVENT:
      /*
          GTID_EVENT (MariaDB Only):

          A New transaction (BEGIN) was started, or a single transaction
          (ddl) statement was executed. In case a single transaction was
          executed, the FL_GROUP_COMMIT id flag is not set.

          Header:
            uint64_t sequence_nr
            uint64_t domain_id
            uint8_t  flags

            if (flags & FL_GROUP_COMMIT_D)
              uint64_t commit_id
            else
              char[6]  unused
      */
      RPL_CHECK_POS(ev, ev_end, post_header_len);
      rpl_event->event.gtid.sequence_nr= uint8korr(ev);
      ev+= 8;
      rpl_event->event.gtid.domain_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.gtid.flags= *ev;
      ev++;
      if (rpl_event->event.gtid.flags & FL_GROUP_COMMIT_ID)
      {
        RPL_CHECK_POS(ev, ev_end, 8);
        rpl_event->event.gtid.commit_id= uint8korr(ev);
        ev+= 8; // @infer-ignore DEAD_STORE
      }
      else
      {
        uint16_t len;
        RPL_CHECK_POS(ev, ev_end, 6);
        rpl_event->event.gtid.format_id= uint4korr(ev);
        ev+= 4;
        rpl_event->event.gtid.gtrid_len= *ev;
        ev++;
        rpl_event->event.gtid.bqual_len= *ev;
        ev++;
        len= rpl_event->event.gtid.gtrid_len + rpl_event->event.gtid.bqual_len;
        RPL_CHECK_POS(ev, ev_end, len);
        rpl_set_string_and_len(&rpl_event->event.gtid.xid, ev, len);
        ev+= len; // @infer-ignore DEAD_STORE
      }
      break;

    case GTID_LIST_EVENT:
    {
      /*
         GTID_LIST_EVENT (MariaDB only)

         Logged in every binlog to record the current replication state.
         Consists of the last GTID seen for each replication domain.

         The Global Transaction ID, GTID for short, consists of three components:
         replication domain id, server id and sequence nr

         Header:
           uint32_t gtid_cnt  - number of global transaction id's

         Payload:
           for i=0; i < gtid_cnt; i++
             uint32_t domain_id
             uint32_t server_id
             uint64_t sequence_nr
      */
      uint32_t gtid_cnt;
      unsigned char *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);

      gtid_cnt= rpl_event->event.gtid_list.gtid_cnt= uint4korr(ev);
      ev+=4;

      if (gtid_cnt > (MAX_PACKET_LENGTH / 16))
        goto malformed_packet;

      ev= post_header_start + post_header_len;

      RPL_CHECK_POS(ev, ev_end, (size_t)gtid_cnt * 16);
      /* Payload */
      if (gtid_cnt)
      {
        uint32_t i;
        if (!(rpl_event->event.gtid_list.gtid=
         (MARIADB_GTID *)ma_calloc_root(&rpl_event->memroot,
                                        sizeof(MARIADB_GTID) * rpl_event->event.gtid_list.gtid_cnt)))
          goto mem_error;
        for (i=0; i < rpl_event->event.gtid_list.gtid_cnt; i++)
        {
          rpl_event->event.gtid_list.gtid[i].domain_id= uint4korr(ev);
          ev+= 4;
          rpl_event->event.gtid_list.gtid[i].server_id= uint4korr(ev);
          ev+= 4;
          rpl_event->event.gtid_list.gtid[i].sequence_nr= uint8korr(ev);
          ev+= 8;
        }
      }
      break;
    }

    case WRITE_ROWS_COMPRESSED_EVENT_V1:
    case UPDATE_ROWS_COMPRESSED_EVENT_V1:
     case DELETE_ROWS_COMPRESSED_EVENT_V1:
    case WRITE_ROWS_EVENT_V1:
    case UPDATE_ROWS_EVENT_V1:
    case DELETE_ROWS_EVENT_V1:
    case WRITE_ROWS_EVENT:
    case UPDATE_ROWS_EVENT:
    case DELETE_ROWS_EVENT:
    {
      /*
         WRITE/UPDATE/DELETE_ROWS_EVENT_V1 (MariaDB only)
         WRITE/UPDATE/DELETE_ROWS_EVENT_COMPRESSED_V1 (MariaDB only)
         WRITE/UPDATE/DELETE_ROWS_EVENT (MySQL only)

         ROWS events are written for row-based replication if data is
         inserted, deleted or updated.

         Header
           uint<6>    table_id
           uint<2>    flags

           if MySQL (version 2)
             uint<<2>                     extra_data_length
             char[extra_data_length]      extra_data

           uint<lenenc>  number of columns
           uint8_t<n>    Bitmap of columns used.
                         n= (number of columns + 7) / 8

           if UPDATE_ROWS_v1 (MariaDB)
             uint8_t<n>  columns updated
                         n= (number of columns + 7) / 8

           uint7_t<n>    null bitmap
                         n= (number of columns + 7) / 8

           str<len>      Column data. If event is not compressed,
                         length must be calculated.

           if UPDATE_ROWS_v1 (MariaDB)
             byte<n>     Null bitmap update
                         n= (number of columns + 7) / 8
             str<len>    Update column data

      */

      uint32_t bitmap_len= 0;
      unsigned char *post_header_start= ev;

      RPL_CHECK_POS(ev, ev_end, post_header_len);

      if (rpl_event->event_type >= WRITE_ROWS_COMPRESSED_EVENT) {
        rpl_event->event.rows.compressed= 1;
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_COMPRESSED_EVENT;
        ev= ev_end;
        return rpl_event;
      } else if (rpl_event->event_type >= WRITE_ROWS_COMPRESSED_EVENT_V1) {
        rpl_event->event.rows.compressed= 1;
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_COMPRESSED_EVENT_V1;
      } else if (rpl_event->event_type >= WRITE_ROWS_EVENT)
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_EVENT;
      else
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_EVENT_V1;

      RPL_CHECK_POS(ev, ev_end, 8);
      rpl_event->event.rows.table_id= uint6korr(ev);
      ev+= 6;

      rpl_event->event.rows.flags= uint2korr(ev);
      ev+= 2;


      /* payload */

      /* ROWS_EVENT V2 has the extra-data field.
         See also: https://dev.mysql.com/doc/internals/en/rows-event.html
      */
      if (IS_ROW_VERSION2(rpl_event->event_type))
      {
        size_t payload_size= 0;

        RPL_CHECK_POS(ev, ev_end, 2);
        rpl_event->event.rows.extra_data_size= uint2korr(ev);

        ev+= 2;

        if (rpl_event->event.rows.extra_data_size < 2)
          goto malformed_packet;

        payload_size = rpl_event->event.rows.extra_data_size - 2;

        RPL_CHECK_POS(ev, ev_end, payload_size);

        if (payload_size > 0)
        {
          rpl_alloc_set_string_and_len(rpl_event, rpl_event->event.rows.extra_data, ev, payload_size);
          ev+= payload_size;
        }
      } else {
        ev= post_header_start + post_header_len;
      }
      /* END_ROWS_EVENT_V2 */

      /* number of columns */
      RPL_CHECK_FIELD_LENGTH(ev, ev_end);
      rpl_event->event.rows.column_count= mysql_net_field_length(&ev);
      bitmap_len= (rpl_event->event.rows.column_count + 7) / 8;

      if (rpl_event->event.rows.column_count < 1)
        goto malformed_packet;

      /* columns updated bitmap */
      RPL_CHECK_POS(ev, ev_end, bitmap_len);
      rpl_event->event.rows.column_bitmap= ev;
      ev+= bitmap_len;

      if (rpl_event->event_type == UPDATE_ROWS_EVENT_V1 ||
          rpl_event->event_type == UPDATE_ROWS_COMPRESSED_EVENT_V1)
      {
        RPL_CHECK_POS(ev, ev_end, bitmap_len);
        rpl_event->event.rows.column_update_bitmap= ev;
        ev+= bitmap_len;
      }

      RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, len, malformed_packet);

      if (rpl_event->event.rows.compressed)
      {
        uint8_t algorithm= 0, header_size= 0;
        uLongf source_len;
        uLong dest_len;
        uint32_t uncompressed_len= get_compression_info(ev, &algorithm, &header_size);

        if (header_size >= (ev_end - ev) ||
            uncompressed_len == 0 ||
            uncompressed_len > MAX_PACKET_LENGTH)
        {
          rpl_set_error(rpl, CR_ERR_BINLOG_UNCOMPRESS, SQLSTATE_UNKNOWN, RPL_ERR_POS(rpl));
          mariadb_free_rpl_event(rpl_event);
          return NULL;
        }

        if (ev + header_size > ev_end)
          goto malformed_packet;

        source_len= (uLongf)(ev_end - (ev + header_size));

        if (!(rpl_event->event.rows.row_data = ma_calloc_root(&rpl_event->memroot, uncompressed_len)))
          goto mem_error;

        dest_len= (uLong)uncompressed_len;

        if ((uncompress((Bytef*)rpl_event->event.rows.row_data, (uLong *)&dest_len,
           (Bytef*)ev + header_size, source_len) != Z_OK))
        {
          rpl_set_error(rpl, CR_ERR_BINLOG_UNCOMPRESS, SQLSTATE_UNKNOWN, 0, RPL_ERR_POS(rpl));
          mariadb_free_rpl_event(rpl_event);
          return NULL;
        }
        rpl_event->event.rows.row_data_size= dest_len;
        RPL_CHECK_POS(ev, ev_end, header_size + len);
        ev+= header_size + source_len;
      } else {
        RPL_CALC_SAFE_LEN(ev, ev_end, rpl->use_checksum, rpl_event->event.rows.row_data_size, malformed_packet);

        if (ev + rpl_event->event.rows.row_data_size > ev_end)
          goto malformed_packet;
        if (!(rpl_event->event.rows.row_data =
            (char *)ma_calloc_root(&rpl_event->memroot, rpl_event->event.rows.row_data_size)))
          goto mem_error;
        memcpy(rpl_event->event.rows.row_data, ev, rpl_event->event.rows.row_data_size);
      }
      break;
    }
    default:
      /* We need to report an error if this event can't be ignored */
      if (!(rpl_event->flags & LOG_EVENT_IGNORABLE_F))
      {
        rpl_set_error(rpl, CR_UNKNOWN_BINLOG_EVENT, 0, RPL_ERR_POS(rpl),
                      rpl_event->event_type);
        mariadb_free_rpl_event(rpl_event);
        return 0;
      }
      return rpl_event;
    }

    /* Safe guard */
    RPL_CHECK_POS(ev, ev_end, 0);

    /* check if we have to send acknowledgement to primary
       when semi sync replication is used */
    if (rpl_event->is_semi_sync &&
        rpl_event->semi_sync_flags == SEMI_SYNC_ACK_REQ)
    {
      if (mariadb_rpl_send_semisync_ack(rpl, rpl_event))
      {
        /* ACK failed and rpl->error was set */
        return rpl_event;
      }
    }

    if (rpl->use_checksum && !rpl_event->checksum)
    {
      rpl_event->checksum= uint4korr(ev_end - 4);

      if (rpl_event->checksum && rpl->verify_checksum)
      {
        unsigned long crc= crc32(0L, Z_NULL, 0);
        crc= crc32(crc, checksum_start, (uint32_t)(ev_end - checksum_start - 4));
        if (rpl_event->checksum != (uint32_t)crc)
        {
          rpl_set_error(rpl, CR_ERR_CHECKSUM_VERIFICATION_ERROR, SQLSTATE_UNKNOWN, 0,
                       RPL_ERR_POS(rpl),
                       rpl_event->checksum, (uint32_t)crc);
          mariadb_free_rpl_event(rpl_event);
          return 0;
        }
      }
    }
    return rpl_event;
  }
mem_error:
  mariadb_free_rpl_event(rpl_event);
  rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
  return 0;
malformed_packet:
  rpl_set_error(rpl, CR_BINLOG_ERROR, 0, RPL_ERR_POS(rpl),
                "Malformed packet");
  mariadb_free_rpl_event(rpl_event);
  return 0;
}

void STDCALL mariadb_rpl_close(MARIADB_RPL *rpl)
{
  if (!rpl)
    return;
  free((void *)rpl->filename);
  if (rpl->fp)
  {
    ma_close(rpl->fp);
  }
  free(rpl->host);
  free(rpl);
  return;
}

int STDCALL mariadb_rpl_optionsv(MARIADB_RPL *rpl,
                                 enum mariadb_rpl_option option,
                                 ...)
{
  va_list ap;
  int rc= 0;

  if (!rpl)
    return 1;

  va_start(ap, option);

  switch (option) {
  case MARIADB_RPL_FILENAME:
  {
    char *arg1= va_arg(ap, char *);
    rpl->filename_length= (uint32_t)va_arg(ap, size_t);
    free((void *)rpl->filename);
    rpl->filename= NULL;
    if (rpl->filename_length)
    {
      if ((rpl->filename= (char *)malloc(rpl->filename_length)))
        memcpy((void *)rpl->filename, arg1, rpl->filename_length);
      else {
        va_end(ap);
        rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
        return 1;
      }
    }
    else if (arg1)
    {
      rpl->filename= strdup((const char *)arg1);
      if (!rpl->filename)
      {
        va_end(ap);
        rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
        return 1;
      }
      rpl->filename_length= (uint32_t)strlen(rpl->filename);
    }
    break;
  }
  case MARIADB_RPL_SERVER_ID:
  {
    rpl->server_id= va_arg(ap, unsigned int);
    break;
  }
  case MARIADB_RPL_FLAGS:
  {
    rpl->flags= va_arg(ap, unsigned int);
    break;
  }
  case MARIADB_RPL_START:
  {
    rpl->start_position= va_arg(ap, unsigned long);
    break;
  }
  case MARIADB_RPL_VERIFY_CHECKSUM:
  {
    rpl->verify_checksum= va_arg(ap, uint32_t);
    break;
  }
  case MARIADB_RPL_UNCOMPRESS:
  {
    rpl->uncompress= (uint8_t)va_arg(ap, uint32_t);
    break;
  }
  case MARIADB_RPL_PORT:
  {
    rpl->port= va_arg(ap, uint32_t);
    break;
  }
  case MARIADB_RPL_HOST:
  {
    rpl->host= strdup(va_arg(ap, char *));
    break;
  }
  case MARIADB_RPL_EXTRACT_VALUES:
  {
    rpl->extract_values= (uint8_t)va_arg(ap, uint32_t);
    break;
  }
  case MARIADB_RPL_SEMI_SYNC:
  {
    rpl->is_semi_sync = (uint8_t)va_arg(ap, uint32_t);
    break;
  }
  default:
    rc= -1;
    goto end;
  }
end:
  va_end(ap);
  return rc;
}

int STDCALL mariadb_rpl_get_optionsv(MARIADB_RPL *rpl,
                                     enum mariadb_rpl_option option,
                                     ...)
{
  va_list ap;

  if (!rpl)
    return 1;

  va_start(ap, option);

  switch (option) {
  case MARIADB_RPL_FILENAME:
  {
    const char **name= (const char **)va_arg(ap, char **);
    size_t *len= (size_t*)va_arg(ap, size_t *);

    *name= rpl->filename;
    *len= rpl->filename_length;
    break;
  }
  case MARIADB_RPL_SERVER_ID:
  {
    unsigned int *id= va_arg(ap, unsigned int *);
    *id= rpl->server_id;
    break;
  }
  case MARIADB_RPL_FLAGS:
  {
    unsigned int *flags= va_arg(ap, unsigned int *);
    *flags= rpl->flags;
    break;
  }
  case MARIADB_RPL_START:
  {
    unsigned long *start= va_arg(ap, unsigned long *);
    *start= rpl->start_position;
    break;
  }
  case MARIADB_RPL_SEMI_SYNC:
  {
    unsigned int* semi_sync = va_arg(ap, unsigned int*);
    *semi_sync = rpl->is_semi_sync;
    break;
  }

  default:
    va_end(ap);
    return 1;
  }
  va_end(ap);
  return 0;
}
