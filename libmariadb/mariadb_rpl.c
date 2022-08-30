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
#include <mariadb_rpl.h>


#ifdef WIN32
#define alloca _alloca
#endif

void rpl_set_error(MARIADB_RPL *rpl,
                   unsigned int error_nr,
                   const char *format,
                    ...)
{
  va_list ap;

  const char *errmsg;

  if (!format)
  {
    if (error_nr >= CR_MIN_ERROR && error_nr <= CR_MYSQL_LAST_ERROR)
      errmsg= ER(error_nr);
    else if (error_nr >= CER_MIN_ERROR && error_nr <= CR_MARIADB_LAST_ERROR)
      errmsg= CER(error_nr);
    else
      errmsg= ER(CR_UNKNOWN_ERROR);
  }

  rpl->error_no= error_nr;
  va_start(ap, format);
  vsnprintf(rpl->error_msg, MYSQL_ERRMSG_SIZE - 1,
            format ? format : errmsg, ap);
  va_end(ap);
  return;
}


static void *ma_calloc_root(void *memroot, size_t len)
{
  void *p;

  if ((p= ma_alloc_root(memroot, len)))
    memset(p, 0, len);
  return p;
}

static int rpl_set_string_and_len(MARIADB_RPL_EVENT *event,
                            MARIADB_STRING *s,
                            unsigned char *buffer,
                            size_t len)
{
  if (!buffer || !len)
  {
    s->length= 0;
    return 0;
  }
  if (!(s->str= ma_calloc_root(&event->memroot, len)))
    return 1;
  memcpy(s->str, buffer, len);
  s->length= len;
  return 0;
}

static int rpl_set_string0(MARIADB_RPL_EVENT *event,
                           MARIADB_STRING *s,
                           const char *buffer)
{
  size_t len;
  if (!buffer || !buffer[0]) 
  {
    s->length= 0;
    return 0;
  }

  len= strlen(buffer);

  if (!(s->str= ma_calloc_root(&event->memroot, len)))
    return 1;
  strcpy(s->str, buffer);
  s->length= len;
  return 0;
}

static int rpl_set_data(MARIADB_RPL_EVENT *event, unsigned char  **buf, void *val, size_t len)
{
  if (!val || !len)
    return 0;
  if (!(*buf= ma_calloc_root(&event->memroot, len)))
    return 1;
  memcpy(*buf, val, len);
  return 0;
}

MARIADB_RPL * STDCALL mariadb_rpl_init_ex(MYSQL *mysql, unsigned int version)
{
  MARIADB_RPL *rpl;

  if (version < MARIADB_RPL_REQUIRED_VERSION ||
      version > MARIADB_RPL_VERSION)
  {
    my_set_error(mysql, CR_VERSION_MISMATCH, SQLSTATE_UNKNOWN, 0, version,
                     MARIADB_RPL_VERSION, MARIADB_RPL_REQUIRED_VERSION);
    return 0;
  }

  /* if there is no connection, we read a file 
  if (!mysql)
    return NULL; */

  if (!(rpl= (MARIADB_RPL *)calloc(1, sizeof(MARIADB_RPL))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    return 0;
  }
  rpl->version= version;

  if ((rpl->mysql= mysql))
  {
    if (!mysql_query(mysql, "select @@binlog_checksum"))
    {
      MYSQL_RES *result;
      if ((result= mysql_store_result(mysql)))
      {
        MYSQL_ROW row= mysql_fetch_row(result);
        if (!strcmp(row[0], "CRC32"))
        {
          rpl->artificial_checksun= 1;
        }
        mysql_free_result(result);
      }
    }
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
  if (rpl->mysql && rpl->mysql->options.extension && rpl->mysql->options.extension->rpl_host)
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
     size_t len= MIN(strlen(rpl->mysql->options.extension->rpl_host), 255);
    
     p= buffer;
     int4store(p, rpl->server_id);
     p+= 4;
     *p++= (unsigned char)len;
     memcpy(p, rpl->mysql->options.extension->rpl_host, len);
     p+= len;

     /* Don't send user, password, rank and server_id */
     *p++= 0;
     *p++= 0;
     int2store(p, rpl->mysql->options.extension->rpl_port);
     p+= 2;

     int4store(p, 0);
     p+= 4;
     int4store(p, 0);
     p+= 4;

     if (ma_simple_command(rpl->mysql, COM_REGISTER_SLAVE, (const char *)buffer, p - buffer, 1, 0))
       return 1;
  }

  if (rpl->mysql)
  {  
    ptr= buf=
  #ifdef WIN32
      (unsigned char *)malloca(rpl->filename_length + 11);
  #else
      (unsigned char *)alloca(rpl->filename_length + 11);
  #endif

    int4store(ptr, (unsigned int)rpl->start_position);
    ptr+= 4;
    int2store(ptr, rpl->flags);
    ptr+= 2;
    int4store(ptr, rpl->server_id);
    ptr+= 4;
    memcpy(ptr, rpl->filename, rpl->filename_length);
    ptr+= rpl->filename_length;

    return (ma_simple_command(rpl->mysql, COM_BINLOG_DUMP, (const char *)buf, ptr - buf, 1, 0));
  } else
  {
    char *buf[RPL_BINLOG_FILEHEADER_SIZE];

    if (rpl->fp)
      fclose(rpl->fp);

    if (!(rpl->fp= fopen((const char *)rpl->filename, "r")))
    {
      rpl_set_error(rpl, CR_FILE_NOT_FOUND, 0, rpl->filename, errno);
      return errno;
    }

    if (fread(buf, 1, RPL_BINLOG_MAGIC_SIZE, rpl->fp) != 4)
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
 *
 *
 *
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
 
MARIADB_RPL_EVENT * STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl, MARIADB_RPL_EVENT *event)
{
  unsigned char *ev= 0;
  unsigned char *checksum_start= 0;
  unsigned char *ev_start= 0;
  unsigned char *ev_end= 0;
  size_t len= 0;
  MARIADB_RPL_EVENT *rpl_event= 0;

  if (!rpl || (!rpl->mysql && !rpl->fp))
    return 0;

  while (1) {
    unsigned long pkt_len;

    if (rpl->mysql)
    {
      pkt_len= ma_net_safe_read(rpl->mysql);

      if (pkt_len == packet_error)
      {
        rpl->buffer_size= 0;
        return 0;
      }

      /* EOF packet:
         see https://mariadb.com/kb/en/library/eof_packet/
         Packet length must be less than 9 bytes, EOF header
         is 0xFE.
      */
      if (pkt_len < 9 && rpl->mysql->net.read_pos[0] == 0xFE)
      {
        rpl->buffer_size= 0;
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

      rpl->buffer_size= pkt_len;
      ev= rpl->buffer= rpl->mysql->net.read_pos;
    } else if (rpl->fp) {
      char buf[EVENT_HEADER_OFS]; /* header */
      size_t rc;
      uint32_t len= 0;
      char *p= buf;

      memset(buf, 0, EVENT_HEADER_OFS);
      if (fread(buf, 1, EVENT_HEADER_OFS, rpl->fp) != EVENT_HEADER_OFS)
      {
         rpl_set_error(rpl, CR_BINLOG_ERROR, 0, "Can't read event header");
         return NULL;
      }
      len= uint4korr(p + 9);

      if (rpl->buffer_size < len)
      {
        if (!(rpl->buffer= realloc(rpl->buffer, len)))
        {
          rpl_set_error(rpl, CR_OUT_OF_MEMORY, 0);
          return NULL;
        }
      }

      rpl->buffer_size= len;
      memcpy(rpl->buffer, buf, EVENT_HEADER_OFS);
      len-= EVENT_HEADER_OFS;
      rc= fread(rpl->buffer + EVENT_HEADER_OFS, 1, len, rpl->fp);
      if (rc != len)
      {
        rpl_set_error(rpl, CR_BINLOG_ERROR, 0, "Error while reading post header");
        return NULL;
      }
      ev= rpl->buffer;
    }
    ev_end= rpl->buffer + rpl->buffer_size;

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

    if (rpl->mysql)
    {
      rpl_event->ok= *ev++;

      /* CONC-470: add support for semi snychronous replication */
      if ((rpl_event->is_semi_sync= (*ev == SEMI_SYNC_INDICATOR)))
      {
        ev++;
        rpl_event->semi_sync_flags= *ev++;
      }
    }

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
      - uint32_t next_pos:  Position of next binary log event
      - uint16_t flags:     flags

     The size of binlog event header must match the header size returned
     by FORMAT_DESCIPTION_EVENT. In version 4 it is always 19. 
    ********************************************************************/
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

    switch(rpl_event->event_type) {
    case UNKNOWN_EVENT:
    case SLAVE_EVENT:
       return rpl_event;
       break;
    case HEARTBEAT_LOG_EVENT:
      /* post header */
      rpl_event->event.heartbeat.timestamp= uint4korr(ev);
      ev+= 4;
      rpl_event->event.heartbeat.next_position= uint4korr(ev);
      ev+= 4;
      rpl_event->event.heartbeat.type= (uint8_t)*ev;
      ev+= 1;
      rpl_event->event.heartbeat.flags= uint2korr(ev);
      ev+= 2;
      
      break;

    case BEGIN_LOAD_QUERY_EVENT:
      /* Post header */
      rpl_event->event.begin_load_query.file_id= uint4korr(ev);
      ev+= 4;

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type]);

      /* Payload: query_data (zero terminated) */
      if (rpl_set_data(event, &rpl_event->event.begin_load_query.data, ev, strlen((char *)ev)))
        goto mem_error;
      ev+= strlen((char *)ev) + 1;
      break;

    case START_ENCRYPTION_EVENT:
      /* Post header */
      rpl_event->event.start_encryption.scheme= *ev++;
      rpl_event->event.start_encryption.key_version= uint4korr(ev);
      ev+= 4;
      memcpy(rpl_event->event.start_encryption.nonce, ev, 12);
      ev+= 12;

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);
      break;

    case EXECUTE_LOAD_QUERY_EVENT:
    {
      uint16_t status_len;
      uint8_t schema_len;

      /* Post header */
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

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);

      /* Payload:
         - status variables
         - query schema
         - statement */
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.execute_load_query.status_vars, ev, status_len))
        goto mem_error;
      ev+= status_len;
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.execute_load_query.schema, ev, schema_len))
        goto mem_error;
      ev+= (schema_len + 1);
      len= rpl_event->event_length - (ev - ev_start) - (rpl->use_checksum ? 4 : 0) - (EVENT_HEADER_OFS - 1);
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.execute_load_query.statement, ev, len))
        goto mem_error;
      ev+= len;
      break;
    }
    case BINLOG_CHECKPOINT_EVENT:
      /* Post header */
      len= uint4korr(ev);
      ev+= 4;

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);

      /* payload: filname */
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.checkpoint.filename, ev, len) ||
          ma_set_rpl_filename(rpl, ev, len))
        goto mem_error;
      ev+= len;
      break;

    case FORMAT_DESCRIPTION_EVENT:
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
      if ((rpl_event->event.format_description.format = uint2korr(ev)) < 4)
      {
        mariadb_free_rpl_event(rpl_event);
        my_set_error(rpl->mysql, CR_ERR_UNSUPPORTED_BINLOG_FORMAT, SQLSTATE_UNKNOWN, 0,
                     rpl->filename_length, rpl->filename, rpl->start_position, uint2korr(ev));
        return 0;
      }

      ev+= 2;
      rpl_event->event.format_description.server_version = (char *)(ev);
      ev+= 50;
      rpl_event->event.format_description.timestamp= uint4korr(ev);
      ev+= 4;
      rpl->fd_header_len= rpl_event->event.format_description.header_len= *ev;
      ev+= 1;
      /*Post header lengths: 1 byte for each event, non used events/gaps in enum should
                             have a zero value */
      len= ev_end - ev - 5;
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.format_description.post_header_lengths, ev, len))
        goto mem_error;
      memset(rpl->post_header_len, 0, ENUM_END_EVENT);
      memcpy(rpl->post_header_len, rpl_event->event.format_description.post_header_lengths.str, 
             MIN(len, ENUM_END_EVENT));
      ev+= len;
      if ((rpl->use_checksum= *ev++))
      {
        rpl_event->checksum= uint4korr(ev);
        ev+= 4;
      }
      break;

    case QUERY_COMPRESSED_EVENT:
    case QUERY_EVENT:
    {
      size_t db_len, status_len;

      /***********
       post_header
       ***********/
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

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);

      /*******
       payload
       ******/
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.query.status, ev, status_len))
        goto mem_error;
      ev+= status_len;

      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.query.database, ev, db_len))
        goto mem_error;
      ev+= db_len + 1; /* zero terminated */

      len= rpl_event->event_length - (ev - ev_start) -  (rpl->use_checksum ? 4 : 0) - (EVENT_HEADER_OFS - 1);

      if (rpl_event->event_type == QUERY_EVENT) {
        if (rpl_set_string_and_len(rpl_event, &rpl_event->event.query.statement, ev, len))
          goto mem_error;
      }

      if (rpl_event->event_type == QUERY_COMPRESSED_EVENT)
      {
        uint8_t header_size= 0,
                algorithm= 0;

        uint32_t uncompressed_len= get_compression_info(ev, &algorithm, &header_size);

        len-= header_size;
        if (!(rpl_event->event.query.statement.str = ma_calloc_root(&rpl_event->memroot, uncompressed_len)))
          goto mem_error;

        if ((uncompress((Bytef*)rpl_event->event.query.statement.str, (uLongf *)&uncompressed_len,
           (Bytef*)ev + header_size, (uLongf)*&len) != Z_OK))
        {
          mariadb_free_rpl_event(rpl_event);
          SET_CLIENT_ERROR(rpl->mysql, CR_ERR_NET_UNCOMPRESS, SQLSTATE_UNKNOWN, 0);
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
           byte<n>   netadata{metadata_size]
           byte<n>   bit fields, indicating which column can be null
                     n= (column_count + 7) / 8;
      */

      /* Post header length */
      rpl_event->event.table_map.table_id= uint6korr(ev);
      ev+= 8;  /* 2 byte in header ignored */

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);

      /* Payload */
      len= *ev;
      ev++;

      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.table_map.database, ev, len))
        goto mem_error;
      ev+= len + 1; /* Zero terminated */

      len= *ev;
      ev++;
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.table_map.table, ev, len))
        goto mem_error;
      ev+= len + 1; /* Zero terminated */

      rpl_event->event.table_map.column_count= mysql_net_field_length(&ev);
      len= rpl_event->event.table_map.column_count;
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.table_map.column_types, ev, len))
        goto mem_error;

      ev+= len;
      len= mysql_net_field_length(&ev);
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.table_map.metadata, ev, len))
        goto mem_error;
      ev+= len;

      len= ev_end - ev - (rpl->use_checksum ? 4 : 0);
      if (rpl_set_data(rpl_event, &rpl_event->event.table_map.null_indicator, ev, len))
        goto mem_error;
      ev+= len;

      break;

    case RAND_EVENT:
      rpl_event->event.rand.first_seed= uint8korr(ev);
      ev+= 8;
      rpl_event->event.rand.second_seed= uint8korr(ev);
      ev+= 8;

      break;
    }

    case INTVAR_EVENT:
      rpl_event->event.intvar.type= *ev;
      ev++;
      rpl_event->event.intvar.value= uint8korr(ev);
      ev+= 8;
      break;

    case USER_VAR_EVENT:
      len= uint4korr(ev);
      ev+= 4;
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.uservar.name, ev, len))
        goto mem_error;
      ev+= len;
      if (!(rpl_event->event.uservar.is_null= (uint8)*ev)) 
      {
        ev++;
        rpl_event->event.uservar.type= *ev;
        ev++;
        rpl_event->event.uservar.charset_nr= uint4korr(ev);
        ev+= 4;
        len= uint4korr(ev);
        ev+= 4;
        if (rpl_set_string_and_len(rpl_event, &rpl_event->event.uservar.value, ev, len))
          goto mem_error;
        ev+= len;
        if ((unsigned long)(ev - rpl->buffer) < rpl->buffer_size)
          rpl_event->event.uservar.flags= *ev;
      }
      break;

    case ANNOTATE_ROWS_EVENT:
      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);

      /* Payload */
      len= rpl_event->event_length - (ev - ev_start) -  (rpl->use_checksum ? 4 : 0) - (EVENT_HEADER_OFS - 1);
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.annotate_rows.statement, ev, len))
        goto mem_error;
      break;

    case ROTATE_EVENT:
      /* Payload */
      rpl_event->event.rotate.position= uint8korr(ev);
      ev+= 8;

      len= ev_end - ev - 4;
      if (rpl_event->timestamp == 0 &&
          rpl_event->flags & LOG_EVENT_ARTIFICIAL_F)
      {
        if (rpl->artificial_checksun)
        {
          int4store(ev_end - 4, rpl_event->checksum);
          if (mariadb_connection(rpl->mysql))
            rpl->artificial_checksun= 0;
        }
      }
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.rotate.filename, ev, len) ||
          ma_set_rpl_filename(rpl, ev, len))
        goto mem_error;
      
      ev+= len;
      break;

    case XID_EVENT:
      /*
         XID_EVENT was generated if a transaction which modified tables was
         committed.

         Header:
           - uint64_t  transaction number
      */

      rpl_event->event.xid.transaction_nr= uint8korr(ev);
      break;

    case XA_PREPARE_LOG_EVENT:
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

      rpl_event->event.xa_prepare_log.one_phase= *ev;
      ev++;
      rpl_event->event.xa_prepare_log.format_id= uint4korr(ev);
      ev+= 4;
      len= rpl_event->event.xa_prepare_log.gtrid_len= uint4korr(ev);
      ev+= 4;
      len+= rpl_event->event.xa_prepare_log.bqual_len= uint4korr(ev);
      ev+= 4;
      if (rpl_set_string_and_len(rpl_event, &rpl_event->event.xa_prepare_log.xid, ev, len))
        goto mem_error;
      break;

    case STOP_EVENT:
      /* 
         STOP_EVENT - server shutdown or crash. It's always the last written
         event after shutdown or after resuming from crash.

         After starting the server a new binary log file will be created, additionally
         a ROTATE_EVENT will be appended to the old log file.

         No data to process.
      */
      break;

    case ANONYMOUS_GTID_LOG_EVENT:
    case PREVIOUS_GTIDS_LOG_EVENT:
      /*
         ANONYMOUS_GTID_LOG_EVENT,
         PREVIOUS_GTIDS_LOG_EVENT (MySQL only)

         Header:
           uint8_t flag:         commit flag
           uint64_t source_id:   numerical representation of server's UUID
           uint64_t sequence_nr: sequence number
       */
      rpl_event->event.gtid_log.commit_flag= *ev;
      ev++;
      memcpy(rpl_event->event.gtid_log.source_id, ev, 16);
      ev+= 16;
      rpl_event->event.gtid_log.sequence_nr= uint8korr(ev);
      break;

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
      rpl_event->event.gtid.sequence_nr= uint8korr(ev);
      ev+= 8;
      rpl_event->event.gtid.domain_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.gtid.flags= *ev;
      ev++;
      if (rpl_event->event.gtid.flags & FL_GROUP_COMMIT_ID)
      {
        rpl_event->event.gtid.commit_id= uint8korr(ev);
        ev+= 8;
      }
      else
        ev+= 6;
      break;

    case GTID_LIST_EVENT:
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

      rpl_event->event.gtid_list.gtid_cnt= uint4korr(ev);
      ev+=4;

      /* check post_header_length */
      DBUG_ASSERT(ev - ev_start == rpl->post_header_len[rpl_event->event_type - 1]);

      /* Payload */
      if (rpl_event->event.gtid_list.gtid_cnt)        
      {
        uint32 i;
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
      else
        ev+=4;
      break;

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

         ROWS events are written for row based replicatoin if data is
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

      if (rpl_event->event_type >= WRITE_ROWS_COMPRESSED_EVENT) {
        return rpl_event;
        rpl_event->event.rows.compressed= 1;
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_COMPRESSED_EVENT;
      } else if (rpl_event->event_type >= WRITE_ROWS_COMPRESSED_EVENT_V1) {
        rpl_event->event.rows.compressed= 1;
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_COMPRESSED_EVENT_V1;
      } else if (rpl_event->event_type >= WRITE_ROWS_EVENT)
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_EVENT;
      else
        rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_EVENT_V1;

      rpl_event->event.rows.table_id= uint6korr(ev);
      ev+= 6;

      /* TODO: Flags not defined yet in rpl.h  */
      rpl_event->event.rows.flags= uint2korr(ev);
      ev+= 2;

      /* ROWS_EVENT V2 has the extra-data field.
         See also: https://dev.mysql.com/doc/internals/en/rows-event.html
      */
      if (IS_ROW_VERSION2(rpl_event->event_type))
      {
        rpl_event->event.rows.extra_data_size= uint2korr(ev);
        ev+= 2;
        if (rpl_event->event.rows.extra_data_size - 2 > 0)
        {
          if (!(rpl_event->event.rows.extra_data =
                (char *)ma_calloc_root(&rpl_event->memroot,
                                      rpl_event->event.rows.extra_data_size - 2)))
            goto mem_error;
          memcpy(rpl_event->event.rows.extra_data,
                 ev,
                 rpl_event->event.rows.extra_data_size -2);
          ev+= rpl_event->event.rows.extra_data_size;
        }
      }
      /* END_ROWS_EVENT_V2 */

      /* number of columns */
      rpl_event->event.rows.column_count= mysql_net_field_length(&ev);
      bitmap_len= (rpl_event->event.rows.column_count + 7) / 8;
      DBUG_ASSERT(rpl_event->event.rows.column_count > 0);

      /* columns updated bitmap */
      if (rpl_set_data(rpl_event, &rpl_event->event.rows.column_bitmap, ev, bitmap_len))
        goto mem_error;
      ev+= bitmap_len;

      if (rpl_event->event_type == UPDATE_ROWS_EVENT_V1 ||
          rpl_event->event_type == UPDATE_ROWS_COMPRESSED_EVENT_V1)
      {
        if (rpl_set_data(rpl_event, &rpl_event->event.rows.column_update_bitmap,
                         ev, bitmap_len))
          goto mem_error;
        ev+= bitmap_len;
      }

      len= ev_end - ev - (rpl->use_checksum ? 4 : 0);

      if (rpl_event->event.rows.compressed)
      {
        uint8_t algorithm= 0, header_size= 0;
        uint32_t uncompressed_len= get_compression_info(ev, &algorithm, &header_size);

        if (!(rpl_event->event.rows.row_data = ma_calloc_root(&rpl_event->memroot, uncompressed_len)))
          goto mem_error;

        if ((uncompress((Bytef*)rpl_event->event.rows.row_data, (uLong *)&uncompressed_len,
           (Bytef*)ev + header_size, (uLongf )len) != Z_OK))
        {
          my_set_error(rpl->mysql, CR_ERR_NET_UNCOMPRESS, SQLSTATE_UNKNOWN, 0, rpl->filename_length,
                       rpl->filename, rpl->start_position);
          mariadb_free_rpl_event(rpl_event);
          return 0;
        }
        rpl_event->event.rows.row_data_size= uncompressed_len;
        ev+= header_size + len;
      } else {
        rpl_event->event.rows.row_data_size= ev_end - ev - (rpl->use_checksum ? 4 : 0);
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
        mariadb_free_rpl_event(rpl_event);
        my_set_error(rpl->mysql, CR_UNKNOWN_BINLOG_EVENT, SQLSTATE_UNKNOWN, 0, 
                     rpl->filename_length, rpl->filename, rpl->start_position, rpl_event->event_type);
        return 0;
      }
      return rpl_event;
      break;
    }

    /* check if we have to send acknowledgement to primary
       when semi sync replication is used */
    if (rpl_event->is_semi_sync &&
        rpl_event->semi_sync_flags == SEMI_SYNC_ACK_REQ)
    {
      size_t buf_size= rpl->filename_length + 1 + 9;
      uchar *buffer= alloca(buf_size);

      buffer[0]= SEMI_SYNC_INDICATOR;
      int8store(buffer + 1, (int64_t)rpl_event->next_event_pos);
      memcpy(buffer + 9, rpl->filename, rpl->filename_length);
      buffer[buf_size - 1]= 0;

      if (ma_net_write(&rpl->mysql->net, buffer, buf_size) ||
         (ma_net_flush(&rpl->mysql->net)))
        goto net_error;
    }

    if (rpl->use_checksum && !rpl_event->checksum)
    {
      rpl_event->checksum= uint4korr(ev_end -4);

      if (rpl_event->checksum &&  rpl->verify_checksum)
      {
        unsigned long crc= crc32_z(0L, Z_NULL, 0);
        crc=  crc32_z(crc, checksum_start, ev_end - checksum_start - 4);
        if (rpl_event->checksum != (uint32_t)crc)
        {
          my_set_error(rpl->mysql, CR_ERR_CHECKSUM_VERIFICATION_ERROR, SQLSTATE_UNKNOWN, 0, 
                       rpl->filename_length, rpl->filename, rpl->start_position,
                       rpl_event->checksum, (uint32_t)crc);
          mariadb_free_rpl_event(rpl_event);
          return 0;
        }
      }
    }

    //rpl->start_position= rpl_event->next_event_pos;
    return rpl_event;
  }
mem_error:
  mariadb_free_rpl_event(rpl_event);
  SET_CLIENT_ERROR(rpl->mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
  return 0;
net_error:
  mariadb_free_rpl_event(rpl_event);
  SET_CLIENT_ERROR(rpl->mysql, CR_CONNECTION_ERROR, SQLSTATE_UNKNOWN, 0);
  return 0;
}

void STDCALL mariadb_rpl_close(MARIADB_RPL *rpl)
{
  if (!rpl)
    return;
  if (rpl->filename)
    free((void *)rpl->filename);
  if (rpl->fp)
  {
    free(rpl->buffer);
    fclose(rpl->fp);
  }
  free(rpl);
  return;
}

int mariadb_rpl_optionsv(MARIADB_RPL *rpl,
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
      rpl->filename= (char *)malloc(rpl->filename_length);
      memcpy((void *)rpl->filename, arg1, rpl->filename_length);
    }
    else if (arg1)
    {
      rpl->filename= strdup((const char *)arg1);
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
  default:
    rc= -1;
    goto end;
  }
end:
  va_end(ap);
  return rc;
}

int mariadb_rpl_get_optionsv(MARIADB_RPL *rpl,
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
  default:
    va_end(ap);
    return 1;
    break;
  }
  va_end(ap);
  return 0;
}
