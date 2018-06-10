/************************************************************************************
    Copyright (C) 2018 MariaDB Corpoeation AB

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
#include <mysql.h>
#include <errmsg.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <zlib.h>

MARIADB_RPL STDCALL *mariadb_rpl_init_ex(MYSQL *mysql, unsigned int version)
{
  MARIADB_RPL *rpl;

  if (version < MARIADB_RPL_REQUIRED_VERSION ||
      version > MARIADB_RPL_VERSION)
  {
    my_set_error(mysql, CR_VERSION_MISMATCH, SQLSTATE_UNKNOWN, 0, version,
                     MARIADB_RPL_VERSION, MARIADB_RPL_REQUIRED_VERSION);
    return 0;
  }

  if (!mysql)
    return NULL;

  if (!(rpl= (MARIADB_RPL *)calloc(1, sizeof(MARIADB_RPL))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    return 0;
  }
  rpl->version= version;
  rpl->mysql= mysql;
  return rpl;
}

int STDCALL mariadb_rpl_open(MARIADB_RPL *rpl)
{
  unsigned char *ptr, *buf;
  if (!rpl || !rpl->mysql)
    return 1;

  if (!(rpl->flags & MARIADB_RPL_DUMP_GTID))
  {
    /* COM_BINLOG_DUMP:
       Ofs  Len Data
       0      1 COM_BINLOG_DUMP
       1      4 position
       5      2 flags
       7      4 server id
       11     * filename

       * = filename length

     */
    ptr= buf= (unsigned char *)alloca(rpl->filename_length + 11);

    int4store(ptr, (unsigned int)rpl->start_position);
    ptr+= 4;
    int2store(ptr, rpl->flags);
    ptr+= 2;
    int4store(ptr, rpl->server_id);
    ptr+= 4;
    memcpy(ptr, rpl->filename, rpl->filename_length);
    ptr+= rpl->filename_length;
  } else
  {
    /* COM_BINLOG_GTID: */
  }
  if (ma_simple_command(rpl->mysql, COM_BINLOG_DUMP, (const char *)buf, ptr - buf, 1, 0))
    return 1;
  return 0;
}

int STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl, MARIADB_RPL_EVENT *rpl_event)
{
  unsigned char *ev;

  if (!rpl || !rpl->mysql)
    return 1;

  while (1) {
    unsigned long pkt_len= ma_net_safe_read(rpl->mysql);

    if (pkt_len == packet_error)
    {
      rpl->buffer_size= 0;
      return -1;
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
    rpl->buffer= rpl->mysql->net.read_pos;

    if (!rpl_event)
      return 0;

    memset(rpl_event, 0, sizeof(MARIADB_RPL_EVENT));
    rpl_event->checksum= uint4korr(rpl->buffer + rpl->buffer_size - 4);

    rpl_event->ok= rpl->buffer[0];
    rpl_event->timestamp= uint4korr(rpl->buffer + 1);
    rpl_event->event_type= (unsigned char)*(rpl->buffer + 5);
    rpl_event->server_id= uint4korr(rpl->buffer + 6);
    rpl_event->event_length= uint4korr(rpl->buffer + 10);
    rpl_event->next_event_pos= uint4korr(rpl->buffer + 14);
    rpl_event->flags= uint2korr(rpl->buffer + 18);

    ev= rpl->buffer + EVENT_HEADER_OFS;

    switch(rpl_event->event_type) {
    case BINLOG_CHECKPOINT_EVENT:
      rpl_event->event.checkpoint.filename_len= uint4korr(ev);
      ev+= 4;
      rpl_event->event.checkpoint.filename= (char *)ev;
      break;
    case FORMAT_DESCRIPTION_EVENT:
      rpl_event->event.format_description.format = uint2korr(ev);
      ev+= 2;
      rpl_event->event.format_description.server_version = (char *)(ev);
      ev+= 50;
      rpl_event->event.format_description.timestamp= uint4korr(ev);
      ev+= 2;
      rpl_event->event.format_description.header_len= *ev;
      break;
    case QUERY_EVENT:
      rpl_event->event.query.thread_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.query.seconds= uint4korr(ev);
      ev+= 4;
      rpl_event->event.query.database_len= *ev;
      ev++;
      rpl_event->event.query.errornr= uint2korr(ev);
      ev+= 2;
      rpl_event->event.query.status_len= uint2korr(ev);
      ev+= 2;
      rpl_event->event.query.status= (char *)ev;
      /* todo: status variables */
      ev+= rpl_event->event.query.status_len;
      rpl_event->event.query.database= (char *)ev;
      ev+= (rpl_event->event.query.database_len + 1); /* zero terminated */
      rpl_event->event.query.statement= (char *)ev;
      /* calculate statement size: buffer + buffer_size - current_ofs (ev) - crc_size */
      rpl_event->event.query.statement_len= (uint)(rpl->buffer + rpl->buffer_size - ev - 4);
      //printf("%s\n", rpl_event->event.query.statement);
      break;
    case TABLE_MAP_EVENT:
      rpl_event->event.table_map.table_id= uint6korr(ev);
      ev+= 8;
      rpl_event->event.table_map.database_len= *ev;
      ev++;
      rpl_event->event.table_map.database= (char *)ev;
      ev+= rpl_event->event.table_map.database_len + 1;
      rpl_event->event.table_map.table_len= *ev;
      ev++;
      rpl_event->event.table_map.table= (char *)ev;
      ev+= rpl_event->event.table_map.table_len + 1;
      rpl_event->event.table_map.column_count= mysql_net_field_length(&ev);
      rpl_event->event.table_map.column_types= (char *)ev;
      ev+= rpl_event->event.table_map.column_count;
      rpl_event->event.table_map.metadata_len= mysql_net_field_length(&ev);
      rpl_event->event.table_map.metadata= (char *)ev;
      break;
    case RAND_EVENT:
      rpl_event->event.rand.first_seed= uint8korr(ev);
      ev+= 8;
      rpl_event->event.rand.second_seed= uint8korr(ev);
      break;
    case INTVAR_EVENT:
      rpl_event->event.intvar.type= *ev;
      ev++;
      rpl_event->event.intvar.value= uint8korr(ev);
      break;
    case USER_VAR_EVENT:
      rpl_event->event.uservar.name_len= uint4korr(ev);
      ev+= 4;
      rpl_event->event.uservar.name= (char *)ev;
      printf("uservar: %s", rpl_event->event.uservar.name);
      ev+= rpl_event->event.uservar.name_len;
      if (!(rpl_event->event.uservar.is_null= (uint8)*ev)) 
      {
        ev++;
        rpl_event->event.uservar.type= *ev;
        ev++;
        rpl_event->event.uservar.charset_nr= uint4korr(ev);
        ev+= 4;
        rpl_event->event.uservar.value_len= uint4korr(ev);
        ev+= 4;
        rpl_event->event.uservar.value= (char *)ev;
        printf(" value=%s\n", rpl_event->event.uservar.value);
        ev+= rpl_event->event.uservar.value_len;
        if ((unsigned long)(ev - rpl->buffer) < rpl->buffer_size)
          rpl_event->event.uservar.flags= *ev;
      }
      break;
    case START_ENCRYPTION_EVENT:
      rpl_event->event.encryption.scheme= *ev;
      ev++;
      rpl_event->event.encryption.key_version= uint4korr(ev);
      ev+= 4;
      rpl_event->event.encryption.nonce= (char *)ev;
      break;
    case ANNOTATE_ROWS_EVENT:
      rpl_event->event.annotate_rows.statement_len= (uint32)(rpl->buffer + rpl->buffer_size - (unsigned char *)ev - 4);
      rpl_event->event.annotate_rows.statement= (char *)ev;
      break;
    case ROTATE_EVENT:
      rpl_event->event.rotate.position= uint8korr(ev);
      ev+= 8;
      rpl_event->event.rotate.filename= (char *)ev;
      rpl_event->event.rotate.filename_len= rpl->buffer + rpl->buffer_size - ev;
      break;
    case XID_EVENT:
      rpl_event->event.xid.transaction_nr= uint8korr(ev);
      break;
    case STOP_EVENT:
      /* nothing to do here */
      break;
    case GTID_EVENT:
      rpl_event->event.gtid.sequence_nr= uint8korr(ev);
      ev+= 8;
      rpl_event->event.gtid.domain_id= uint4korr(ev);
      ev+= 4;
      rpl_event->event.gtid.flags= *ev;
      ev++;
      if (rpl_event->event.gtid.flags & FL_GROUP_COMMIT_ID)
        rpl_event->event.gtid.commit_id= uint8korr(ev);
      break;
    case GTID_LIST_EVENT:
      rpl_event->event.gtid_list.gtid_cnt= uint4korr(ev);
      ev++;
      if (!(rpl_event->event.gtid_list.gtid= (MARIADB_GTID *)malloc(sizeof(MARIADB_GTID) * rpl_event->event.gtid_list.gtid_cnt)))
      {
        SET_CLIENT_ERROR(rpl->mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
        return 1;
      } else {
        unsigned int i;
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
    case WRITE_ROWS_EVENT_V1:
    case UPDATE_ROWS_EVENT_V1:
    case DELETE_ROWS_EVENT_V1:
      rpl_event->event.rows.type= rpl_event->event_type - WRITE_ROWS_EVENT_V1;
    default:
      //printf("event not handled: %d\n", rpl_event->event_type);
      break;
    }
    return 0;
  }
}

int STDCALL mariadb_rpl_close(MARIADB_RPL *rpl)
{
  if (!rpl)
    return 1;
  if (rpl->buffer)
    free((void *)rpl->buffer);
  if (rpl->filename)
    free((void *)rpl->filename);
  free(rpl);
  return 0;
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
    rpl->filename_length= va_arg(ap, size_t);
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
      rpl->filename_length= strlen(rpl->filename);
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
  default:
    rc= -1;
    goto end;
  }
end:
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
    return 1;
    break;
  }
  return 0;
}
