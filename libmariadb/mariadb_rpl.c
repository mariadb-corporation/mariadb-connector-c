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

MARIADB_RPL STDCALL *mariadb_rpl_init(MYSQL *mysql)
{
  MARIADB_RPL *rpl;

  if (!mysql)
    return NULL;

  if (!(rpl= (MARIADB_RPL *)calloc(1, sizeof(MARIADB_RPL))))
  {
    SET_CLIENT_ERROR(mysql, CR_OUT_OF_MEMORY, SQLSTATE_UNKNOWN, 0);
    return 0;
  }
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

int STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl)
{
  if (!rpl || !rpl->mysql)
    return 1;

  while (1) {
    unsigned long pkt_len= ma_net_safe_read(rpl->mysql);

    if (pkt_len == packet_error)
      return -1;

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
      enum mariadb_rpl_event event= rpl->mysql->net.read_pos[1 + 4];
      if (event == HEARTBEAT_LOG_EVENT)
        continue;
    }

    rpl->buffer_size= pkt_len;
    rpl->buffer = rpl->mysql->net.read_pos;
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
      rpl->filename= (const char *)malloc(rpl->filename_length);
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
  int rc= 0;

  if (!rpl)
    return 1;

  va_start(ap, option);

  switch (option) {
  case MARIADB_RPL_FILENAME:
  {
    const char **name= va_arg(ap, char **);
    size_t *len= va_arg(ap, size_t *);

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
}
