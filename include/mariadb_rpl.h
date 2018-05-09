/* Copyright (C) 2018 MariaDB Corporation AB 

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
 
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
 
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02111-1301, USA */
#ifndef _mariadb_rpl_h_
#define _mariadb_rpl_h_

/* Protocol flags */
#define MARIADB_RPL_BINLOG_DUMP_NON_BLOCK 1
#define MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS 2
#define MARIADB_RPL_DUMP_GTID   (1 << 16)
#define MARIADB_RPL_IGNORE_HEARTBEAT (1 << 17)

/* Options */
enum mariadb_rpl_option {
  MARIADB_RPL_FILENAME,       /* Filename and length */
  MARIADB_RPL_START,          /* Start position */
  MARIADB_RPL_SERVER_ID,      /* Server ID */
  MARIADB_RPL_FLAGS,          /* Protocol flags */
  MARIADB_RPL_GTID_CALLBACK,  /* GTID callback function */
  MARIADB_RPL_GTID_DATA,      /* GTID data */
  MARIADB_RPL_BUFFER
};

/* Event types: From MariaDB Server sql/log_event.h */
enum mariadb_rpl_event {
  UNKNOWN_EVENT= 0,
  START_EVENT_V3= 1,
  QUERY_EVENT= 2,
  STOP_EVENT= 3,
  ROTATE_EVENT= 4,
  INTVAR_EVENT= 5,
  LOAD_EVENT= 6,
  SLAVE_EVENT= 7,
  CREATE_FILE_EVENT= 8,
  APPEND_BLOCK_EVENT= 9,
  EXEC_LOAD_EVENT= 10,
  DELETE_FILE_EVENT= 11,
  NEW_LOAD_EVENT= 12,
  RAND_EVENT= 13,
  USER_VAR_EVENT= 14,
  FORMAT_DESCRIPTION_EVENT= 15,
  XID_EVENT= 16,
  BEGIN_LOAD_QUERY_EVENT= 17,
  EXECUTE_LOAD_QUERY_EVENT= 18,
  TABLE_MAP_EVENT = 19,

  PRE_GA_WRITE_ROWS_EVENT = 20, /* deprecated */
  PRE_GA_UPDATE_ROWS_EVENT = 21, /* deprecated */
  PRE_GA_DELETE_ROWS_EVENT = 22, /* deprecated */

  WRITE_ROWS_EVENT_V1 = 23,
  UPDATE_ROWS_EVENT_V1 = 24,
  DELETE_ROWS_EVENT_V1 = 25,
  INCIDENT_EVENT= 26,
  HEARTBEAT_LOG_EVENT= 27,
  IGNORABLE_LOG_EVENT= 28,
  ROWS_QUERY_LOG_EVENT= 29,
  WRITE_ROWS_EVENT = 30,
  UPDATE_ROWS_EVENT = 31,
  DELETE_ROWS_EVENT = 32,
  GTID_LOG_EVENT= 33,
  ANONYMOUS_GTID_LOG_EVENT= 34,
  PREVIOUS_GTIDS_LOG_EVENT= 35,
  TRANSACTION_CONTEXT_EVENT= 36,
  VIEW_CHANGE_EVENT= 37,
  XA_PREPARE_LOG_EVENT= 38,

  /*
    Add new events here - right above this comment!
    Existing events (except ENUM_END_EVENT) should never change their numbers
  */

  /* New MySQL/Sun events are to be added right above this comment */
  MYSQL_EVENTS_END,

  MARIA_EVENTS_BEGIN= 160,
  ANNOTATE_ROWS_EVENT= 160,
  BINLOG_CHECKPOINT_EVENT= 161,
  GTID_EVENT= 162,
  GTID_LIST_EVENT= 163,
  START_ENCRYPTION_EVENT= 164,
  QUERY_COMPRESSED_EVENT = 165,
  WRITE_ROWS_COMPRESSED_EVENT_V1 = 166,
  UPDATE_ROWS_COMPRESSED_EVENT_V1 = 167,
  DELETE_ROWS_COMPRESSED_EVENT_V1 = 168,
  WRITE_ROWS_COMPRESSED_EVENT = 169,
  UPDATE_ROWS_COMPRESSED_EVENT = 170,
  DELETE_ROWS_COMPRESSED_EVENT = 171,

  /* Add new MariaDB events here - right above this comment!  */

  ENUM_END_EVENT /* end marker */
};

struct st_mariadb_rpl_rotate_log_hdr {
  unsigned long long position;
  size_t filename_length;
  const char *filename;
};

typedef struct st_mariadb_rpl {
  MYSQL *mysql;
  const char *filename;
  size_t filename_length;
  const unsigned char *buffer;
  unsigned long buffer_size;
  unsigned int server_id;
  unsigned long start_position;
  unsigned int flags;
  union {
    struct st_mariadb_rpl_rotate_log_hdr rotate_log;
  } event_hdr;
} MARIADB_RPL;

/* Function prototypes */
MARIADB_RPL STDCALL *mariadb_rpl_init(MYSQL *mysql);
int mariadb_rpl_optionsv(MARIADB_RPL *rpl, enum mariadb_rpl_option, ...);
int mariadb_rpl_get_optionsv(MARIADB_RPL *rpl, enum mariadb_rpl_option, ...);
int STDCALL mariadb_rpl_open(MARIADB_RPL *rpl);
int STDCALL mariadb_rpl_close(MARIADB_RPL *rpl);
int STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl);

#endif
