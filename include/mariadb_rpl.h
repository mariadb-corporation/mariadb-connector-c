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
#define MARIADB_RPL_DUMP_GTID   (1 << 16)
#define MARIADB_RPL_SKIP_HEARTBEAT (1 << 17)

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

typedef struct st_mariadb_rpl {
  MYSQL *mysql;
  const char *filename;
  size_t filename_length;
  const unsigned char *buffer;
  unsigned long buffer_size;
  unsigned int server_id;
  unsigned long start_position;
  unsigned int flags;
} MARIADB_RPL;

/* Function prototypes */
MARIADB_RPL STDCALL *mariadb_rpl_init(MYSQL *mysql);
int mariadb_rpl_optionv(MARIADB_RPL *rpl, enum mariadb_rpl_option, ...);
int mariadb_rpl_get_optionv(MARIADB_RPL *rpl, enum mariadb_rpl_option, ...);
int STDCALL mariadb_rpl_open(MARIADB_RPL *rpl);
int STDCALL mariadb_rpl_close(MARIADB_RPL *rpl);
int STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl);

#endif
