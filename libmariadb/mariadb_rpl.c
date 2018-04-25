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

#include <mysql.h>
#include <errmsg.h>
#include <stdlib.h>
#include <string.h>

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
  if (!rpl || !rpl->mysql)
    return 1;
  return 0;
}

int STDCALL mariadb_rpl_fetch(MARIADB_RPL *rpl)
{
  if (!rpl || !rpl->mysql)
    return 1;
  return 0;
}

int STDCALL mariadb_rpl_close(MARIADB_RPL *rpl)
{
  if (!rpl)
    return 1;
  if (rpl->buffer)
    free((void *)rpl->buffer);
  free(rpl);
  return 0;
}

int mariadb_rpl_optionv(MARIADB_RPL *rpl,
                        enum mariadb_rpl_option option,
                        ...)
{
  if (!rpl)
    return 1;

  switch (option) {
    default:
      return -1;
  }
  return 0;
}
