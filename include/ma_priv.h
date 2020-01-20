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
MYSQL_FIELD * unpack_fields(MYSQL_DATA *data,
                            MA_MEM_ROOT *alloc,uint fields,
                            my_bool default_value);

#endif
