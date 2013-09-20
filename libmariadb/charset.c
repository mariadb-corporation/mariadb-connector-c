/* Copyright (C) 2000 MySQL AB & MySQL Finland AB & TCX DataKonsult AB
   
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
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA */

#include "mysys_priv.h"
#include "mysys_err.h"
#include <m_ctype.h>
#include <m_string.h>
#include <my_dir.h>

CHARSET_INFO *default_charset_info = (CHARSET_INFO *)&compiled_charsets[5];
CHARSET_INFO *my_charset_bin= (CHARSET_INFO *)&compiled_charsets[32];
CHARSET_INFO *my_charset_latin1= (CHARSET_INFO *)&compiled_charsets[5];
CHARSET_INFO *my_charset_utf8_general_ci= (CHARSET_INFO *)&compiled_charsets[21];

CHARSET_INFO * STDCALL mysql_get_charset_by_nr(uint cs_number)
{
  int i= 0;

  while (compiled_charsets[i].nr && cs_number != compiled_charsets[i].nr)
    i++;
  
  return (compiled_charsets[i].nr) ? (CHARSET_INFO *)&compiled_charsets[i] : NULL;
}

my_bool set_default_charset(uint cs, myf flags)
{
  CHARSET_INFO *new_charset;
  DBUG_ENTER("set_default_charset");
  DBUG_PRINT("enter",("character set: %d",(int) cs));
  new_charset = mysql_get_charset_by_nr(cs);
  if (!new_charset)
  {
    DBUG_PRINT("error",("Couldn't set default character set"));
    DBUG_RETURN(TRUE);   /* error */
  }
  default_charset_info = new_charset;
  DBUG_RETURN(FALSE);
}

CHARSET_INFO * STDCALL mysql_get_charset_by_name(const char *cs_name)
{
  int i= 0;

  while (compiled_charsets[i].nr && strcmp(cs_name, compiled_charsets[i].csname) != 0)
    i++;
 
  return (compiled_charsets[i].nr) ? (CHARSET_INFO *)&compiled_charsets[i] : NULL;
}

my_bool set_default_charset_by_name(const char *cs_name, myf flags)
{
  CHARSET_INFO *new_charset;
  DBUG_ENTER("set_default_charset_by_name");
  DBUG_PRINT("enter",("character set: %s", cs_name));
  new_charset = mysql_get_charset_by_name(cs_name);
  if (!new_charset)
  {
    DBUG_PRINT("error",("Couldn't set default character set"));
    DBUG_RETURN(TRUE);   /* error */
  }

  default_charset_info = new_charset;
  DBUG_RETURN(FALSE);
}
