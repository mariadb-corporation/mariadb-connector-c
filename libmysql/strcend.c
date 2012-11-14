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

/*  File   : strcend.c
    Author : Michael Widenius:	ifdef MC68000
    Updated: 20 April 1984
    Defines: strcend()

    strcend(s, c) returns a pointer to the  first  place  in  s where  c
    occurs,  or a pointer to the end-null of s if c does not occur in s.
*/

#include <my_global.h>
#include "m_string.h"

/**
 \fn     char *strcend
 \brief  returns a pointer to the first occurence of specified stopchar
 \param  str char *
 \param  stopchar char

 returns a poimter to the first occurence of stopchar or to null char,
 if stopchar wasn't found.
*/
char *strcend(register const char *str, register char stopchar)
{
  for (;;)
  {
     if (*str == stopchar)
       return (char*) str;
     if (!*str++) 
       return (char*) str-1;
  }
}
