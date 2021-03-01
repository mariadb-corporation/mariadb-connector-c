/************************************************************************************
    Copyright (C) 2021 MariaDB AB

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
*************************************************************************************/

#include <ma_global.h>
#include <ma_sys.h>

/**
 * Expands symbolic links and resolves references like '.', '\..'.
 * resulting path name is stored in buffer as a null terminated string
 *
 * @param pathname[in]   (relative) path or file name
 * @param buffer[in/out] absolute path
 * @param buflen[in]     length of allocated buffer for absolute path
 *
 * @return               Zero on success, otherwise error number
 */
int ma_realpath(const char *pathname, char *buffer, size_t buflen)
{
  if (!buflen)
    return ENAMETOOLONG;
#ifdef WIN32
  if (!GetFullPathName(pathname, (DWORD)buflen, buffer, NULL))
    return GetLastError();
#else
  if (!realpath(pathname, buffer))
    return errno;
#endif
  return 0;
}

/**
 * Helper function which checks file type for absolute
 * pathname.
 *
 * @param pathname[in]   absolute path
 * @param flag[in]       flag, e.g. S_IFDIR, S_IFREF
 *
 * @return  1 if the file has the specified flag, otherwise 0.
**/
int ma_check_file_type(const char *pathname, int flag)
{
#ifndef _WIN32
  struct stat st;

  if (stat(pathname, &st))
#else
  struct _stat st;

  if (_stat(pathname, &st))
#endif
    return 0;

  return (st.st_mode & flag);
}
