/************************************************************************************
  Copyright (C) 2023 MariaDB plc

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

#ifndef __ma_helper_h__

#define __ma_helper_h__

#ifdef _WIN32

#include <windows.h>

extern RTL_OSVERSIONINFOW ma_windows_version;

typedef LONG NTSTATUS, * PNTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS (0x00000000)
#endif
typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

void ma_get_windows_version();

enum enum_version_compare {
  VERSION_LESS = 0,
  VERSION_LESS_OR_EQUAL = 1,
  VERSION_EQUAL = 2,
  VERSION_GREATER_OR_EQUAL = 3,
  VERSION_GREATER = 4
};

int ma_check_windows_version(enum enum_version_compare, DWORD major, DWORD minor, DWORD build);

#endif

#endif /* __ma_helper_h__ */
