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

   Part of this code includes code from the PHP project which
   is freely available from http://www.php.net
*************************************************************************************/
#include "ma_global.h"
#include "ma_helper.h"

#ifdef _WIN32

/* Get Windows version without manifest. This solution is based on answer
   https://stackoverflow.com/questions/36543301/detecting-windows-10-version/36543774#36543774 */

RTL_OSVERSIONINFOW ma_windows_version;

void ma_get_windows_version() {
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  if (module) {
    RtlGetVersionPtr funcPtr;
    if ((funcPtr = (RtlGetVersionPtr)GetProcAddress(module, "RtlGetVersion")))
    {
       ma_windows_version.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
       if ((funcPtr(&ma_windows_version) == STATUS_SUCCESS))
         return;
     
    }
  }
  memset(&ma_windows_version, 0, sizeof(PRTL_OSVERSIONINFOW));
  return;
}

int ma_check_windows_version(enum enum_version_compare compare, DWORD major, DWORD minor, DWORD build)
{
  switch (compare) {
    case VERSION_LESS:
      if (ma_windows_version.dwMajorVersion < major ||
         (ma_windows_version.dwMajorVersion == major &&
          ma_windows_version.dwMinorVersion < minor) ||
         (build &&
          (ma_windows_version.dwMajorVersion == major &&
            ma_windows_version.dwMinorVersion == minor &&
            ma_windows_version.dwBuildNumber < build)))
        return 1;
      break;
    case VERSION_LESS_OR_EQUAL:
      if (ma_windows_version.dwMajorVersion < major ||
        (ma_windows_version.dwMajorVersion == major &&
          ma_windows_version.dwMinorVersion < minor) ||
        (ma_windows_version.dwMajorVersion == major &&
          ma_windows_version.dwMinorVersion == minor&&
          (build == 0 ||
            ma_windows_version.dwBuildNumber <= build)))
        return 1;
      break;

    case VERSION_EQUAL:
      if (ma_windows_version.dwMajorVersion == major &&
        ma_windows_version.dwMinorVersion == minor &&
        (build == 0 ||
          ma_windows_version.dwBuildNumber == build))
        return 1;
      break;

    case VERSION_GREATER_OR_EQUAL:
      if (ma_windows_version.dwMajorVersion > major ||
        (ma_windows_version.dwMajorVersion == major &&
          ma_windows_version.dwMinorVersion > minor) ||
        (ma_windows_version.dwMajorVersion == major &&
          ma_windows_version.dwMinorVersion == minor &&
          (build == 0 ||
            ma_windows_version.dwBuildNumber >= build)))
        return 1;
      break;

    case VERSION_GREATER:
      if (ma_windows_version.dwMajorVersion > major ||
        (ma_windows_version.dwMajorVersion == major &&
          ma_windows_version.dwMinorVersion > minor) ||
        (build != 0 &&
          (ma_windows_version.dwMajorVersion == major &&
            ma_windows_version.dwMinorVersion == minor &&
            ma_windows_version.dwBuildNumber > build)))
        return 1;
      break;

    default:
      return 0;
      
  }
  return 0;
}

#endif
