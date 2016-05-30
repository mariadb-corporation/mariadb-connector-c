#
#  Copyright (C) 2010  Michael Bell <michael.bell@web.de>
#                2015-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the  COPYING-CMAKE-SCRIPTS file.
#
#  ICONV_EXTERNAL - Iconv is an external library (not libc)
#  ICONV_FOUND - system has Iconv
#  ICONV_INCLUDE_DIR - the Iconv include directory
#  ICONV_LIBRARIES - Link these to use Iconv
#  ICONV_SECOND_ARGUMENT_IS_CONST - the second argument for iconv() is const
#  ICONV_VERSION - Iconv version string
#
include(CheckCSourceCompiles)

find_path(ICONV_INCLUDE_DIR iconv.h)

IF(CMAKE_SYSTEM_NAME MATCHES "SunOS")
  # There is some libiconv.so in  /usr/local that must
  # be avoided, iconv routines are in libc  
  find_library(ICONV_LIBRARIES NAMES c)
ELSEIF(APPLE)
  find_library(ICONV_LIBRARIES NAMES iconv libiconv PATHS
               /usr/lib/
               NO_CMAKE_SYSTEM_PATH)
    set(ICONV_EXTERNAL TRUE)
ELSE()
  find_library(ICONV_LIBRARIES NAMES iconv libiconv libiconv-2)
  IF(ICONV_LIBRARIES)
    set(ICONV_EXTERNAL TRUE)
  ELSE()
    find_library(ICONV_LIBRARIES NAMES c)
  ENDIF()
ENDIF()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(ICONV REQUIRED_VARS ICONV_LIBRARIES ICONV_INCLUDE_DIR VERSION_VAR ICONV_VERSION)

if (ICONV_FOUND)
  check_c_source_compiles("
  #include <iconv.h>
  int main(){
    iconv_t conv = 0;
    const char* in = 0;
    size_t ilen = 0;
    char* out = 0;
    size_t olen = 0;
    iconv(conv, &in, &ilen, &out, &olen);
    return 0;
  }
" ICONV_SECOND_ARGUMENT_IS_CONST )

  set(CMAKE_REQUIRED_INCLUDES ${ICONV_INCLUDE_DIR})
  set(CMAKE_REQUIRED_LIBRARIES ${ICONV_LIBRARIES})
endif(ICONV_FOUND)

mark_as_advanced(
  ICONV_INCLUDE_DIR
  ICONV_LIBRARIES
  ICONV_SECOND_ARGUMENT_IS_CONST
)

