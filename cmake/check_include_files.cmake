#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
# This file is included by CMakeLists.txt and
# checks for various header files.
# You will find the appropriate defines in 
# include/my_config.h.in

INCLUDE(CheckIncludeFiles)

CHECK_INCLUDE_FILES (alloca.h HAVE_ALLOCA_H)
CHECK_INCLUDE_FILES (dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILES (fcntl.h HAVE_FCNTL_H)
CHECK_INCLUDE_FILES (float.h HAVE_FLOAT_H)
CHECK_INCLUDE_FILES (limits.h HAVE_LIMITS_H)
CHECK_INCLUDE_FILES (linux/limits.h HAVE_LINUX_LIMITS_H)
CHECK_INCLUDE_FILES (pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES (select.h HAVE_SELECT_H)

CHECK_INCLUDE_FILES (signal.h INCLUDE_SIGNAL)
IF(INCLUDE_SIGNAL)
  SET(CMAKE_EXTRA_INCLUDE_FILES signal.h)
ENDIF(INCLUDE_SIGNAL)

CHECK_INCLUDE_FILES (stddef.h HAVE_STDDEF_H)

CHECK_INCLUDE_FILES (stdint.h HAVE_STDINT_H)
IF(HAVE_STDINT_H)
  SET(CMAKE_EXTRA_INCLUDE_FILES stdint.h)
ENDIF(HAVE_STDINT_H)

CHECK_INCLUDE_FILES (stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES (string.h HAVE_STRING_H)

CHECK_INCLUDE_FILES (sys/ioctl.h HAVE_SYS_IOCTL_H)
CHECK_INCLUDE_FILES (sys/select.h HAVE_SYS_SELECT_H)
CHECK_INCLUDE_FILES (sys/socket.h HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES (sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES (sys/stat.h HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES (sys/un.h HAVE_SYS_UN_H)
CHECK_INCLUDE_FILES (unistd.h HAVE_UNISTD_H)
IF(WITH_BOOST_CONTEXT)
  CHECK_INCLUDE_FILE_CXX (boost/fiber/context.hpp HAVE_BOOST_CONTEXT_H)
ENDIF()

IF(APPLE)
  SET(CMAKE_REQUIRED_DEFINITIONS -D_XOPEN_SOURCE=600)
ENDIF()
CHECK_INCLUDE_FILES (ucontext.h HAVE_FILE_UCONTEXT_H)
IF(NOT HAVE_FILE_UCONTEXT_H)
  CHECK_INCLUDE_FILES (sys/ucontext.h HAVE_FILE_UCONTEXT_H)
ENDIF()
