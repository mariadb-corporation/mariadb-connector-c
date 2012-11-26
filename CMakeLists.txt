# CMakeLists.txt


# This is the libmysql-lgpl project.
PROJECT(mariadb-client)

# Minimum required version is Cmake 2.6.x
CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)
IF(COMMAND CMAKE_POLICY)
  CMAKE_POLICY(SET CMP0003 NEW)
ENDIF(COMMAND CMAKE_POLICY)

# If the build type isn't specified, set to Release as default.
# This will make your life easier on Windows.
IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE "Release")
ENDIF(NOT CMAKE_BUILD_TYPE)

# Generic compiler flags for GNU C/C++ compiler
IF(CMAKE_COMPILER_IS_GNUCXX)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-rtti -fno-exceptions")
  SET(CMAKE_CXX_COMPILER "${CMAKE_C_COMPILER}" CACHE INTERNAL "C++ Compiler" FORCE)
ENDIF(CMAKE_COMPILER_IS_GNUCXX)

# various defines for generating include/mysql_version.h
SET(PROTOCOL_VERSION 10) # we adapted new password option from PHP's mysqlnd !
SET(MYSQL_CLIENT_VERSION_MAJOR "5")
SET(MYSQL_CLIENT_VERSION_MINOR "3")
SET(MYSQL_CLIENT_VERSION_PATCH "1")
SET(MYSQL_CLIENT_VERSION "${MYSQL_CLIENT_VERSION_MAJOR}.${MYSQL_CLIENT_VERSION_MINOR}.${MYSQL_CLIENT_VERSION_PATCH}")
MATH(EXPR MYSQL_VERSION_ID "${MYSQL_CLIENT_VERSION_MAJOR} * 10000 +
                            ${MYSQL_CLIENT_VERSION_MINOR} * 100   +
                            ${MYSQL_CLIENT_VERSION_PATCH}")
IF (NOT MYSQL_PORT)
  SET(MYSQL_PORT 3306)
ENDIF (NOT MYSQL_PORT)
IF(NOT MYSQL_UNIX_ADDR)
  SET(MYSQL_UNIX_ADDR "/tmp/mysql.sock")
ENDIF(NOT MYSQL_UNIX_ADDR)

# todo: we don't character sets in share - all is compiled in
SET(SHAREDIR "share")
SET(DEFAULT_CHARSET_HOME "${CMAKE_INSTALL_PREFIX}")

FIND_PACKAGE(Threads)

IF(${CMAKE_HAVE_PTHREAD_H})
  SET(CMAKE_REQUIRED_INCLUDES pthread.h)
ENDIF(${CMAKE_HAVE_PTHREAD_H})
#Check for threads
IF(WIN32)
  SET(HAVE_THREADS 1)
  ADD_DEFINITIONS(-DHAVE_DLOPEN)
  ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996" )
ELSEIF(WIN32)
  SET(HAVE_THREADS ${CMAKE_USE_PTHREADS})
ENDIF(WIN32)

FIND_LIBRARY(DL_LIBRARY dl)
IF(DL_LIBRARY)
  SET(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} ${CMAKE_DL_LIBS})
ENDIF(DL_LIBRARY)

# check for various include files
INCLUDE(LibmysqlIncludeFiles.txt)
# check for various functions
INCLUDE(LibmysqlFunctions.txt)
# check for various types
INCLUDE(LibmysqlTypes.txt)



# Check for OpenSSL
INCLUDE(FindOpenSSL)
IF(OPENSSL_FOUND)
  ADD_DEFINITIONS(-DHAVE_OPENSSL)
ENDIF(OPENSSL_FOUND)

MESSAGE(STATUS "writing configuration files")
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/include/mysql_version.h.in
               ${CMAKE_CURRENT_SOURCE_DIR}/include/mysql_version.h)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/include/my_config.h.in
               ${CMAKE_CURRENT_SOURCE_DIR}/include/my_config.h)

ADD_SUBDIRECTORY(zlib)
ADD_SUBDIRECTORY(libmysql)
ADD_SUBDIRECTORY(examples)
IF(NOT WIN32)
  ADD_SUBDIRECTORY(mysql_config)
ENDIF(NOT WIN32)

IF(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/unittest)
  MESSAGE(STATUS "found unittests")
  ADD_SUBDIRECTORY(unittest/mytap)
  ADD_SUBDIRECTORY(unittest/libmysql)
ENDIF(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/unittest)

IF(WIN32)
 SET(CMAKE_INSTALL_PREFIX "")
ENDIF(WIN32)


SET(CPACK_VERSION_MAJOR ${MYSQL_CLIENT_VERSION_MAJOR})
SET(CPACK_VERSION_MINOR ${MYSQL_CLIENT_VERSION_MINOR})
SET(CPACK_VERSION_PATCH ${MYSQL_CLIENT_VERSION_PATCH})

SET(CPACK_PACKAGE_VENDOR "Monty Program AB")
SET(CPACK_PACKAGE_DESCRIPTION "MariaDB client library. A library for connecting to MariaDB and MySQL servers")
SET(CPACK_PACKAGE_NAME "mariadb_client")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING.LIB")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${MYSQL_CLIENT_VERSION}-src")

SET(CPACK_SOURCE_IGNORE_FILES
.bzr/
CMakeCache.txt
cmake_dist.cmake
CPackSourceConfig.cmake
CPackConfig.cmake
.build/
html/
unittest
/cmake_install.cmake
/CTestTestfile.cmake
/CMakeFiles/
/version_resources/
/_CPack_Packages/
.*gz$
.*zip$
.*so$
.*so.*$
.*dll$
.*a$
.*pdb$
/CMakeFiles/
/version_resources/
/_CPack_Packages/
Makefile$
include/my_config.h$
/autom4te.cache/
errmsg.sys$
)

IF(NOT WIN32)
  SET(CPACK_GENERATOR "TGZ")
  SET(CPACK_SOURCE_GENERATOR "TGZ")
ELSEIF(NOT WIN32)
  SET(CPACK_GENERATOR "ZIP")
  SET(CPACK_SOURCE_GENERATOR "ZIP")
ENDIF(NOT WIN32)

INCLUDE(CPack)
