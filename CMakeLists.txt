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
SET(MYSQL_CLIENT_VERSION "3.23.59")
SET(MYSQL_VERSION_ID "32359")
IF (NOT MYSQL_PORT)
  SET(MYSQL_PORT 3306)
ENDIF (NOT MYSQL_PORT)

SET(SHAREDIR "share")
SET(DEFAULT_CHARSET_HOME "${CMAKE_INSTALL_PREFIX}")

# check for various include files
INCLUDE(LibmysqlIncludeFiles.txt)
# check for various functions
INCLUDE(LibmysqlFunctions.txt)
# check for various types
INCLUDE(LibmysqlTypes.txt)

#Check for threads
IF(WIN32)
  SET(HAVE_THREADS 1)
ELSEIF(WIN32)
  SET(HAVE_THREADS ${CMAKE_USE_PTHREADS})
ENDIF(WIN32)


MESSAGE(STATUS "writing configuration files")
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/include/mysql_version.h.in
               ${CMAKE_CURRENT_SOURCE_DIR}/include/mysql_version.h)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/include/my_config.h.in
               ${CMAKE_CURRENT_SOURCE_DIR}/include/my_config.h)

ADD_SUBDIRECTORY(zlib)
ADD_SUBDIRECTORY(libmysql)

IF(IS_DIRECTORY unittest)
MESSAGE(STATUS "found unittests")
ADD_SUBDIRECTORY(unittest/mytap)
ADD_SUBDIRECTORY(unittest/libmysql)
ENDIF(IS_DIRECTORY unittest)
