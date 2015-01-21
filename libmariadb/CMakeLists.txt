INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include 
                    ${ZLIB_INC}
                    ${CMAKE_SOURCE_DIR}/libmariadb)
					
ADD_DEFINITIONS(-D ENABLED_LOCAL_INFILE)
ADD_DEFINITIONS(-D HAVE_COMPRESS)
ADD_DEFINITIONS(-D LIBMARIADB)
ADD_DEFINITIONS(-D THREAD)

SET(LIBMARIADB_SOURCES 
array.c 
ma_dyncol.c
bchange.c 
bmove.c 
bmove_upp.c 
my_charset.c
hash.c
violite.c 
net.c
charset.c
ma_time.c
dbug.c
default.c
errmsg.c
my_vsnprintf.c
errors.c
getopt1.c
getopt.c 
int2str.c
is_prefix.c
libmariadb.c
list.c
llstr.c
longlong2str.c 
mf_dirname.c 
mf_fn_ext.c 
mf_format.c
mf_loadpath.c 
mf_pack.c 
mf_path.c
mf_unixpath.c
mf_wcomp.c
mulalloc.c 
my_alloc.c
my_compress.c
my_context.c
my_div.c
my_error.c 
my_fopen.c
my_fstream.c
my_getwd.c
my_init.c
my_lib.c
my_malloc.c
my_messnc.c
my_net.c
my_once.c
my_open.c
my_port.c 
my_pthread.c
my_read.c
my_realloc.c
my_seek.c
my_static.c
my_symlink.c
my_thr_init.c
my_write.c
mysql_async.c
password.c 
str2int.c
strcend.c
strcont.c 
strend.c
strfill.c
string.c
strinstr.c
strmake.c
strmov.c
strnmov.c
strtoll.c
strtoull.c 
strxmov.c
strxnmov.c
thr_mutex.c
typelib.c
sha1.c
my_stmt.c
my_loaddata.c
my_stmt_codec.c
client_plugin.c
my_auth.c
ma_secure.c
)

IF(MSVC)
  SET(EXPORT_FILE libmariadb_exports.def)
ENDIF()

IF(WIN32)
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/win-iconv)
  SET(LIBMARIADB_SOURCES ${LIBMARIADB_SOURCES}
                         ${CMAKE_SOURCE_DIR}/win-iconv/win_iconv.c)
ENDIF()

IF(WITH_SQLITE)
  SET(LIBMARIADB_SOURCES ${LIBMARIADB_SOURCES}
                         ${CMAKE_SOURCE_DIR}/plugins/sqlite/sqlite3.c
                         ${CMAKE_SOURCE_DIR}/plugins/sqlite/sqlite_client_plugin.c)
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/plugins/sqlite)
  ADD_DEFINITIONS(-DSQLITE_ENABLE_COLUMN_METADATA=1)
ENDIF()

IF(ZLIB_FOUND)
  INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIR})
  LINK_LIBRARIES(${ZLIB_LIBRARY})
ELSE()
  SET(ZLIB_SOURCES
    ../zlib/adler32.c 
    ../zlib/compress.c
    ../zlib/crc32.c
    ../zlib/deflate.c
    ../zlib/gzclose.c
    ../zlib/gzlib.c
    ../zlib/gzread.c
    ../zlib/gzwrite.c
    ../zlib/infback.c
    ../zlib/inffast.c
    ../zlib/inflate.c
    ../zlib/inftrees.c
    ../zlib/trees.c
    ../zlib/uncompr.c
    ../zlib/zutil.c
  )
SET(LIBMARIADB_SOURCES ${LIBMARIADB_SOURCES} ${ZLIB_SOURCES})
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/zlib)
ENDIF()

# CREATE OBJECT LIBRARY 
ADD_LIBRARY(mariadb_obj OBJECT ${LIBMARIADB_SOURCES})
IF(UNIX)
  SET_TARGET_PROPERTIES(mariadb_obj PROPERTIES COMPILE_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
ENDIF()

ADD_LIBRARY(mariadbclient STATIC $<TARGET_OBJECTS:mariadb_obj> ${EXPORT_FILE})
TARGET_LINK_LIBRARIES(mariadbclient ${SYSTEM_LIBS})

ADD_LIBRARY(libmariadb SHARED $<TARGET_OBJECTS:mariadb_obj> ${EXPORT_FILE})
TARGET_LINK_LIBRARIES(libmariadb ${SYSTEM_LIBS})
IF(UNIX)
  SET_TARGET_PROPERTIES(libmariadb PROPERTIES COMPILE_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
ENDIF()

IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
  TARGET_LINK_LIBRARIES (libmariadb "-Wl,--no-undefined")
  TARGET_LINK_LIBRARIES (libmariadb "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/version_script.txt")
  TARGET_LINK_LIBRARIES (mariadbclient "-Wl,--no-undefined")
  TARGET_LINK_LIBRARIES (mariadbclient "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/version_script.txt")
ENDIF()

SET_TARGET_PROPERTIES(libmariadb PROPERTIES PREFIX "")

SET_TARGET_PROPERTIES(libmariadb PROPERTIES VERSION 
   ${CPACK_PACKAGE_VERSION_MAJOR}
   SOVERSION ${CPACK_PACKAGE_VERSION_MAJOR})

#
# Installation
#

# There are still several projects which don't make use
# of the config program. To make sure these programs can
# use mariadb client library we provide libmysql symlinks
IF(NOT WIN32 AND WITH_MYSQLCOMPAT)
  ADD_CUSTOM_COMMAND(OUTPUT "libmysql${CMAKE_SHARED_LIBRARY_SUFFIX}"
                            "libmysqlclient${CMAKE_SHARED_LIBRARY_SUFFIX}"
                            "libmysqlclient_r${CMAKE_SHARED_LIBRARY_SUFFIX}"
                            "libmysqlclient${CMAKE_STATIC_LIBRARY_SUFFIX}"
                     COMMAND ${CMAKE_COMMAND} ARGS -E remove -f libmysql${CMAKE_SHARED_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E create_symlink libmariadb${CMAKE_SHARED_LIBRARY_SUFFIX} libmysql${CMAKE_SHARED_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E remove -f libmysqlclient_r${CMAKE_SHARED_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E create_symlink libmariadb${CMAKE_SHARED_LIBRARY_SUFFIX} libmysqlclient_r${CMAKE_SHARED_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E remove -f libmysqlclient${CMAKE_SHARED_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E create_symlink libmariadb${CMAKE_SHARED_LIBRARY_SUFFIX} libmysqlclient${CMAKE_SHARED_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E remove -f libmysqlclient${CMAKE_STATIC_LIBRARY_SUFFIX}
                     COMMAND ${CMAKE_COMMAND} ARGS -E create_symlink libmariadbclient${CMAKE_STATIC_LIBRARY_SUFFIX} libmysqlclient${CMAKE_STATIC_LIBRARY_SUFFIX}
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/libmariadb
                    DEPENDS libmariadb mariadbclient)

ADD_CUSTOM_TARGET(LIBMYSQL_SYMLINKS
                  ALL
                  DEPENDS "libmysql${CMAKE_SHARED_LIBRARY_SUFFIX}"
                          "libmysqlclient_r${CMAKE_SHARED_LIBRARY_SUFFIX}"
                          "libmysqlclient${CMAKE_SHARED_LIBRARY_SUFFIX}"
                          "libmysqlclient${CMAKE_STATIC_LIBRARY_SUFFIX}"
                  VERBATIM)
ENDIF()


INSTALL(TARGETS
          libmariadb mariadbclient
          RUNTIME DESTINATION "${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}"
          LIBRARY DESTINATION "${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}"
          ARCHIVE DESTINATION "${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}")

IF(NOT WIN32 AND WITH_MYSQLCOMPAT)
  INSTALL(FILES "${CMAKE_BINARY_DIR}/libmariadb/libmysql${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "${CMAKE_BINARY_DIR}/libmariadb/libmysqlclient${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "${CMAKE_BINARY_DIR}/libmariadb/libmysqlclient_r${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "${CMAKE_BINARY_DIR}/libmariadb/libmysqlclient${CMAKE_STATIC_LIBRARY_SUFFIX}"
                DESTINATION ${LIB_INSTALL_DIR}/mariadb)
ENDIF()

INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
        DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR})
INSTALL(FILES 
   ${CMAKE_BINARY_DIR}/include/my_config.h
   ${CMAKE_BINARY_DIR}/include/mysql_version.h
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR})


