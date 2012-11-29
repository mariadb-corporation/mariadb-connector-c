INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include 
                    ${ZLIB_INC}
                    ${CMAKE_SOURCE_DIR}/libmysql)
					
IF(OPENSSL_FOUND)
 INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
ENDIF()


ADD_DEFINITIONS(-D ENABLED_LOCAL_INFILE)
ADD_DEFINITIONS(-D HAVE_COMPRESS)
ADD_DEFINITIONS(-D THREAD)

SET(LIBMYSQL_SOURCES 
array.c 
bchange.c 
bmove.c 
bmove_upp.c 
my_charset.c 
violite.c 
net.c
charset.c
dbug.c
default.c
errmsg.c
my_vsnprintf.c
errors.c
getopt1.c
getopt.c 
get_password.c
int2str.c
is_prefix.c
libmysql.c
list.c
llstr.c
longlong2str.c 
mf_dirname.c 
mf_fn_ext.c 
mf_format.c
mf_loadpath.c 
mf_pack.c 
mf_path.c
mf_tempfile.c 
mf_unixpath.c
mf_wcomp.c
mulalloc.c 
my_alloc.c
my_compress.c
my_create.c
my_delete.c
my_div.c
my_error.c 
my_fopen.c
my_fstream.c
my_gethostbyname.c
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
password.c 
safemalloc.c
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
my_secure.c
libmysql_exports.def
)



IF(ZLIB_FOUND)
  INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIR})
  LINK_LIBRARIES(${ZLIB_LIBRARY})
ELSE()
  SET(ZLIB_SOURCES
    ../zlib/adler32.c 
    ../zlib/compress.c
    ../zlib/crc32.c
    ../zlib/deflate.c
    ../zlib/example.c
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
  SET(LIBMYSQL_SOURCES ${LIBMYSQL_SOURCES} ${ZLIB_SOURCES})
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/zlib)
ENDIF()


ADD_LIBRARY(mariadbclient STATIC ${LIBMYSQL_SOURCES})
TARGET_LINK_LIBRARIES(mariadbclient ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
IF(OPENSSL_FOUND)
  TARGET_LINK_LIBRARIES(mariadbclient ${OPENSSL_LIBRARIES})
ENDIF()

ADD_LIBRARY(libmariadb SHARED ${LIBMYSQL_SOURCES})
TARGET_LINK_LIBRARIES(libmariadb ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

IF(OPENSSL_FOUND)
  TARGET_LINK_LIBRARIES(libmariadb ${OPENSSL_LIBRARIES})
ENDIF()


IF(WIN32)
  TARGET_LINK_LIBRARIES(libmariadb ws2_32)
  TARGET_LINK_LIBRARIES(mariadbclient ws2_32)
ELSE()
  TARGET_LINK_LIBRARIES(libmariadb m)
  TARGET_LINK_LIBRARIES(mariadbclient m)
ENDIF()

IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
  TARGET_LINK_LIBRARIES (libmariadb "-Wl,--no-undefined")
  TARGET_LINK_LIBRARIES (libmariadb "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/version_script.txt")
ENDIF()

SET_TARGET_PROPERTIES(libmariadb PROPERTIES PREFIX "")

SET_TARGET_PROPERTIES(libmariadb PROPERTIES VERSION 
   ${CPACK_PACKAGE_VERSION_MAJOR}
   SOVERSION ${CPACK_PACKAGE_VERSION_MAJOR})

#
# Installation
#

INSTALL(TARGETS
          libmariadb mariadbclient
          RUNTIME DESTINATION "lib"
          LIBRARY DESTINATION "lib"
          ARCHIVE DESTINATION "lib")

INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include
        DESTINATION mariadbclient)
INSTALL(FILES 
   ${CMAKE_BINARY_DIR}/include/my_config.h
   ${CMAKE_BINARY_DIR}/include/mysql_version.h
   DESTINATION mariadbclient/include
)
