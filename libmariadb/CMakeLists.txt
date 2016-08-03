INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include 
                    ${ZLIB_INC}
                    ${CMAKE_SOURCE_DIR}/libmariadb)
					
ADD_DEFINITIONS(-D ENABLED_LOCAL_INFILE)
ADD_DEFINITIONS(-D HAVE_COMPRESS)
ADD_DEFINITIONS(-D LIBMARIADB)
ADD_DEFINITIONS(-D THREAD)

SET(EXPORT_SYMBOLS
 load_defaults
 mariadb_connection
 mariadb_convert_string
 mariadb_dyncol_check
 mariadb_dyncol_column_cmp_named
 mariadb_dyncol_column_count
 mariadb_dyncol_create_many_named
 mariadb_dyncol_create_many_num
 mariadb_dyncol_exists_named
 mariadb_dyncol_exists_num
 mariadb_dyncol_free
 mariadb_dyncol_get_named
 mariadb_dyncol_get_num
 mariadb_dyncol_has_names
 mariadb_dyncol_json
 mariadb_dyncol_list_named
 mariadb_dyncol_list_num
 mariadb_dyncol_unpack
 mariadb_dyncol_update_many_named
 mariadb_dyncol_update_many_num
 mariadb_dyncol_val_double
 mariadb_dyncol_val_long
 mariadb_dyncol_val_str
 myodbc_remove_escape
 mysql_affected_rows
 mysql_autocommit
 mysql_autocommit_cont
 mysql_autocommit_start
 mysql_change_user
 mysql_change_user_cont
 mysql_change_user_start
 mysql_character_set_name
 mysql_client_find_plugin
 mysql_client_register_plugin
 mysql_close
 mysql_close_cont
 mysql_close_start
 mysql_commit
 mysql_commit_cont
 mysql_commit_start
 mysql_data_seek
 mysql_debug
 mysql_dump_debug_info
 mysql_dump_debug_info_cont
 mysql_dump_debug_info_start
 mysql_eof
 mysql_errno
 mysql_error
 mysql_escape_string
 mysql_fetch_field
 mysql_fetch_field_direct
 mysql_fetch_fields
 mysql_fetch_lengths
 mysql_fetch_row
 mysql_fetch_row_cont
 mysql_fetch_row_start
 mysql_field_count
 mysql_field_seek
 mysql_field_tell
 mysql_free_result
 mysql_free_result_cont
 mysql_free_result_start
 mysql_get_character_set_info
 mysql_get_charset_by_name
 mysql_get_charset_by_nr
 mysql_get_client_info
 mysql_get_client_version
 mysql_get_host_info
 mysql_get_parameters
 mysql_get_proto_info
 mysql_get_server_info
 mysql_get_server_name
 mysql_get_server_version
 mysql_get_socket
 mysql_get_ssl_cipher
 mysql_get_timeout_value
 mysql_get_timeout_value_ms
 mysql_hex_string
 mysql_info
 mysql_init
 mysql_insert_id
 mysql_kill
 mysql_kill_cont
 mysql_kill_start
 mysql_list_dbs
 mysql_list_dbs_cont
 mysql_list_dbs_start
 mysql_list_fields
 mysql_list_fields_cont
 mysql_list_fields_start
 mysql_list_processes
 mysql_list_processes_cont
 mysql_list_processes_start
 mysql_list_tables
 mysql_list_tables_cont
 mysql_list_tables_start
 mysql_load_plugin;
 mysql_load_plugin_v
 mysql_more_results
 mysql_next_result
 mysql_next_result_cont
 mysql_next_result_start
 mysql_num_fields
 mysql_num_rows
 mysql_options
 mysql_optionsv
 mysql_ping
 mysql_ping_cont
 mysql_ping_start
 mysql_ps_fetch_functions
 mysql_query
 mysql_query_cont
 mysql_query_start
 mysql_read_query_result
 mysql_read_query_result_cont
 mysql_read_query_result_start
 mysql_real_connect
 mysql_real_connect_cont
 mysql_real_connect_start
 mysql_real_escape_string
 mysql_real_query
 mysql_real_query_cont
 mysql_real_query_start
 mysql_refresh
 mysql_refresh_cont
 mysql_refresh_start
 mysql_rollback
 mysql_rollback_cont
 mysql_rollback_start
 mysql_row_seek
 mysql_row_tell
 mysql_select_db
 mysql_select_db_cont
 mysql_select_db_start
 mysql_send_query
 mysql_send_query_cont
 mysql_send_query_start
 mysql_server_end
 mysql_server_init
 mysql_set_character_set
 mysql_set_character_set_cont
 mysql_set_character_set_start
 mysql_set_local_infile_default
 mysql_set_local_infile_handler
 mysql_set_server_option
 mysql_set_server_option_cont
 mysql_set_server_option_start
 mysql_shutdown
 mysql_shutdown_cont
 mysql_shutdown_start
 mysql_sqlstate
 mysql_ssl_set
 mysql_stat
 mysql_stat_cont
 mysql_stat_start
 mysql_stmt_affected_rows
 mysql_stmt_attr_get
 mysql_stmt_attr_set
 mysql_stmt_bind_param
 mysql_stmt_bind_result
 mysql_stmt_close
 mysql_stmt_close_cont
 mysql_stmt_close_start
 mysql_stmt_data_seek
 mysql_stmt_errno
 mysql_stmt_error
 mysql_stmt_execute
 mysql_stmt_execute_cont
 mysql_stmt_execute_start
 mysql_stmt_fetch
 mysql_stmt_fetch_column
 mysql_stmt_fetch_cont
 mysql_stmt_fetch_start
 mysql_stmt_field_count
 mysql_stmt_free_result
 mysql_stmt_free_result_cont
 mysql_stmt_free_result_start
 mysql_stmt_init
 mysql_stmt_insert_id
 mysql_stmt_more_results
 mysql_stmt_next_result
 mysql_stmt_next_result_cont
 mysql_stmt_next_result_start
 mysql_stmt_num_rows
 mysql_stmt_param_count
 mysql_stmt_param_metadata
 mysql_stmt_prepare
 mysql_stmt_prepare_cont
 mysql_stmt_prepare_start
 mysql_stmt_reset
 mysql_stmt_reset_cont
 mysql_stmt_reset_start
 mysql_stmt_result_metadata
 mysql_stmt_row_seek
 mysql_stmt_row_tell
 mysql_stmt_send_long_data
 mysql_stmt_send_long_data_cont
 mysql_stmt_send_long_data_start
 mysql_stmt_sqlstate
 mysql_stmt_store_result
 mysql_stmt_store_result_cont
 mysql_stmt_store_result_start
 mysql_store_result
 mysql_store_result_cont
 mysql_store_result_start
 mysql_thread_end
 mysql_thread_id
 mysql_thread_init
 mysql_thread_safe
 mysql_use_result
 mysql_warning_count)

IF(WITH_OPENSSL)
  SET(EXPORT_SYMBOLS ${EXPORT_SYMBOLS} mariadb_deinitialize_ssl)
ENDIF()

IF(WIN32)
  SET(EXPORT_CONTENT "EXPORTS\n")
  FOREACH(SYMBOL ${EXPORT_SYMBOLS})
    SET(EXPORT_CONTENT "${EXPORT_CONTENT}  ${SYMBOL}\n")
  ENDFOREACH()
  SET(EXPORT_FILE "${CMAKE_BINARY_DIR}/libmariadb/exports.def")
  SET(EXPORT_LINK ${EXPORT_FILE})
ELSE()
  SET(EXPORT_CONTENT "{\nglobal:\n")
  FOREACH(SYMBOL ${EXPORT_SYMBOLS})
    SET(EXPORT_CONTENT "${EXPORT_CONTENT} ${SYMBOL}\\;\n")
  ENDFOREACH()
  SET(EXPORT_FILE "${CMAKE_BINARY_DIR}/libmariadb/exports.txt")
  SET(EXPORT_CONTENT "${EXPORT_CONTENT}local:\n *\\;\n}\\;")
ENDIF()

FILE(WRITE ${EXPORT_FILE} ${EXPORT_CONTENT})

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
ma_dtoa.c
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
)
IF(WITH_OPENSSL)
  SET(LIBMARIADB_SOURCES ${LIBMARIADB_SOURCES} ma_secure.c)
ENDIF()

IF(WIN32)
  INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/win-iconv)
  SET(LIBMARIADB_SOURCES ${LIBMARIADB_SOURCES}
                         ${CMAKE_SOURCE_DIR}/win-iconv/win_iconv.c)
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

IF(WIN32)
  SET_VERSION_INFO("TARGET:libmariadb"
                   "FILE_TYPE:VFT_DLL"
                   "SOURCE_FILE:libmariadb/libmariadb.c"
                   "ORIGINAL_FILE_NAME:libmariadb.dll"
                   "FILE_DESCRIPTION:Dynamic lib for client/server communication")
  SET_VERSION_INFO("TARGET:mariadbclient"
                   "FILE_TYPE:VFT_STATIC_LIB"
                   "SOURCE_FILE:libmariadb/libmariadb.c"
                   "ORIGINAL_FILE_NAME:mariadbclient.lib"
                   "FILE_DESCRIPTION:Static lib for client/server communication")
ENDIF()

# CREATE OBJECT LIBRARY 
ADD_LIBRARY(mariadb_obj OBJECT ${LIBMARIADB_SOURCES})
IF(UNIX)
  SET_TARGET_PROPERTIES(mariadb_obj PROPERTIES COMPILE_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
ENDIF()

# Xcode doesn't support targets that have only object files,
# so let's add an empty file to keep Xcode happy
IF(CMAKE_GENERATOR MATCHES Xcode)
  FILE(WRITE ${CMAKE_SOURCE_DIR}/libmariadb/empty.c "")
  SET(EMPTY_FILE ${CMAKE_SOURCE_DIR}/libmariadb/empty.c)
ENDIF()

ADD_LIBRARY(mariadbclient STATIC ${mariadbclient_RC} $<TARGET_OBJECTS:mariadb_obj> ${EMPTY_FILE} ${EXPORT_LINK})
TARGET_LINK_LIBRARIES(mariadbclient ${SYSTEM_LIBS})

ADD_LIBRARY(libmariadb SHARED ${libmariadb_RC} $<TARGET_OBJECTS:mariadb_obj> ${EMPTY_FILE} ${EXPORT_LINK})
TARGET_LINK_LIBRARIES(libmariadb ${SYSTEM_LIBS})
IF(UNIX)
  SET_TARGET_PROPERTIES(libmariadb PROPERTIES COMPILE_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
ENDIF()
SIGN_TARGET(libmariadb)

IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
  TARGET_LINK_LIBRARIES (libmariadb "-Wl,--no-undefined")
  TARGET_LINK_LIBRARIES (libmariadb "-Wl,--version-script=${EXPORT_FILE}")
  TARGET_LINK_LIBRARIES (mariadbclient "-Wl,--no-undefined")
  TARGET_LINK_LIBRARIES (mariadbclient "-Wl,--version-script=${EXPORT_FILE}")
ENDIF()

SET_TARGET_PROPERTIES(libmariadb PROPERTIES PREFIX "")

SET_TARGET_PROPERTIES(libmariadb PROPERTIES VERSION 
   ${CPACK_PACKAGE_VERSION_MAJOR}
   SOVERSION ${CPACK_PACKAGE_VERSION_MAJOR})

#
# Installation
#
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/symlink.cmake)


# There are still several projects which don't make use
# of the config program. To make sure these programs can
# use mariadb client library we provide libmysql symlinks
IF(NOT WIN32 AND WITH_MYSQLCOMPAT)
  SET(INSTALL_PATH ${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR})
  create_symlink(libmysqlclient${CMAKE_SHARED_LIBRARY_SUFFIX} libmariadb ${INSTALL_PATH})
  create_symlink(libmysqlclient_r${CMAKE_SHARED_LIBRARY_SUFFIX} libmariadb ${INSTALL_PATH})
  create_symlink(libmysqlclient${CMAKE_STATIC_LIBRARY_SUFFIX} mariadbclient ${INSTALL_PATH})
  create_symlink(libmysqlclient_r${CMAKE_STATIC_LIBRARY_SUFFIX} mariadbclient ${INSTALL_PATH})
ENDIF()


INSTALL(TARGETS
          libmariadb mariadbclient
          RUNTIME DESTINATION "${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}"
          LIBRARY DESTINATION "${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}"
          ARCHIVE DESTINATION "${LIB_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}")

INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
        DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR})
INSTALL(FILES 
   ${CMAKE_BINARY_DIR}/include/my_config.h
   ${CMAKE_BINARY_DIR}/include/mysql_version.h
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR})


