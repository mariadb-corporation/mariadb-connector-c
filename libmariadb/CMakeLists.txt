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
 mariadb_deinitialize_ssl
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

ADD_LIBRARY(mariadbclient STATIC $<TARGET_OBJECTS:mariadb_obj> ${EXPORT_LINK})
TARGET_LINK_LIBRARIES(mariadbclient ${SYSTEM_LIBS})

ADD_LIBRARY(libmariadb SHARED $<TARGET_OBJECTS:mariadb_obj> ${EXPORT_LINK})
TARGET_LINK_LIBRARIES(libmariadb ${SYSTEM_LIBS})
IF(UNIX)
  SET_TARGET_PROPERTIES(libmariadb PROPERTIES COMPILE_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
ENDIF()

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


