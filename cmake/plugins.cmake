# plugin configuration

MACRO(REGISTER_PLUGIN name source struct type allow)
  IF(PLUGINS)
    LIST(REMOVE_ITEM PLUGINS ${name})
  ENDIF()
  SET(${name}_PLUGIN_SOURCE ${source})
  SET(${name}_PLUGIN_TYPE ${type})
  SET(${name}_PLUGIN_STRUCT ${struct})
  SET(${name}_PLUGIN_SOURCE ${source})
  SET(${name}_PLUGIN_CHG ${allow})
  SET(PLUGINS ${PLUGINS} "${name}")
ENDMACRO()

MARK_AS_ADVANCED(PLUGINS)

# CIO
REGISTER_PLUGIN("SOCKET" "${CMAKE_SOURCE_DIR}/plugins/cio/cio_socket.c" "cio_socket_plugin" "STATIC" 0)
IF(WIN32)
  REGISTER_PLUGIN("NPIPE" "${CMAKE_SOURCE_DIR}/plugins/cio/cio_npipe.c" "cio_npipe_plugin" "DYNAMIC" 1)
  REGISTER_PLUGIN("SHMEM" "${CMAKE_SOURCE_DIR}/plugins/cio/cio_shmem.c" "cio_shmem_plugin" "DYNAMIC" 1)
ENDIF()

# AUTHENTICATION
REGISTER_PLUGIN("AUTH_NATIVE" "${CMAKE_SOURCE_DIR}/plugins/auth/my_auth.c" "native_password_client_plugin" "STATIC" 0)
REGISTER_PLUGIN("AUTH_OLDPASSWORD" "${CMAKE_SOURCE_DIR}/plugins/auth/my_auth.c" "old_password_client_plugin" "STATIC" 0)
REGISTER_PLUGIN("AUTH_DIALOG" "${CMAKE_SOURCE_DIR}/plugins/auth/dialog.c" "auth_dialog_plugin" "DYNAMIC" 1)
REGISTER_PLUGIN("AUTH_CLEARTEXT" "${CMAKE_SOURCE_DIR}/plugins/auth/mariadb_clear_text.c" "auth_cleartext_plugin" "DYNAMIC" 1)

#Remote_IO
REGISTER_PLUGIN("REMOTEIO" "${CMAKE_SOURCE_DIR}/plugins/io/remote_io.c" "remote_io_plugin" "DYNAMIC" 1)

#Trace
REGISTER_PLUGIN("TRACE_EXAMPLE" "${CMAKE_SOURCE_DIR}/plugins/trace/trace_example.c" "trace_example_plugin" "DYNAMIC" 1)

#Connection
REGISTER_PLUGIN("REPLICATION" "${CMAKE_SOURCE_DIR}/plugins/connection/replication.c" "connection_replication_plugin" "STATIC" 1)

# Allow registration of additional plugins
IF(PLUGIN_CONF_FILE)
  INCLUDE(${PLUGIN_CONF_FILE})
ENDIF()


SET(LIBMARIADB_SOURCES "")

MESSAGE(STATUS "Plugin configuration")
FOREACH(PLUGIN ${PLUGINS})
  IF(WITH_${PLUGIN}_PLUGIN AND ${${PLUGIN}_PLUGIN_CHG} GREATER 0)
    SET(${PLUGIN}_PLUGIN_TYPE ${WITH_${PLUGIN}_PLUGIN})
  ENDIF()
  IF(${PLUGIN}_PLUGIN_TYPE MATCHES "STATIC")
    SET(LIBMARIADB_SOURCES ${LIBMARIADB_SOURCES} ${${PLUGIN}_PLUGIN_SOURCE})
    SET(EXTERNAL_PLUGINS "${EXTERNAL_PLUGINS}extern struct st_mysql_client_plugin ${${PLUGIN}_PLUGIN_STRUCT};\n")
    SET(BUILTIN_PLUGINS "${BUILTIN_PLUGINS}(struct st_mysql_client_plugin *)&${${PLUGIN}_PLUGIN_STRUCT},\n")
  ENDIF()
  MESSAGE(STATUS "${PLUGIN}: ${${PLUGIN}_PLUGIN_TYPE}")
  MARK_AS_ADVANCED(${PLUGIN}_PLUGIN_TYPE)
ENDFOREACH()

# since some files contain multiple plugins, remove duplicates from source files 
LIST(REMOVE_DUPLICATES LIBMARIADB_SOURCES)

CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/libmariadb/client_plugin.c.in
               ${CMAKE_BINARY_DIR}/libmariadb/client_plugin.c)

MARK_AS_ADVANCED(LIBMARIADB_SOURCES)
