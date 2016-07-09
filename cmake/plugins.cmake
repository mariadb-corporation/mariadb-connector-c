#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
# plugin configuration

MACRO(REGISTER_PLUGIN name source struct type target allow)
  SET(PLUGIN_TYPE ${${name}})
  IF(NOT PLUGIN_TYPE STREQUAL "OFF" AND NOT PLUGIN_TYPE)
    SET(PLUGIN_TYPE ${type})
  ENDIF()
  IF(PLUGINS)
    LIST(REMOVE_ITEM PLUGINS ${name})
  ENDIF()
  SET(${name}_PLUGIN_SOURCE ${source})
  MARK_AS_ADVANCED(${name}_PLUGIN_SOURCE})
  SET(${name}_PLUGIN_TYPE ${PLUGIN_TYPE})
  IF(NOT ${target} STREQUAL "")
    SET(${name}_PLUGIN_TARGET ${target})
  ENDIF()
  SET(${name}_PLUGIN_STRUCT ${struct})
  SET(${name}_PLUGIN_SOURCE ${source})
  SET(${name}_PLUGIN_CHG ${allow})
  SET(PLUGINS ${PLUGINS} "${name}")
  ADD_DEFINITIONS(-DHAVE_${name}=1)
ENDMACRO()

MARK_AS_ADVANCED(PLUGINS)

# CIO
REGISTER_PLUGIN("SOCKET" "${PROJECT_SOURCE_DIR}/plugins/pvio/pvio_socket.c" "pvio_socket_plugin" "STATIC" pvio_socket 0)
IF(WIN32)
  REGISTER_PLUGIN("NPIPE" "${PROJECT_SOURCE_DIR}/plugins/pvio/pvio_npipe.c" "pvio_npipe_plugin" "STATIC" pvio_npipe 1)
  REGISTER_PLUGIN("SHMEM" "${PROJECT_SOURCE_DIR}/plugins/pvio/pvio_shmem.c" "pvio_shmem_plugin" "DYNAMIC" pvio_shmem 1)
ENDIF()

# AUTHENTICATION
REGISTER_PLUGIN("AUTH_NATIVE" "${PROJECT_SOURCE_DIR}/plugins/auth/my_auth.c" "native_password_client_plugin" "STATIC" "" 0)
REGISTER_PLUGIN("AUTH_OLDPASSWORD" "${PROJECT_SOURCE_DIR}/plugins/auth/old_password.c" "old_password_client_plugin" "STATIC" "" 1)
REGISTER_PLUGIN("AUTH_DIALOG" "${PROJECT_SOURCE_DIR}/plugins/auth/dialog.c" "auth_dialog_plugin" "DYNAMIC" dialog 1)
REGISTER_PLUGIN("AUTH_CLEARTEXT" "${PROJECT_SOURCE_DIR}/plugins/auth/mariadb_clear_text.c" "auth_cleartext_plugin" "DYNAMIC" "mysql_clear_password" 1)
IF(WIN32)
    SET(GSSAPI_SOURCES ${PROJECT_SOURCE_DIR}/plugins/auth/auth_gssapi_client.c ${PROJECT_SOURCE_DIR}/plugins/auth/sspi_client.c ${PROJECT_SOURCE_DIR}/plugins/auth/sspi_errmsg.c)
    REGISTER_PLUGIN("AUTH_GSSAPI" "${GSSAPI_SOURCES}" "auth_gssapi_plugin" "DYNAMIC" "auth_gssapi_client" 1)
ELSE()
  IF(GSSAPI_FOUND)
    SET(GSSAPI_SOURCES ${PROJECT_SOURCE_DIR}/plugins/auth/auth_gssapi_client.c ${PROJECT_SOURCE_DIR}/plugins/auth/gssapi_client.c ${PROJECT_SOURCE_DIR}/plugins/auth/gssapi_errmsg.c)
    REGISTER_PLUGIN("AUTH_GSSAPI" "${GSSAPI_SOURCES}" "auth_gssapi_plugin" "DYNAMIC" "auth_gssapi_client" 1)
  ENDIF()
ENDIF()

#Remote_IO
IF(CURL_FOUND)
  IF(WIN32)
    REGISTER_PLUGIN("REMOTEIO" "${PROJECT_SOURCE_DIR}/plugins/io/remote_io.c" "remote_io_plugin" "DYNAMIC" "remote_io" 1)
  ELSE()
    REGISTER_PLUGIN("REMOTEIO" "${PROJECT_SOURCE_DIR}/plugins/io/remote_io.c" "remote_io_plugin" "DYNAMIC" "remote_io" 1)
  ENDIF()
ENDIF()

#Trace
REGISTER_PLUGIN("TRACE_EXAMPLE" "${PROJECT_SOURCE_DIR}/plugins/trace/trace_example.c" "trace_example_plugin" "DYNAMIC" "trace_example" 1)

#Connection
REGISTER_PLUGIN("REPLICATION" "${PROJECT_SOURCE_DIR}/plugins/connection/replication.c" "connection_replication_plugin" "DYNAMIC" "replication" 1)
REGISTER_PLUGIN("AURORA" "${PROJECT_SOURCE_DIR}/plugins/connection/aurora.c" "connection_aurora_plugin" "DYNAMIC" "aurora"  1)

# Allow registration of additional plugins
IF(PLUGIN_CONF_FILE)
  INCLUDE(${PLUGIN_CONF_FILE})
ENDIF()


SET(LIBMARIADB_SOURCES "")

MESSAGE(STATUS "Plugin configuration:")
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
MESSAGE(STATUS "STATIC PLUGIN SOURCES: ${LIBMARIADB_SOURCES}")

IF(NOT REMOTEIO_PLUGIN_TYPE MATCHES "NO")
  FIND_PACKAGE(CURL)
ENDIF()

# since some files contain multiple plugins, remove duplicates from source files 
LIST(REMOVE_DUPLICATES LIBMARIADB_SOURCES)

CONFIGURE_FILE(${PROJECT_SOURCE_DIR}/libmariadb/ma_client_plugin.c.in
  ${PROJECT_BINARY_DIR}/libmariadb/ma_client_plugin.c)

MARK_AS_ADVANCED(LIBMARIADB_SOURCES)
