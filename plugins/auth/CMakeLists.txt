INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/plugins/auth)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/install_plugins.cmake)
IF(WITH_SIGNCODE)
  INCLUDE(${CMAKE_SOURCE_DIR}/cmake/sign.cmake)
ENDIF()

# Dialog plugin
IF(AUTH_DIALOG_PLUGIN_TYPE MATCHES "DYNAMIC")
  ADD_DEFINITIONS(-DHAVE_DIALOG_DYNAMIC=1)
  IF(WIN32)
    SET_VERSION_INFO("TARGET:dialog"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/auth/dialog.c"
                     "ORIGINAL_FILE_NAME:dialog.dll"
                     "FILE_DESCRIPTION:Authentication plugin")
  ENDIF()
  SET(DIALOG_SOURCES ${ialog_RC} dialog.c ${CMAKE_SOURCE_DIR}/libmariadb/get_password.c)
  IF(WIN32)
    SET(DIALOG_SOURCES ${DIALOG_SOURCES} ${CMAKE_SOURCE_DIR}/plugins/plugin.def)
  ENDIF()
  ADD_LIBRARY(dialog MODULE ${DIALOG_SOURCES})
  SET_TARGET_PROPERTIES(dialog PROPERTIES PREFIX "")
  INSTALL_PLUGIN(dialog ${CMAKE_BINARY_DIR}/plugins/auth)
  SIGN_TARGET(dialog)
ENDIF()

# old_password plugin
IF(AUTH_OLDPASSWORD_PLUGIN_TYPE MATCHES "DYNAMIC")
  ADD_DEFINITIONS(-DHAVE_OLDPASSWORD_DYNAMIC=1)
  IF(WIN32)
    SET_VERSION_INFO("TARGET:mysql_old_password"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/auth/old_password.c"
                     "ORIGINAL_FILE_NAME:mysql_old_password.dll"
                     "FILE_DESCRIPTION:Authentication plugin")
  ENDIF()
  SET(OLDPASSWORD_SOURCES ${old_password_RC} old_password.c)
  IF(WIN32)
    SET(OLDPASSWORD_SOURCES ${DIALOG_SOURCES} ${CMAKE_SOURCE_DIR}/plugins/plugin.def)
  ENDIF()
  ADD_LIBRARY(mysql_old_password MODULE ${OLDPASSWORD_SOURCES})
  SET_TARGET_PROPERTIES(mysql_old_password PROPERTIES PREFIX "")
  INSTALL_PLUGIN(mysql_old_password ${CMAKE_BINARY_DIR}/plugins/auth)
  SIGN_TARGET(mysql_old_password)
ENDIF()

# Cleartext
IF(AUTH_CLEARTEXT_PLUGIN_TYPE MATCHES "DYNAMIC")
  ADD_DEFINITIONS(-DHAVE_CLEARTEXT_DYNAMIC=1)
  IF(WIN32)
    SET_VERSION_INFO("TARGET:mysql_clear_password"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/auth/mariadb_cleartext.c"
                     "ORIGINAL_FILE_NAME:mysql_clear_password.dll"
                     "FILE_DESCRIPTION:Authentication plugin")
  ENDIF()
  SET(CTEXT_SOURCES mariadb_cleartext.c)
  IF(WIN32)
    SET(CTEXT_SOURCES ${CTEXT_SOURCES} ${mysql_clear_password_RC} ${CMAKE_SOURCE_DIR}/plugins/plugin.def)
  ENDIF()
  ADD_LIBRARY(mysql_clear_password MODULE ${CTEXT_SOURCES})
  SET_TARGET_PROPERTIES(mysql_clear_password PROPERTIES PREFIX "")
  INSTALL_PLUGIN(mysql_clear_password ${CMAKE_BINARY_DIR}/plugins/auth)
  SIGN_TARGET(mysql_clear_password)
ENDIF()

# SSPI/GSSAPI plugin
IF(WIN32)
  SET(USE_SSPI 1)
ENDIF()

MESSAGE(STATUS "GSSAPI: ${AUTH_GSSAPI_PLUGIN_TYPE}")
IF(${AUTH_GSSAPI_PLUGIN_TYPE} MATCHES "DYNAMIC")
  IF(WIN32)
    SET_VERSION_INFO("TARGET:auth_gssapi_client"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/auth/auth_gssapi_client.c"
                     "ORIGINAL_FILE_NAME:auth_gssapi_client.dll"
                     "FILE_DESCRIPTION:Authentication plugin")
                   ADD_DEFINITIONS(-DHAVE_AUTH_GSSAPI_DYNAMIC=1)               
    SET(GSSAPI_SOURCES auth_gssapi_client.c sspi_client.c sspi_errmsg.c ${CMAKE_SOURCE_DIR}/plugins/plugin.def ${gssapi_RC})
  ELSE()
    IF(GSSAPI_FOUND)
      SET(GSSAPI_SOURCES auth_gssapi_client.c gssapi_client.c gssapi_errmsg.c)
    ENDIF()
  ENDIF()
  IF(GSSAPI_FOUND OR WIN32)
    ADD_LIBRARY(auth_gssapi_client MODULE ${GSSAPI_SOURCES})
    IF(WIN32)
      TARGET_LINK_LIBRARIES(auth_gssapi_client secur32.lib)
    ELSE()
      TARGET_LINK_LIBRARIES(auth_gssapi_client ${GSSAPI_LIBS})
    ENDIF()
    SET_TARGET_PROPERTIES(auth_gssapi_client PROPERTIES PREFIX "")
    INSTALL_PLUGIN(auth_gssapi_client ${CMAKE_BINARY_DIR}/plugins/auth)
    SIGN_TARGET(auth_gssapi_client)
  ENDIF()
ENDIF()
