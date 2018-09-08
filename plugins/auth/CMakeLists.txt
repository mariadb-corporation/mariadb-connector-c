SET(AUTH_DIR ${CC_SOURCE_DIR}/plugins/auth)

INCLUDE_DIRECTORIES(${AUTH_DIR})
INCLUDE_DIRECTORIES(${CC_SOURCE_DIR}/include)

#native password
REGISTER_PLUGIN(TARGET mysql_native_password
                TYPE MARIADB_CLIENT_PLUGIN_AUTH
                CONFIGURATIONS STATIC
                DEFAULT STATIC
                SOURCES ${CC_SOURCE_DIR}/plugins/auth/my_auth.c)

#Dialog client authentication plugin
REGISTER_PLUGIN(TARGET dialog
                TYPE MARIADB_CLIENT_PLUGIN_AUTH
                CONFIGURATIONS DYNAMIC STATIC OFF
                DEFAULT DYNAMIC
                SOURCES ${CC_SOURCE_DIR}/plugins/auth/dialog.c
                        ${CC_SOURCE_DIR}/libmariadb/get_password.c)

#GSSAPI client authentication plugin
IF(NOT WIN32)
  INCLUDE(${CC_SOURCE_DIR}/cmake/FindGSSAPI.cmake)
  IF(GSSAPI_FOUND)
    SET(GSSAPI_SOURCES ${AUTH_DIR}/auth_gssapi_client.c ${AUTH_DIR}/gssapi_client.c ${AUTH_DIR}/gssapi_errmsg.c)
  ENDIF()
ELSE()
  SET(GSSAPI_LIBS secur32)
  SET(GSSAPI_SOURCES ${AUTH_DIR}/auth_gssapi_client.c ${AUTH_DIR}/sspi_client.c ${AUTH_DIR}/sspi_errmsg.c)
ENDIF()
IF(GSSAPI_SOURCES)
  REGISTER_PLUGIN(TARGET auth_gssapi_client
                  TYPE MARIADB_CLIENT_PLUGIN_AUTH
                  CONFIGURATIONS DYNAMIC STATIC OFF
                  DEFAULT DYNAMIC
                  SOURCES ${GSSAPI_SOURCES}
                  INCLUDES ${CC_SOURCE_DIR}/plugins/auth ${GSSAPI_INCS}
                  LIBRARIES ${GSSAPI_LIBS})
ENDIF()

IF(${WITH_SSL} STREQUAL "OPENSSL" OR ${WITH_SSL} STREQUAL "SCHANNEL")
  IF(WITH_SSL STREQUAL "SCHANNEL")
    SET(SHA256_LIBS crypt32)
  ELSE()
    SET(SHA256_LIBS ${SSL_LIBRARIES})
  ENDIF()
  REGISTER_PLUGIN(TARGET sha256_password
                  TYPE MARIADB_CLIENT_PLUGIN_AUTH
                  CONFIGURATIONS DYNAMIC STATIC OFF
                  DEFAULT DYNAMIC
                  SOURCES ${AUTH_DIR}/sha256_pw.c
                  LIBRARIES ${SHA256_LIBS})
ENDIF()

# old_password plugin
REGISTER_PLUGIN(TARGET mysql_old_password
                TYPE MARIADB_CLIENT_PLUGIN_AUTH
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT STATIC
                SOURCES ${AUTH_DIR}/old_password.c)


# Cleartext
REGISTER_PLUGIN(TARGET mysql_clear_password
                TYPE MARIADB_CLIENT_PLUGIN_AUTH
                CONFIGURATIONS DYNAMIC STATIC OFF
                DEFAULT DYNAMIC
                SOURCES ${AUTH_DIR}/mariadb_cleartext.c)

