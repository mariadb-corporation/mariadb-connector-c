SET(MARIADB_CLIENT_INCLUDES ${CC_SOURCE_DIR}/include/mariadb_com.h
                            ${CC_SOURCE_DIR}/include/mysql.h
                            ${CC_SOURCE_DIR}/include/mariadb_stmt.h
                            ${CC_SOURCE_DIR}/include/ma_pvio.h
                            ${CC_SOURCE_DIR}/include/ma_tls.h
                            ${CC_BINARY_DIR}/include/mariadb_version.h
                            ${CC_SOURCE_DIR}/include/ma_list.h
                            ${CC_SOURCE_DIR}/include/errmsg.h
                            ${CC_SOURCE_DIR}/include/mariadb_dyncol.h
                            ${CC_SOURCE_DIR}/include/mariadb_ctype.h
                            PARENT_SCOPE)
SET(MYSQL_ADDITIONAL_INCLUDES
   ${CC_SOURCE_DIR}/include/mysql/client_plugin.h
   ${CC_SOURCE_DIR}/include/mysql/plugin_auth_common.h
   ${CC_SOURCE_DIR}/include/mysql/plugin_auth.h
   PARENT_SCOPE)
 SET(MARIADB_ADDITIONAL_INCLUDES
   ${CC_SOURCE_DIR}/include/mariadb/ma_io.h
   PARENT_SCOPE)

INSTALL(FILES
   ${MARIADB_CLIENT_INCLUDES}
   DESTINATION ${INSTALL_INCLUDEDIR}
   COMPONENT Development)
INSTALL(FILES
   ${MYSQL_ADDITIONAL_INCLUDES}
   DESTINATION ${INSTALL_INCLUDEDIR}/mysql
   COMPONENT Development)
INSTALL(FILES
   ${MARIADB_ADDITIONAL_INCLUDES}
   DESTINATION ${INSTALL_INCLUDEDIR}/mariadb
   COMPONENT Development)
