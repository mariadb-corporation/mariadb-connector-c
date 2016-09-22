SET(MARIADB_CLIENT_INCLUDES ${CC_SOURCE_DIR}/include/mariadb_com.h
                            ${CC_SOURCE_DIR}/include/mysql.h
                            ${CC_SOURCE_DIR}/include/mariadb_stmt.h
                            ${CC_SOURCE_DIR}/include/ma_pvio.h
                            ${CC_SOURCE_DIR}/include/ma_tls.h
                            ${CC_BINARY_DIR}/include/mariadb_version.h
                            ${CC_SOURCE_DIR}/include/ma_list.h
                            ${CC_SOURCE_DIR}/include/ma_errmsg.h
                            ${CC_SOURCE_DIR}/include/mariadb_dyncol.h
                            ${CC_SOURCE_DIR}/include/mariadb_ctype.h)
SET(MYSQL_ADDITIONAL_INCLUDES
   ${CC_SOURCE_DIR}/include/mysql/client_plugin.h
   ${CC_SOURCE_DIR}/include/mysql/plugin_auth_common.h
   ${CC_SOURCE_DIR}/include/mysql/plugin_auth.h)
 SET(MARIADB_ADDITIONAL_INCLUDES
   ${CC_SOURCE_DIR}/include/mariadb/ma_io.h)

INSTALL(FILES
   ${MARIADB_CLIENT_INCLUDES}
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}
   COMPONENT Development)
INSTALL(FILES
   ${MYSQL_ADDITIONAL_INCLUDES}
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}/mysql
   COMPONENT Development)
INSTALL(FILES
   ${MARIADB_ADDITIONAL_INCLUDES}
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}/mariadb
   COMPONENT Development)


