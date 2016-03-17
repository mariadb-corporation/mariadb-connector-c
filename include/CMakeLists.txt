SET(MARIADB_CLIENT_INCLUDES ${CMAKE_SOURCE_DIR}/include/mariadb_com.h
                            ${CMAKE_SOURCE_DIR}/include/mysql.h
                            ${CMAKE_SOURCE_DIR}/include/mariadb_stmt.h
                            ${CMAKE_SOURCE_DIR}/include/ma_pvio.h
                            ${CMAKE_SOURCE_DIR}/include/ma_tls.h
                            ${CMAKE_SOURCE_DIR}/include/mariadb_version.h
                            ${CMAKE_SOURCE_DIR}/include/ma_list.h
                            ${CMAKE_SOURCE_DIR}/include/ma_errmsg.h
                            ${CMAKE_SOURCE_DIR}/include/mariadb_dyncol.h
                            ${CMAKE_SOURCE_DIR}/include/mariadb_ctype.h)
SET(MYSQL_ADDITIONAL_INCLUDES
   ${CMAKE_SOURCE_DIR}/include/mysql/client_plugin.h
   ${CMAKE_SOURCE_DIR}/include/mysql/plugin_auth_common.h
   ${CMAKE_SOURCE_DIR}/include/mysql/plugin_auth.h)
 SET(MARIADB_ADDITIONAL_INCLUDES
   ${CMAKE_SOURCE_DIR}/include/mariadb/ma_io.h)

INSTALL(FILES
   ${MARIADB_CLIENT_INCLUDES}
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}
   COMPONENT ALL)
INSTALL(FILES
   ${MYSQL_ADDITIONAL_INCLUDES}
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}/mysql
   COMPONENT ALL)
INSTALL(FILES
   ${MARIADB_ADDITIONAL_INCLUDES}
   DESTINATION ${INCLUDE_INSTALL_DIR}/${SUFFIX_INSTALL_DIR}/mariadb
   COMPONENT ALL)


