PROJECT(mariadb_client_docs)
# Minimum required version is Cmake 2.6.x
CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)
IF(COMMAND CMAKE_POLICY)
  CMAKE_POLICY(SET CMP0003 NEW)
ENDIF(COMMAND CMAKE_POLICY)

FIND_PROGRAM(XMLTO_PROC xmlto)

IF(XMLTO_PROC)
  ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/html/index.html
                     DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/mariadb-client.xml
	             COMMAND ${XMLTO_PROC} xhtml --stringparam admon.graphics  -m config.xsl mariadb-client.xml --skip-validation -ohtml)

  ADD_CUSTOM_TARGET(GENERATE_HTML ALL
                    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/html/index.html)
ELSE(XMLTO_PROC)
  MESSAGE(ERROR "xmlto not found")
ENDIF(XMLTO_PROC)
