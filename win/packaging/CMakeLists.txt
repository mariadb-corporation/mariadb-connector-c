SET(CLIENT_LIB_DIR ${CMAKE_BINARY_DIR}/libmariadb/${CMAKE_BUILD_TYPE})
SET(CLIENT_DBG_DIR ${CMAKE_BINARY_DIR}/libmariadb/Debug)
SET(CLIENT_INC_DIR ${CMAKE_SOURCE_DIR}/include)

SET(PRODUCT_NAME "MariaDB C Client Library")
SET(PRODUCT_MANUFACTURER "MariaDB")
SET(PRODUCT_VERSION "${MYSQL_CLIENT_VERSION_MAJOR}.${MYSQL_CLIENT_VERSION_MINOR}.${MYSQL_CLIENT_VERSION_PATCH}")

MESSAGE(STATUS "sizeof ${CMAKE_SIZEOF_VOID_P}")

IF(${MSI_64})
  SET(PRODUCT_NAME "${PRODUCT_NAME} 64-bit")
  SET(PLATFORM "win64")
  SET(IS_WIN64 "yes")
  SET(WIXPLATFORM "x64")
  SET(FOLDER "ProgramFiles64Folder")
ELSE()
  SET(PLATFORM "win32")
  SET(IS_WIN64 "no")
  SET(WIXPLATFORM "x86")
  SET(FOLDER "ProgramFilesFolder")
ENDIF()

FOREACH(src ${MARIADB_CLIENT_INCLUDES})
  STRING(REPLACE "-" "_" src_id ${src})
  SET(MARIADB_INCLUDE_FILES "${MARIADB_INCLUDE_FILES}        <File Id=\"${src_id}\" Name=\"${src}\"  DiskId=\"1\"  Source=\"${CMAKE_SOURCE_DIR}/include/${src}\"/>\n")
ENDFOREACH()

CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/win/packaging/mariadb-native-client.xml.in
  ${CMAKE_BINARY_DIR}/win/packaging/mariadb-native-client.xml)
SET(MSI_PACKAGE "mariadb-native-client-${PRODUCT_VERSION}-${PLATFORM}.msi")

ADD_CUSTOM_TARGET(
        MSI_PACKAGE_ALL
        DEPENDS ${MSI_PACKAGE})

ADD_CUSTOM_COMMAND(
        OUTPUT ${MSI_PACKAGE}
        DEPENDS mariadb-native-client.wixobj
        COMMAND light.exe -ext WixUIExtension mariadb-native-client.wixobj -o ${MSI_PACKAGE})

ADD_CUSTOM_COMMAND(
        OUTPUT mariadb-native-client.wixobj
        DEPENDS mariadb-native-client.xml
        COMMAND candle.exe mariadb-native-client.xml -o mariadb-native-client.wixobj)

