#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
FUNCTION(GET_FILE_VERSION FILE_NAME FILE_VERSION)

  # if we build from a git repository, we calculate the file version:
  #  Patch number is number of commits for given file
  IF(GIT_EXECUTABLE AND EXISTS ${CC_SOURCE_DIR}/.git)
    EXECUTE_PROCESS(COMMAND ${GIT_EXECUTABLE} --git-dir=${CC_SOURCE_DIR}/.git --work-tree=${CC_SOURCE_DIR} rev-list HEAD --count -- ${FILE_NAME} 
      OUTPUT_VARIABLE FV)
    STRING(REPLACE "\n" "" FV ${FV})
    SET(${FILE_VERSION} ${FV} PARENT_SCOPE)
  ELSE()
    SET(${FILE_VERSION} 0)
  ENDIF()
ENDFUNCTION()

MACRO(SET_VERSION_INFO)
  SET(FILE_VERSION "0")
  FOREACH(PROPERTY ${ARGN})
    IF(${PROPERTY} MATCHES "TARGET:")
      STRING(REGEX REPLACE "^[TARGET:\\s]" "" TARGET ${PROPERTY})
    ELSEIF(${PROPERTY} MATCHES "FILE_TYPE:")
      STRING(REGEX REPLACE "^[FILE_TYPE:\\s]" "" FILE_TYPE ${PROPERTY})
    ELSEIF(${PROPERTY} MATCHES "ORIGINAL_FILE_NAME:")
      STRING(REGEX REPLACE "^[ORIGINAL_FILE_NAME:\\s]" "" ORIGINAL_FILE_NAME ${PROPERTY})
    ELSEIF(${PROPERTY} MATCHES "SOURCE_FILE:")
      STRING(REGEX REPLACE "^[SOURCE_FILE:\\s]" "" SOURCE ${PROPERTY})
      GET_FILE_VERSION(${SOURCE} FILE_VERSION)
    ELSEIF(${PROPERTY} MATCHES "FILE_DESCRIPTION:")
      STRING(REPLACE "FILE_DESCRIPTION:" "" FILE_DESCRIPTION ${PROPERTY})
    ENDIF()
  ENDFOREACH()
  # Connector can be packaged with server, so set the "file version"
  # to the server version
  # In this case, numeric file version should be consistent with server
  # Only this way MSI minor upgrade can work.
  # The product version string  will still refer to Connectors own version
  IF((NOT DEFINED MAJOR_VERSION) OR (NOT DEFINED MINOR_VERSION) OR (NOT DEFINED PATCH_VERSION) OR (NOT DEFINED TINY_VERSION))
    SET(MAJOR_VERSION ${CPACK_PACKAGE_VERSION_MAJOR})
    SET(MINOR_VERSION ${CPACK_PACKAGE_VERSION_MINOR})
    SET(PATCH_VERSION ${CPACK_PACKAGE_VERSION_PATCH})
    SET(TINY_VERSION  ${FILE_VERSION})
  ENDIF()
  CONFIGURE_FILE(${CC_SOURCE_DIR}/win/resource.rc.in
                 ${CC_BINARY_DIR}/win/${TARGET}.rc)
  SET(${TARGET}_RC ${CC_BINARY_DIR}/win/${TARGET}.rc)
ENDMACRO()



