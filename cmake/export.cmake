#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
MACRO(CREATE_EXPORT_FILE targetname directory version symbols append include_version)
  SET(EXPORT_FILE "${directory}/${targetname}.def")
  IF(WIN32)
    SET(EXPORT_CONTENT "EXPORTS\n")
    FOREACH(exp_symbol ${symbols})
      SET(EXPORT_CONTENT ${EXPORT_CONTENT} "${exp_symbol}\n")
    ENDFOREACH()
  ELSE()
    SET(EXPORT_CONTENT "${version} {\nglobal:\n")
    FOREACH(exp_symbol ${symbols})
      SET(EXPORT_CONTENT "${EXPORT_CONTENT} ${exp_symbol}\\;\n")
    ENDFOREACH()
    SET(EXPORT_CONTENT "${EXPORT_CONTENT}local:\n *\\;\n}${include_version}\\;\n")
  ENDIF()
  IF(${append} STREQUAL "1")
    FILE(APPEND ${EXPORT_FILE} ${EXPORT_CONTENT})
  ELSE()
    FILE(WRITE ${EXPORT_FILE} ${EXPORT_CONTENT})
  ENDIF()
ENDMACRO()
