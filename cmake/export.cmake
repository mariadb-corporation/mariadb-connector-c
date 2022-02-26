#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
MACRO(CREATE_EXPORT_FILE export_file_name mysqlclient_version alias_version mariadb_version mysql_symbols mariadb_symbols)
  IF(WIN32)
    STRING(REPLACE ";" "\n" export_file_text "EXPORTS\n${mariadb_symbols}\n${mysql_symbols}\n")
  ELSE()
    STRING(REPLACE ";" ";\n " mysql_symbol_lines "${mysql_symbols}")
    STRING(REPLACE ";" ";\n " mariadb_symbol_lines "${mariadb_symbols}")
    SET(mysql_alias_lines "")
    FOREACH(exp_symbol ${mysql_symbols})
      SET(mysql_alias_lines "${mysql_alias_lines}\"${exp_symbol}@${alias_version}\" = ${exp_symbol};\n")
    ENDFOREACH()
    STRING(CONCAT export_file_text
           "VERSION {\n${mysqlclient_version} {\nglobal:\n ${mysql_symbol_lines};\nlocal:\n *;\n};\n"
           "${alias_version} {\n};\n};\n${mysql_alias_lines}"
           "VERSION {\n${mariadb_version} {\nglobal:\n ${mariadb_symbol_lines};\nlocal:\n *;\n};\n};\n")
  ENDIF()

  # Only write output if file contents change.
  SET(old_file_contents)
  IF(EXISTS "${export_file_name}")
    FILE(READ "${export_file_name}" old_file_contents)
  ENDIF()
  IF(NOT old_file_contents STREQUAL export_file_text)
    FILE(WRITE "${export_file_name}" "${export_file_text}")
  ENDIF()
ENDMACRO()
