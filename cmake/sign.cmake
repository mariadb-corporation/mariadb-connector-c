#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
MACRO(SIGN_TARGET target)
  IF(WITH_SIGNCODE)
    IF(WIN32)
      SET(target_file $<TARGET_FILE:${target}>)
      IF(EXISTS "/tools/sign.bat")
        ADD_CUSTOM_COMMAND(TARGET ${target} COMMAND /tools/sign.bat ARGS ${target_file})
      ELSEIF()
        ADD_CUSTOM_COMMAND(TARGET ${target} COMMAND signtool ARGS sign ${SIGN_OPTIONS} ${target_file})
      ENDIF()
    ENDIF()
  ENDIF()
ENDMACRO()
