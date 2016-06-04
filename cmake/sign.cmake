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
      IF(WITH_SIGNCODE STREQUAL 2)
        SET(SIGN_OPTIONS "/a /fd sha256 /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td sha256 ")
      ENDIF()
      IF(EXISTS "/tools/sign.bat")
        ADD_CUSTOM_COMMAND(TARGET ${target} COMMAND /tools/sign.bat ARGS ${target_file})
      ELSEIF()
        ADD_CUSTOM_COMMAND(TARGET ${target} COMMAND signtool ARGS sign ${SIGN_OPTIONS} ${target_file})
      ENDIF()
    ENDIF()
  ENDIF()
ENDMACRO()
