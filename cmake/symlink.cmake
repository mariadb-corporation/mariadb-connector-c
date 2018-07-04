#
#  Copyright (C) 2013-2016 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the COPYING-CMAKE-SCRIPTS file.
#
MACRO(create_symlink symlink_name target install_path)
# According to cmake documentation symlinks work on unix systems only
IF(UNIX)
  # Set target components
  SET(target_lib $<TARGET_FILE_DIR:${target}>/${symlink_name})

  ADD_CUSTOM_COMMAND(
    TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} ARGS -E remove -f ${target_lib}
    COMMAND ${CMAKE_COMMAND} ARGS -E create_symlink $<TARGET_FILE_NAME:${target}> ${symlink_name})
  
  IF(CMAKE_GENERATOR MATCHES "Xcode")
    # For Xcode, replace project config with install config
    STRING(REPLACE "${CMAKE_CFG_INTDIR}" 
      "\${CMAKE_INSTALL_CONFIG_NAME}" output ${target_path}/${symlink_name})
  ENDIF()

  # presumably this will be used for libmysql*.so symlinks
  INSTALL(FILES ${target_lib} DESTINATION ${install_path}
          COMPONENT SharedLibraries)
ENDIF()
ENDMACRO()
