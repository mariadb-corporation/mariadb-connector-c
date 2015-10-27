# plugin installation

MACRO(INSTALL_PLUGIN name binary_dir)
  IF(NOT WIN32)
    INSTALL(TARGETS ${name}
            RUNTIME DESTINATION "${PLUGIN_INSTALL_DIR}"
            LIBRARY DESTINATION "${PLUGIN_INSTALL_DIR}"
            ARCHIVE DESTINATION "${PLUGIN_INSTALL_DIR}")
  ELSE()
    SET(MARIADB_PLUGINS "${MARIADB_PLUGINS} <File Id=\"${name}.dll\" Name=\"${name}.dll\" DiskId=\"1\" Source=\"${binary_dir}/${CMAKE_BUILD_TYPE}/${name}.dll\"/>\n")
    MARK_AS_ADVANCED(MARIADB_PLUGINS)
  ENDIF()
ENDMACRO()
