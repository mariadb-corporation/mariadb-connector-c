# plugin installation

MACRO(INSTALL_PLUGIN name binary_dir)
  INSTALL(TARGETS ${name}
          RUNTIME DESTINATION "${PLUGIN_INSTALL_DIR}"
          LIBRARY DESTINATION "${PLUGIN_INSTALL_DIR}"
          ARCHIVE DESTINATION "${PLUGIN_INSTALL_DIR}")
  IF(WIN32)
    FILE(APPEND ${CMAKE_BINARY_DIR}/win/packaging/plugin.conf "<File Id=\"${name}.dll\" Name=\"${name}.dll\" DiskId=\"1\" Source=\"${binary_dir}/${CMAKE_BUILD_TYPE}/${name}.dll\"/>\n")
  ENDIF()
ENDMACRO()
