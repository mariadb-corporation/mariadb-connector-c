IF(WIN32)
  SET(EXPORT_FILE "../plugin.def")
ENDIF()

SET(CMAKE_SHARED_LIBRARY_PREFIX "")
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

IF(REPLICATION_PLUGIN_TYPE MATCHES "DYNAMIC")
  IF(WIN32)
    SET_VERSION_INFO("TARGET:replication"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/connection/replication.c"
                     "ORIGINAL_FILE_NAME:replication.dll"
                     "FILE_DESCRIPTION:Connection plugin for master/slave environment")
  ENDIF()
  ADD_DEFINITIONS(-DHAVE_REPLICATION_DYNAMIC=1)
  ADD_LIBRARY(replication MODULE ${replication_RC} replication.c ${EXPORT_FILE})
  IF(WIN32)
    TARGET_LINK_LIBRARIES(replication libmariadb)
  ENDIF()
  SET(INSTALL_LIBS replication)
ENDIF()

IF(AURORA_PLUGIN_TYPE MATCHES "DYNAMIC")
  IF(WIN32)
    SET_VERSION_INFO("TARGET:aurora"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/connection/aurora.c"
                     "ORIGINAL_FILE_NAME:aurora.dll"
                     "FILE_DESCRIPTION:Connection plugin for Amazon AWS Aurora")
  ENDIF()
  ADD_DEFINITIONS(-DHAVE_AURORA_DYNAMIC=1)
  ADD_LIBRARY(aurora MODULE ${aurora_RC} aurora.c ${EXPORT_FILE})
  IF(WIN32)
    TARGET_LINK_LIBRARIES(aurora libmariadb)
  ENDIF()
  SET(INSTALL_LIBS ${INSTALL_LIBS} aurora)
ENDIF()


IF(INSTALL_LIBS)
    INSTALL(TARGETS
            ${INSTALL_LIBS}
            RUNTIME DESTINATION "${PLUGIN_INSTALL_DIR}"
            LIBRARY DESTINATION "${PLUGIN_INSTALL_DIR}"
            ARCHIVE DESTINATION "${PLUGIN_INSTALL_DIR}")
ENDIF()
