IF(WIN32)
  SET(EXPORT_FILE "../plugin.def")
ENDIF()

SET(CMAKE_SHARED_LIBRARY_PREFIX "")

IF(REPLICATION_PLUGIN_TYPE MATCHES "DYNAMIC")
  IF(WIN32)
    SET_VERSION_INFO("TARGET:replication"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/connection/replication.c"
                     "ORIGINAL_FILE_NAME:replication.dll"
                     "FILE_DESCRIPTION:Connection plugin for master/slave environment")
  ENDIF()
  ADD_DEFINITIONS(-DHAVE_REPLICATION_DYNAMIC=1)
  ADD_LIBRARY(replication SHARED replication.c ${EXPORT_FILE})
  SET(INSTALL_LIBS replication)
ENDIF()

IF(INSTALL_LIBS)
    INSTALL(TARGETS
            ${INSTALL_LIBS}
            RUNTIME DESTINATION "${PLUGIN_INSTALL_DIR}"
            LIBRARY DESTINATION "${PLUGIN_INSTALL_DIR}"
            ARCHIVE DESTINATION "${PLUGIN_INSTALL_DIR}")
ENDIF()
