INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/install_plugins.cmake)
IF(WITH_SIGNCODE)
  INCLUDE(${CMAKE_SOURCE_DIR}/cmake/sign.cmake)
ENDIF()

IF(REMOTEIO_PLUGIN_TYPE MATCHES "DYNAMIC")
  IF(CURL_FOUND)
    IF(WIN32)
      SET_VERSION_INFO("TARGET:remote_io"
                       "FILE_TYPE:VFT_DLL"
                       "SOURCE_FILE:plugins/io/remote_io.c"
                       "ORIGINAL_FILE_NAME:remote_io.dll"
                       "FILE_DESCRIPTION:Plugin for remote file access")
    ENDIF()
    # remote file plugin
    INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
    SET(REMOTE_IO_SOURCES ${remote_io_RC} remote_io.c)
    ADD_DEFINITIONS(-DHAVE_REMOTEIO_DYNAMIC=1)
    ADD_LIBRARY(remote_io MODULE ${REMOTE_IO_SOURCES} ${CMAKE_SOURCE_DIR}/plugins/plugin.def)
    TARGET_LINK_LIBRARIES(remote_io ${CURL_LIBRARIES})
    SET_TARGET_PROPERTIES(remote_io PROPERTIES PREFIX "")
    INSTALL_PLUGIN(remote_io ${CMAKE_BINARY_DIR}/plugins/io)
    SIGN_TARGET(remote_io)
  ENDIF()
ENDIF()
