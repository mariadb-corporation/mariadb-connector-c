INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/install_plugins.cmake)
IF(WITH_SIGNCODE)
  INCLUDE(${CMAKE_SOURCE_DIR}/cmake/sign.cmake)
ENDIF()

# Trace example plugin
IF(TRACE_EXAMPLE_PLUGIN_TYPE MATCHES "DYNAMIC")
  IF(WIN32)
    SET_VERSION_INFO("TARGET:trace_example"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/trace/trace_example.c"
                     "ORIGINAL_FILE_NAME:trace_example.dll"
                     "FILE_DESCRIPTION:Trace example")
  ENDIF()
  ADD_DEFINITIONS(-DHAVE_TRACE_EXAMPLE_PLUGIN_DYNAMIC=1)
  SET(TRACE_EXAMPLE_SOURCES ${trace_example_RC} trace_example.c)
  IF(WIN32)
    SET(TRACE_EXAMPLE_SOURCES ${TRACE_EXAMPLE_SOURCES} ${CMAKE_SOURCE_DIR}/plugins/plugin.def)
  ENDIF()
  ADD_LIBRARY(trace_example MODULE ${TRACE_EXAMPLE_SOURCES})
  SET_TARGET_PROPERTIES(trace_example PROPERTIES PREFIX "")
  INSTALL_PLUGIN(trace_example ${CMAKE_BINARY_DIR}/plugins/trace)
  SIGN_TARGET(trace_example)
ENDIF()
