IF(WIN32)
  SET(EXPORT_FILE "pvio_plugin.def")
ENDIF()

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/install_plugins.cmake)
IF(WITH_SIGNCODE)
  INCLUDE(${CMAKE_SOURCE_DIR}/cmake/sign.cmake)
ENDIF()

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

SET(CMAKE_SHARED_LIBRARY_PREFIX "")

IF(SOCKET_PLUGIN_TYPE MATCHES "DYNAMIC")
  IF(WIN32)
    SET_VERSION_INFO("TARGET:pvio_socket"
                     "FILE_TYPE:VFT_DLL"
                     "SOURCE_FILE:plugins/pvio/pvio_socket.c"
                     "ORIGINAL_FILE_NAME:pvio_socket.dll"
                     "FILE_DESCRIPTION:VIO plugin for socket communication")
  ENDIF()
  ADD_DEFINITIONS(-DHAVE_SOCKET_DYNAMIC=1)
  ADD_LIBRARY(pvio_socket SHARED pvio_socket.c ${pvio_socket_RC} ${EXPORT_FILE})
  INSTALL_PLUGIN(pvio_socket ${CMAKE_BINARY_DIR}/plugins/pvio)
  SIGN_TARGET(pvio_socket)
ENDIF()

IF(WIN32)
  IF(NPIPE_PLUGIN_TYPE MATCHES "DYNAMIC")
    IF(WIN32)
      SET_VERSION_INFO("TARGET:pvio_npipe"
                       "FILE_TYPE:VFT_DLL"
                       "SOURCE_FILE:plugins/pvio/pvio_npipe.c"
                       "ORIGINAL_FILE_NAME:pvio_npipe.dll"
                       "FILE_DESCRIPTION:VIO plugin for named pipe communication")
    ENDIF()
    ADD_DEFINITIONS(-DHAVE_NPIPE_DYNAMIC=1)
    ADD_LIBRARY(pvio_npipe SHARED pvio_npipe.c ${pvio_npipe_RC} ${EXPORT_FILE})
    INSTALL_PLUGIN(pvio_npipe ${CMAKE_BINARY_DIR}/plugins/pvio)
    SIGN_TARGET(pvio_npipe)
  ENDIF()
  IF(SHMEM_PLUGIN_TYPE MATCHES "DYNAMIC")
    ADD_DEFINITIONS(-DHAVE_SHMEM_DYNAMIC=1)
    IF(WIN32)
      SET_VERSION_INFO("TARGET:pvio_shmem"
                       "FILE_TYPE:VFT_DLL"
                       "SOURCE_FILE:plugins/pvio/pvio_shmm.c"
                       "ORIGINAL_FILE_NAME:pvio_shmem.dll"
                       "FILE_DESCRIPTION:VIO plugin for shared memory communication")
    ENDIF()
    ADD_LIBRARY(pvio_shmem SHARED pvio_shmem.c ${pvio_shmem_RC} ${EXPORT_FILE})
    INSTALL_PLUGIN(pvio_shmem ${CMAKE_BINARY_DIR}/plugins/pvio)
    SIGN_TARGET(pvio_shmem)
  ENDIF()
ENDIF()
