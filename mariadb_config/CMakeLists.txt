INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

# Figure out additional libraries for use with 

FOREACH (dep ${libmariadb_LIB_DEPENDS})
  STRING(REGEX MATCH "^-l.*$" out "${dep}")
  IF(out)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} ${dep}")
  ENDIF(out)
ENDFOREACH(dep)

IF(UNIX)
  IF(OPENSSL_LIBRARIES)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} -lssl")
  ENDIF()
  SEARCH_LIBRARY(LIBNSL getaddrinfo "nsl_r;nsl")
  SEARCH_LIBRARY(LIBBIND bind "bind;socket")
  SEARCH_LIBRARY(LIBSOCKET setsockopt "socket")
  SEARCH_LIBRARY(LIBDL dlopen "dl")
  SEARCH_LIBRARY(LIBM floor m)
  FOREACH(lib ${EXTRA_LIBS})
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} -l${lib}")
  ENDFOREACH()
  IF(WITH_SQLITE)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} -lsqlite")
  ENDIF()  
ENDIF(UNIX)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/mariadb_config.c.in
               ${CMAKE_CURRENT_BINARY_DIR}/mariadb_config.c @ONLY)

ADD_EXECUTABLE(mariadb_config ${CMAKE_CURRENT_BINARY_DIR}/mariadb_config.c)
TARGET_LINK_LIBRARIES(mariadb_config mariadbclient)

# Installation
#
INSTALL(TARGETS mariadb_config
        DESTINATION "bin")
