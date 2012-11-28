INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

# Figure out additional libraries for use with 

FOREACH (dep ${libmysql_LIB_DEPENDS})
  STRING(REGEX MATCH "^-.*$" out "${dep}")
  IF(out)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} ${dep}")
  ENDIF(out)
ENDFOREACH(dep)

IF(UNIX)
  IF(OPENSSL_LIBRARIES)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} -lssl")
  ENDIF(OPENSSL_LIBRARIES)
  IF(DL_LIBRARY)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} -ldl")
  ENDIF(DL_LIBRARY)
  IF(MATH_LIBRARY)
    SET(extra_dynamic_LDFLAGS "${extra_dynamic_LDFLAGS} -lm")
  ENDIF(MATH_LIBRARY)
ENDIF(UNIX)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/mysql_config.c.in
               ${CMAKE_CURRENT_BINARY_DIR}/mysql_config.c @ONLY)

ADD_EXECUTABLE(mariadb_config ${CMAKE_CURRENT_BINARY_DIR}/mysql_config.c)
TARGET_LINK_LIBRARIES(mariadb_config mariadbclient)

# Installation
#
INSTALL(TARGETS mariadb_config
        DESTINATION "bin")
