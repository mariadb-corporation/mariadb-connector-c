FIND_PROGRAM(PANDOC pandoc REQUIRED)

SET(CC_WIKI_DIR ${CC_SOURCE_DIR}/docs/wiki)
SET(DEPRECATED_FUNCS mysql_list_fields mysql_list_tables
                     mysql_list_dbs mysql_list_processes
                     mariadb_rpl_init_ex
                     mysql_escape_string)

FOREACH(func ${CC_DOC_FREF})
  # ignore:
  # - async functions, they are described in a separate chapter
  # - deprecated functions
  IF (${func} MATCHES ".*cont"  OR ${func} MATCHES ".*start" OR ${func} IN_LIST DEPRECATED_FUNCS) 
    CONTINUE()
  ENDIF()
  IF (NOT EXISTS "${CC_WIKI_DIR}/${func}.md")
    SET(NON_DOCUMENTED ${NON_DOCUMENTED} ${func})
    CONTINUE()
  ENDIF()

  ADD_CUSTOM_COMMAND(OUTPUT ${CC_BINARY_DIR}/docs/${func}.3
                     DEPENDS ${CC_WIKI_DIR}/${func}.md
                     COMMAND ${CMAKE_COMMAND} -E echo "% ${func}(3) Version ${CPACK_PACKAGE_VERSION} | MariaDB Connector/C" > ${CC_BINARY_DIR}/docs/header.tmp
                     COMMAND ${CMAKE_COMMAND} -E cat ${CC_BINARY_DIR}/docs/header.tmp ${CC_WIKI_DIR}/${func}.md > ${CC_BINARY_DIR}/docs/${func}.3.md
                     COMMAND echo "${LINK_PATTERN}"
                     COMMAND ${PANDOC} --standalone --lua-filter=${CC_SOURCE_DIR}/docs/delink.lua --to man ${CC_BINARY_DIR}/docs/${func}.3.md -o ${CC_BINARY_DIR}/docs/${func}.3
                     COMMAND rm  ${CC_BINARY_DIR}/docs/${func}.3.md
                     VERBATIM)

  LIST(APPEND CC_MAN_PAGES ${CC_BINARY_DIR}/docs/${func}.3)

ENDFOREACH()

ADD_CUSTOM_TARGET(CREATE_MAN_PAGES ALL DEPENDS ${CC_MAN_PAGES})
INSTALL(FILES ${CC_MAN_PAGES} DESTINATION ${INSTALL_MANDIR}/man3 COMPONENT ManPagesDevelopment)

IF (NON_DOCUMENTED)
  MESSAGE(STATUS "No documentation found for the following functions: ${NON_DOCUMENTED}")
ENDIF()
