# If option WITH_SQLITE was specified, we build this plugin
# as an internal plugin.

IF(NOT WITH_SQLITE)
  #  ADD_DEFINITIONS(-DSQLITE_ENABLE_COLUMN_METADATA)
  #
  #ADD_LIBRARY(sqlite SHARED sqlite3.c)
  #ADD_LIBRARY(sqlite_client_plugin SHARED sqlite_client_plugin.c)
  #TARGET_LINK_LIBRARIES(sqlite_client_plugin sqlite)
  #
  #INSTALL(TARGETS
  #        sqlite
  #        RUNTIME DESTINATION "lib/mariadb"
  #        LIBRARY DESTINATION "lib/mariadb"
  #        ARCHIVE DESTINATION "lib/mariadb")
  #
  #INSTALL(TARGETS
  #        sqlite_client_plugin
  #        RUNTIME DESTINATION "plugins"
  #        LIBRARY DESTINATION "plugins"
  #        ARCHIVE DESTINATION "plugins")
ENDIF()
