INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
ADD_EXECUTABLE(mariadb_client_plugin_info ma_plugin_info.c)
TARGET_LINK_LIBRARIES(mariadb_client_plugin_info mariadbclient)

INSTALL(TARGETS mariadb_client_plugin_info
        DESTINATION "bin")
