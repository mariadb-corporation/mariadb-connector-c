# Aurora
REGISTER_PLUGIN(TARGET aurora
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT OFF
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/aurora.c)

# Replication
REGISTER_PLUGIN(TARGET replication
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT OFF
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/replication.c)

# Redirection
REGISTER_PLUGIN(TARGET redirection
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT DYNAMIC
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/redirection.c
                ${CC_SOURCE_DIR}/plugins/connection/redirection_utility.c) 
