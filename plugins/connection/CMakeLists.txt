# Aurora
REGISTER_PLUGIN(TARGET aurora
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT DYNAMIC
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/aurora.c)

# Replication
REGISTER_PLUGIN(TARGET replication
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT DYNAMIC
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/replication.c)

# DSN
REGISTER_PLUGIN(TARGET dsn
                TYPE MARIADB_CLIENT_PLUGIN_CONNECTION
                CONFIGURATIONS STATIC DYNAMIC OFF
                DEFAULT DYNAMIC
                SOURCES ${CC_SOURCE_DIR}/plugins/connection/dsn.c)

